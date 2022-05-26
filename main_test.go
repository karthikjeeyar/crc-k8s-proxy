package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	os.Setenv("HJ_PROXY_SSL", "true")
	os.Setenv("HJ_SSL", "false")
	os.Setenv("HJ_K8S", "None")
	os.Setenv("HJ_TOKEN", "None")
	os.Setenv("HJ_KEYCLOAK", "None")
}

type jsonStruct struct {
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

func startKCServer() *httptest.Server {
	keyData, _ := ioutil.ReadFile("public.pem")
	jsonObj := jsonStruct{
		PublicKey:       string(keyData),
		TokenService:    "test",
		AccountService:  "test",
		TokensNotBefore: 0,
	}
	k8sServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			jsonString, _ := json.Marshal(jsonObj)
			w.Write(jsonString)
		}
	}))
	return k8sServer
}

func TestBadAuthK8sPath(t *testing.T) {
	k8sServer := startKCServer()
	defer k8sServer.Close()

	os.Setenv("HJ_KEYCLOAK", k8sServer.URL)

	server := httptest.NewServer(getMux())
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("%s/k8s/api", server.URL))

	assert.Nil(t, err, "error was not nil")
	assert.NotNil(t, resp, "response was nil")

	assert.Equal(t, 403, resp.StatusCode)
}

func TestRegistrationPath(t *testing.T) {
	k8sServer := startKCServer()
	defer k8sServer.Close()

	os.Setenv("HJ_KEYCLOAK", k8sServer.URL)

	server := httptest.NewServer(getMux())
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("%s/registration/api/v1/signup", server.URL))

	assert.Nil(t, err, "error was not nil")
	assert.NotNil(t, resp, "response was nil")

	assert.Equal(t, 200, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err, "read error not nil")
	assert.Equal(t, "{\"status\":{\"ready\":true}}", string(body))
}
