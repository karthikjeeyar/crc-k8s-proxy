package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
)

type Realm struct {
	Realm     string `json:"realm"`
	PublicKey string `json:"public_key"`
}

type ManglerConfig struct {
	K8SURL    url.URL
	Bearer    string
	PublicKey string
	Validator *CRCAuthValidator
}

type Mangler struct {
	URL    *url.URL
	Config *ManglerConfig
	Log    *log.Logger
}

func NewMangler(k8sURL url.URL, token, keycloak string, logger *log.Logger) (*Mangler, error) {

	validator, err := NewCRCAuthValidator(&ValidatorConfig{
		KeycloakURL: keycloak,
	}, logger)

	if err != nil {
		return nil, err
	}

	m := &Mangler{
		Config: &ManglerConfig{
			K8SURL:    k8sURL,
			Bearer:    token,
			Validator: validator,
		},
		Log: logger,
	}
	return m, nil
}

func (m *Mangler) modifier(request *http.Request) {
	err := m.Config.Validator.ProcessRequest(request)
	if err != nil {
		panic("error")
	}
	request.URL.Host = m.Config.K8SURL.Host
	request.URL.Scheme = m.Config.K8SURL.Scheme
	request.Host = m.Config.K8SURL.Host
	request.Header.Del("Authorization")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", m.Config.Bearer))
}

func main() {
	k8sURL := os.Getenv("HJ_K8S")
	if k8sURL == "" {
		panic("HJ_K8s env var missing")
	}
	serve := os.Getenv("HJ_SERVE")
	if serve == "" {
		serve = ":8000"
	}
	token := os.Getenv("HJ_TOKEN")
	if token == "" {
		panic("HJ_TOKEN env var missing")
	}
	keycloak := os.Getenv("HJ_KEYCLOAK")
	if keycloak == "" {
		panic("HJ_KEYCLOAK env var missing")
	}
	ssl, err := strconv.ParseBool(os.Getenv("HJ_SSL"))
	if err != nil {
		panic(err)
	}
	proxyssl, err := strconv.ParseBool(os.Getenv("HJ_PROXY_SSL"))
	if err != nil {
		panic(err)
	}

	rpURL, err := url.Parse(k8sURL)
	if err != nil {
		panic(err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Println("Server is starting...")
	logger.Printf("Listening on: %s\n", serve)
	logger.Printf("Forwarding to: %s\n", k8sURL)
	logger.Printf("SSL mode on: %t\n", ssl)
	logger.Printf("Proxy SSL mode on: %t\n\n", proxyssl)

	mangler, err := NewMangler(
		*rpURL,
		token,
		keycloak,
		logger,
	)

	if err != nil {
		panic(fmt.Sprintf("Encountered error loading: %s", err))
	}

	var transport http.RoundTripper
	if proxyssl {
		transport = http.DefaultTransport
	} else {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	proxy := httputil.ReverseProxy{
		Director:  mangler.modifier,
		Transport: transport,
		ErrorLog:  logger,
	}

	if ssl {
		err = http.ListenAndServeTLS(serve, "/tmp/certs/tls.crt", "/tmp/certs/tls.key", &proxy)
		if err != nil {
			fmt.Printf("%s", err)
		}
	} else {
		err = http.ListenAndServe(serve, logging(logger)(&proxy))
		if err != nil {
			fmt.Printf("%s", err)
		}
	}
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				logger.Println(r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}
