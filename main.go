package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
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

var authError = "X-Auth-Error"

type roundTripFilter struct {
	parent http.RoundTripper
}

func (rtf *roundTripFilter) RoundTrip(r *http.Request) (*http.Response, error) {
	if err, ok := r.Header[authError]; ok {
		return &http.Response{
			StatusCode: 403,
		}, errors.New(strings.Join(err, ","))
	}
	return rtf.parent.RoundTrip(r)
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
		request.Header.Add(authError, "bad auth error")
	}
	request.URL.Host = m.Config.K8SURL.Host
	request.URL.Scheme = m.Config.K8SURL.Scheme
	request.Host = m.Config.K8SURL.Host
	request.Header.Del("Authorization")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", m.Config.Bearer))
}

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
}

func signup(w http.ResponseWriter, r *http.Request) {
	logger.Println(r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
	w.Write([]byte("{\"status\":{\"ready\":true}}"))
}

func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if err.Error() == "bad auth error" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("auth was denied by server"))
	}
}

func getMux() *http.ServeMux {
	k8sURL := os.Getenv("HJ_K8S")
	if k8sURL == "" {
		panic("HJ_K8s env var missing")
	}
	token := os.Getenv("HJ_TOKEN")
	if token == "" {
		panic("HJ_TOKEN env var missing")
	}
	keycloak := os.Getenv("HJ_KEYCLOAK")
	if keycloak == "" {
		panic("HJ_KEYCLOAK env var missing")
	}
	proxyssl, err := strconv.ParseBool(os.Getenv("HJ_PROXY_SSL"))
	if err != nil {
		panic(err)
	}

	rpURL, err := url.Parse(k8sURL)
	if err != nil {
		panic(err)
	}

	logger.Printf("Forwarding to: %s\n", k8sURL)
	logger.Printf("Proxy SSL mode on: %t\n", proxyssl)

	mangler, err := NewMangler(
		*rpURL,
		token,
		keycloak,
		logger,
	)

	if err != nil {
		panic(fmt.Sprintf("encountered error loading: %s", err))
	}

	var transport http.RoundTripper
	if proxyssl {
		transport = &roundTripFilter{parent: http.DefaultTransport}
	} else {
		transport = &roundTripFilter{parent: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	}

	proxy := httputil.ReverseProxy{
		Director:     mangler.modifier,
		Transport:    transport,
		ErrorLog:     logger,
		ErrorHandler: proxyErrorHandler,
	}

	mux := http.NewServeMux()

	mux.Handle("/", logging(logger)(&proxy))
	mux.HandleFunc("/registration/api/v1/signup", signup)

	return mux
}

func main() {
	ssl, err := strconv.ParseBool(os.Getenv("HJ_SSL"))
	if err != nil {
		panic(err)
	}

	serve := os.Getenv("HJ_SERVE")
	if serve == "" {
		serve = ":8000"
	}

	logger.Println("Server is starting...")
	logger.Printf("Listening on: %s\n", serve)
	logger.Printf("SSL mode on: %t\n", ssl)

	mux := getMux()

	if ssl {
		err = http.ListenAndServeTLS(serve, "/tmp/certs/tls.crt", "/tmp/certs/tls.key", mux)
		if err != nil {
			fmt.Printf("%s", err)
		}
	} else {
		err = http.ListenAndServe(serve, mux)
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
