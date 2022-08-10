package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
)

type CRCAuthValidator struct {
	config    *ValidatorConfig
	pem       string
	verifyKey *rsa.PublicKey
	logger    *log.Logger
}

type ValidatorConfig struct {
	KeycloakURL string `json:"keycloakURL,omitempty"`
}

func NewCRCAuthValidator(config *ValidatorConfig, logger *log.Logger) (*CRCAuthValidator, error) {
	validator := &CRCAuthValidator{config: config, logger: logger}
	if config.KeycloakURL != "" {
		resp, err := getJWT(config.KeycloakURL)
		if err != nil {
			return nil, fmt.Errorf("could not obtain key: %s", err.Error())
		}
		validator.pem = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", resp)
		logger.Print("PEM Read Successfully\n")
	} else {
		validator.pem = os.Getenv("JWTPEM")
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(validator.pem))
	if err != nil {
		fmt.Println("couldn't verify cert" + err.Error())
		return nil, err
	} else {
		validator.verifyKey = verifyKey
		logger.Println("PEM Verified Successfully")
	}

	return validator, nil
}

func getJWT(keycloakURL string) (string, error) {
	resp, err := http.Get(keycloakURL)
	if err != nil {
		return "", err
	}

	realm := &Realm{}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(body, &realm)
	if err != nil {
		return "", err
	}
	return realm.PublicKey, nil
}

func (crc *CRCAuthValidator) ValidateJWTHeaderRequest(r *http.Request) (*jwt.Token, error) {
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return crc.verifyKey, nil
	})

	if err != nil {
		fmt.Println("couldn't validate jwt header", err.Error())
		return nil, err
	}

	return token, nil
}

func (crc *CRCAuthValidator) processJWTHeaderRequest(r *http.Request) error {
	_, err := crc.ValidateJWTHeaderRequest(r)

	if err != nil {
		return err
	}
	return nil
}

func (crc *CRCAuthValidator) ProcessRequest(r *http.Request) error {
	if strings.Contains(r.Header.Get("Authorization"), "Bearer") {
		return crc.processJWTHeaderRequest(r)
	} else {
		logger.Printf("bad auth request")
		return fmt.Errorf("bad auth type")
	}
}
