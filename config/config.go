package config

import (
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var CertPath map[string]string = map[string]string{
	"http://localhost:3001/metadata": "saml/idp1-cert.pem",
	// "http://localhost:3002/metadata": "saml/idp2-cert.pem",
}

type Config struct {
	BaseUrl      string
	EntityID     string
	CertPath     string
	IdpEntityIDs []string
	IdpCerts     map[string]string
}

func NewConfig() *Config {
	// load env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	baseUrl := os.Getenv("BASE_URL")
	certPath := os.Getenv("CERT_PATH")
	idpEntityEnv := os.Getenv("IDP_ENTITIES_IDS")
	idpEntities := strings.Split(idpEntityEnv, "|")

	idpCerts := make(map[string]string)
	idpCertEnv := os.Getenv("IDP_ENTITIES_CERT")
	idpCertPaths := strings.Split(idpCertEnv, "|")
	for i, idpCertPath := range idpCertPaths {
		idpCerts[idpEntities[i]] = idpCertPath
	}

	return &Config{
		BaseUrl:      baseUrl,
		EntityID:     baseUrl + "/metadata",
		CertPath:     certPath,
		IdpEntityIDs: idpEntities,
		IdpCerts:     idpCerts,
	}
}
