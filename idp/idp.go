package idp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sp-server/config"

	"github.com/beevik/etree"
)

type IDPConfig struct {
	EntityID string
	SSOURL   string
	Cert     *x509.Certificate
}

func LoadAllIdp(cfg *config.Config) map[string]IDPConfig {
	configs := make(map[string]IDPConfig)
	for idpEntityID, idpCertPath := range cfg.IdpCerts {
		configs[idpEntityID] = loadIdp(idpEntityID, idpCertPath)
	}
	return configs
}

func loadIdp(entityID, certPath string) IDPConfig {
	resp, err := http.Get(entityID)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Failed to fetch IdP metadata: %s", resp.Status))
	}

	metadataBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(metadataBytes); err != nil {
		panic(err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		panic(fmt.Errorf("failed to decode PEM block containing certificate"))
	}
	idpCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	entityDescriptor := doc.FindElement("EntityDescriptor")
	ssoElement := entityDescriptor.FindElement(".//SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']")
	ssoURL := ssoElement.SelectAttrValue("Location", "")

	return IDPConfig{
		EntityID: entityID,
		SSOURL:   ssoURL,
		Cert:     idpCert,
	}
}
