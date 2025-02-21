package keys

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"sp-server/config"
)

// load public key
func LoadCert(cfg *config.Config) *x509.Certificate {
	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}
