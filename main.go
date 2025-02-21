package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"sp-server/config"
	"sp-server/idp"
	"sp-server/keys"
	"sp-server/metadata"
	"sp-server/saml"

	"github.com/beevik/etree"
)

var (
	spCert       *x509.Certificate
	idpMetadata  map[string]idp.IDPConfig
	metadataLock sync.Mutex
	cfg          *config.Config
)

func main() {
	cfg = config.NewConfig()
	// Load SP certificate
	spCert = keys.LoadCert(cfg)
	// Initialize IdP metadata map
	idpMetadata = idp.LoadAllIdp(cfg)

	http.HandleFunc("/metadata", metadataHandler)
	http.HandleFunc("/assert", assertHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("SP Server running on port 3000")
	http.ListenAndServe(":3000", nil)
}

func metadataHandler(w http.ResponseWriter, r *http.Request) {
	metadata := metadata.GetMetadata(cfg, spCert.Raw)
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(metadata))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	idpEntityID := r.URL.Query().Get("idpEntityID")
	relayState := r.URL.Query().Get("RelayState")
	metadataLock.Lock()
	idp, ok := idpMetadata[idpEntityID]
	metadataLock.Unlock()
	if !ok {
		http.Error(w, "Unknown IdP", http.StatusBadRequest)
		return
	}

	// Set the RelayState to the current URL if it's not already set
	if relayState == "" {
		relayState = r.URL.String()
	}
	samlRequest := saml.GenerateAuthnRequest(cfg, idpEntityID)
	// fmt.Println(string(samlRequest))
	samlRequestEncoded := base64.StdEncoding.EncodeToString([]byte(samlRequest))
	// fmt.Println(samlRequestEncoded)
	urlFormatString := url.QueryEscape(samlRequestEncoded)

	redirectURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s", idp.SSOURL, urlFormatString, relayState)
	// print decode samlRequest
	// decode, _ := base64.StdEncoding.DecodeString(samlRequestEncoded)
	// fmt.Println(string(decode))

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func assertHandler(w http.ResponseWriter, r *http.Request) {
	samlResponseEncoded := r.FormValue("SAMLResponse")
	relayState := r.FormValue("RelayState")

	// URL-decode the SAMLResponse first
	samlResponseEncoded, err := url.QueryUnescape(samlResponseEncoded)
	if err != nil {
		http.Error(w, "Failed to URL-decode SAMLResponse", http.StatusBadRequest)
		return
	}

	// Base64 decode the SAMLResponse
	samlResponseXML, err := base64.StdEncoding.DecodeString(samlResponseEncoded)
	fmt.Println(string(samlResponseXML))
	if err != nil {
		http.Error(w, "Invalid SAMLResponse (Base64 decoding failed)", http.StatusBadRequest)
		return
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(samlResponseXML); err != nil {
		http.Error(w, "Invalid SAMLResponse", http.StatusBadRequest)
		return
	}

	responseElement := doc.FindElement("samlp:Response")
	assertionElement := responseElement.FindElement("saml:Assertion")
	issuer := assertionElement.FindElement("saml:Issuer").Text()

	metadataLock.Lock()
	idp, ok := idpMetadata[issuer]
	metadataLock.Unlock()
	if !ok {
		http.Error(w, "Unknown IdP", http.StatusBadRequest)
		return
	}

	// Verify the response
	err = saml.VerifySAMLResponse(string(samlResponseXML), idp.Cert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		http.Error(w, "Invalid SAMLResponse", http.StatusBadRequest)
		return
	}

	// Process the assertion
	nameID := assertionElement.FindElement("saml:Subject/saml:NameID").Text()
	fmt.Fprintf(w, "Login successful! User: %s, RelayState: %s", nameID, relayState)
}
