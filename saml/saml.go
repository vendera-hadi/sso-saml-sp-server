package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sp-server/config"
	"sp-server/utils"
	"strings"
	"time"

	"github.com/beevik/etree"
)

func GenerateAuthnRequest(cfg *config.Config, idpEntityID string) string {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	request := doc.CreateElement("samlp:AuthnRequest")
	request.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	request.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	request.CreateAttr("ID", "_"+utils.GenerateID())
	request.CreateAttr("Version", "2.0")
	request.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	request.CreateAttr("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	request.CreateAttr("AssertionConsumerServiceURL", cfg.BaseUrl+"/assert")
	request.CreateElement("saml:Issuer").SetText(idpEntityID)
	request.CreateElement("samlp:NameIDPolicy").CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	doc.Indent(2)

	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}

	return string(xmlBytes)
}

// verifyResponse verifies the SAML response's signature using the IdP's public key.
func VerifySAMLResponse(samlResponse string, pubKey *rsa.PublicKey) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(samlResponse); err != nil {
		return fmt.Errorf("failed to parse SAML response: %v", err)
	}

	// Find the <Signature> element
	signatureElement := doc.FindElement("//ds:Signature")
	if signatureElement == nil {
		return errors.New("no signature found in SAML response")
	}

	// Extract the <SignedInfo> element
	signedInfoElement := signatureElement.FindElement("ds:SignedInfo")
	if signedInfoElement == nil {
		return errors.New("no SignedInfo found in SAML response")
	}

	// Canonicalize the <SignedInfo> element
	canonicalizedSignedInfo, err := utils.Canonicalize(signedInfoElement)
	fmt.Println(canonicalizedSignedInfo)
	if err != nil {
		return fmt.Errorf("failed to canonicalize SignedInfo: %v", err)
	}

	// Extract the <SignatureValue> element
	signatureValueElement := signatureElement.FindElement("ds:SignatureValue")
	if signatureValueElement == nil {
		return errors.New("no SignatureValue found in SAML response")
	}

	// Decode the Base64-encoded signature
	signatureBase64 := strings.TrimSpace(signatureValueElement.Text())
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	// Hash the canonicalized <SignedInfo>
	hashed := sha256.Sum256([]byte(canonicalizedSignedInfo))

	// Verify the signature
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}
