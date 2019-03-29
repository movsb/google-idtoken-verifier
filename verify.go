package googleidtokenverifier

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"time"
)

var googleIssuers = []string{
	"accounts.google.com",
	"https://accounts.google.com",
}

// Verify verifies that the token is issued by Google, and returns the claim set.
func Verify(token string, clientID string) (*ClaimSet, error) {
	header, claims, toBeSigned, theirSignature, err := decodeJwtToken(token)
	if err != nil {
		return nil, err
	}

	ourSignature := func() []byte {
		h := sha256.New()
		h.Write(toBeSigned)
		return h.Sum(nil)
	}()

	certs, err := listCerts()
	if err != nil {
		return nil, err
	}

	pubKey, ok := certs.Keys[header.Kid]
	if !ok {
		return nil, ErrPublicKeyNotFound
	}

	// Step 1: verify signature
	if err := rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, ourSignature, theirSignature); err != nil {
		return nil, err
	}

	// Step 2: verify aud
	if claims.Aud != clientID {
		return nil, ErrBadClientID
	}

	// Step 3: verify issuer
	issuerFound := false
	for _, issuer := range googleIssuers {
		if issuer == claims.Iss {
			issuerFound = true
			break
		}
	}
	if !issuerFound {
		return nil, ErrBadIssuer
	}

	// Step 4: verify expiry time
	expTime := time.Unix(claims.Exp, 0)
	if time.Now().After(expTime) {
		return nil, ErrExpired
	}

	return &claims, nil
}
