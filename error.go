package googleidtokenverifier

import "errors"

var (
	ErrBadToken          = errors.New("jwt: invalid token")
	ErrBadHeader         = errors.New("jwt: bad jwt header")
	ErrBadClaimSet       = errors.New("jwt: bad jwt claim set")
	ErrPublicKeyNotFound = errors.New("jwt: no correspond public key found")
	ErrBadClientID       = errors.New("jwt: client ID mismatch")
	ErrBadIssuer         = errors.New("jwt: bad issuer")
	ErrExpired           = errors.New("jwt: token expired")
)
