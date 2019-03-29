package googleidtokenverifier

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func decodeJwtToken(token string) (header Header, claimSet ClaimSet, toBeSigned []byte, theirSignature []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		err = ErrBadToken
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return
	}
	if header.Typ != "JWT" || header.Alg != "RS256" {
		err = ErrBadHeader
		return
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	if err = json.Unmarshal(claimBytes, &claimSet); err != nil {
		err = ErrBadClaimSet
		return
	}

	theirSignature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}
	toBeSigned = []byte(parts[0] + "." + parts[1])
	return
}
