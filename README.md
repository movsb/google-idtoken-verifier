# Google Sign-In Token Verifier

Used to verify JWT Token issued from [Google Sign-In](https://developers.google.com/identity/sign-in/web/).

## How to use

```go
package main

import (
	"fmt"

	googleidtokenverifier "github.com/movsb/google-idtoken-verifier"
)

func main() {
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImE0MzEzZTdmZDFl..."
	clientID := "YOUR_CLIENT_ID.apps.googleusercontent.com"
	claims, err := googleidtokenverifier.Verify(token, clientID)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Iss:\t%s\nSub:\t%s\nEmail:\t%s\nName:\t%s\nDomain:\t%s\n",
		claims.Iss, claims.Sub, claims.Email, claims.Name, claims.Domain)
}
```

## Features

[All steps](https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token) described in Google Sign-In are satisfied.

## G Suite

If you are using G Suite, be sure that the `Domain` field matches your host suffix.
