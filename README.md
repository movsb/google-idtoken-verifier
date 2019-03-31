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
	fmt.Printf("Iss:\t%s\nSub:\t%s\nEmail:\t%s\nName:\t%s\n",
		claims.Iss, claims.Sub, claims.Email, claims.Name)
}
```

## Features

[All steps](https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token) are satisfied except the G Suit hosted domain (hd) verification.
