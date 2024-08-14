package signature

import "github.com/bitly/go-simplejson"

type (
	PublicKey string
	SecretKey string
	Sign      interface {
		CreateSignature(queryString string) string
		CreateParameters(*simplejson.Json) *simplejson.Json
		GetAPIKey() string
	}
)
