package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/bitly/go-simplejson"
)

type SignHMAC struct {
	apiSecret string
	apiKey    string
}

// Функція для створення підпису
func (sign *SignHMAC) CreateSignature(queryString string) string {
	h := hmac.New(sha256.New, []byte(sign.apiSecret))
	h.Write([]byte(queryString))
	return hex.EncodeToString(h.Sum(nil))
}

func (sign *SignHMAC) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	return signParameters(params, sign)
}

func (sign *SignHMAC) ValidateSignatureParams(params *simplejson.Json) (result bool) {
	// Считування сігнатури
	unsignedParams := params
	signature := params.Get("signature").MustString()
	unsignedParams.Del("signature")
	expectedSignature := func() string {
		paramsStr, err := convertSimpleJSONToString(unsignedParams)
		if err != nil {
			return ""
		}
		return paramsStr
	}

	return sign.ValidateSignature(expectedSignature(), signature)
}

func (sign *SignHMAC) ValidateSignature(message, signature string) bool {
	// Порівняння створеного підпису з наданим
	return sign.CreateSignature(message) == signature
}

func (sign *SignHMAC) GetAPIKey() string {
	return sign.apiKey
}

func NewSignHMAC(apiKey PublicKey, apiSecret SecretKey) *SignHMAC {
	return &SignHMAC{
		apiSecret: string(apiSecret),
		apiKey:    string(apiKey),
	}
}
