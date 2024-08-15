package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"

	"github.com/bitly/go-simplejson"
)

// How can I use RSA API Keys?
// Step 1: Generate the private key test-prv-key.pem. Do not share this file with anyone!

// openssl genrsa -out test-prv-key.pem 2048
// Step 2: Generate the public key test-pub-key.pem from the private key.

// openssl rsa -in test-prv-key.pem -pubout -outform PEM -out test-pub-key.pem

type SignRSA struct {
	apiKey     string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// Функція для створення підпису RSA
func (sign *SignRSA) CreateSignature(queryString string) string {
	hashed := sha256.Sum256([]byte(queryString))
	signature, err := rsa.SignPKCS1v15(rand.Reader, sign.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("Error signing query string: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func (sign *SignRSA) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	return signParameters(params, sign)
}

// Функція для валідації підпису
func (sign *SignRSA) ValidateSignatureParams(params *simplejson.Json) bool {
	signature, err := params.Get("signature").String()
	if err != nil {
		return false
	}

	// Видалення підпису з параметрів
	js, _ := params.MarshalJSON()
	unsignedParams, _ := simplejson.NewJson(js)
	unsignedParams.Del("signature")

	message, err := convertSimpleJSONToString(unsignedParams)
	if err != nil {
		return false
	}

	return sign.ValidateSignature(message, signature)
}

func (sign *SignRSA) ValidateSignature(message, signature string) bool {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	hashed := sha256.Sum256([]byte(message))

	err = rsa.VerifyPKCS1v15(sign.publicKey, crypto.SHA256, hashed[:], signatureBytes)
	return err == nil
}

func (sign *SignRSA) GetAPIKey() string {
	return sign.apiKey
}

func NewSignRSA(apiKey string, publicKey string, privateKey string) (sign *SignRSA, err error) {
	private, err := loadRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return
	}
	public, err := loadRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return
	}

	sign = &SignRSA{
		apiKey:     apiKey,
		privateKey: private,
		publicKey:  public,
	}
	return
}

// Функція для завантаження приватного ключа з PEM рядка
func loadRSAPrivateKeyFromPEM(content string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to assert private key type")
	}

	return rsaPrivateKey, nil
}

// Функція для завантаження публічного ключа з PEM рядка
func loadRSAPublicKeyFromPEM(content string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to assert private key type")
	}

	return rsaPublicKey, nil
}
