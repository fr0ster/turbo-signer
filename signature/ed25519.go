package signature

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/bitly/go-simplejson"
)

// How can I use Ed25519 API keys?
// Step 1: Generate the private key test-prv-key.pem. Do not share this file with anyone!

// openssl genpkey -algorithm ed25519 -out test-prv-key.pem
// Step 2: Compute the public key test-pub-key.pem from the private key.

// openssl pkey -pubout -in test-prv-key.pem -out test-pub-key.pem

type SignEd25519 struct {
	apiKey     string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// Функція для створення підпису Ed25519
func (sign *SignEd25519) CreateSignature(queryString string) string {
	signature := ed25519.Sign(sign.privateKey, []byte(queryString))
	return base64.StdEncoding.EncodeToString(signature)
}

func (sign *SignEd25519) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	return signParameters(params, sign)
}

// Функція для валідації підпису
func (sign *SignEd25519) ValidateSignatureParams(params *simplejson.Json) bool {
	// Витягування підпису з параметрів
	signature, err := params.Get("signature").String()
	if err != nil {
		return false
	}

	// Видалення підпису з параметрів
	js, _ := params.MarshalJSON()
	unsignedParams, _ := simplejson.NewJson(js)
	unsignedParams.Del("signature")

	// Отримання строки параметрів
	message, err := convertSimpleJSONToString(unsignedParams)
	if err != nil {
		return false
	}

	// Валідація підпису
	return sign.ValidateSignature(message, signature)
}

func (sign *SignEd25519) ValidateSignature(message, signature string) bool {
	// Перетворення підпису з Base64 у байти
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	// Валідація підпису
	return ed25519.Verify(sign.publicKey, []byte(message), signatureBytes)
}

func (sign *SignEd25519) GetAPIKey() string {
	return sign.apiKey
}

func NewSignEd25519(apiKey string, publicKey string, privateKey string) (signer *SignEd25519, err error) {
	private, err := loadEd25519PrivateKeyFromPEM(privateKey)
	if err != nil {
		return
	}
	public, err := loadEd25519PublicKeyFromPEM(publicKey)
	if err != nil {
		return
	}
	signer = &SignEd25519{
		apiKey:     apiKey,
		privateKey: ed25519.PrivateKey(private),
		publicKey:  ed25519.PublicKey(public),
	}
	return
}

// Функція для завантаження приватного ключа з PEM рядка
func loadEd25519PrivateKeyFromPEM(content string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}

	return ed25519PrivateKey, nil
}

// Функція для завантаження публічного ключа з PEM рядка
func loadEd25519PublicKeyFromPEM(content string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ed25519PublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}

	return ed25519PublicKey, nil
}
