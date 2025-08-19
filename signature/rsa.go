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

// Функція для створення підпису RSA з обробкою помилок
func (sign *SignRSA) CreateSignature(queryString string) (string, error) {
	// Валідація повідомлення
	if err := sign.ValidateMessageFormat(queryString); err != nil {
		return "", err
	}

	// Валідація ключа
	if err := sign.ValidateKeyStrength(); err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(queryString))
	signature, err := rsa.SignPKCS1v15(rand.Reader, sign.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", NewSignatureErrorWithDetails(ErrInternalError, "failed to create RSA signature", map[string]interface{}{
			"error": err.Error(),
		})
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (sign *SignRSA) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	return signParameters(params, sign)
}

// Функція для валідації підпису
func (sign *SignRSA) ValidateSignatureParams(params *simplejson.Json) (bool, error) {
	signature, err := params.Get("signature").String()
	if err != nil {
		return false, NewSignatureError(ErrInvalidFormat, "signature field is missing or invalid")
	}

	// Видалення підпису з параметрів
	js, err := params.MarshalJSON()
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to marshal params", map[string]interface{}{
			"error": err.Error(),
		})
	}

	unsignedParams, err := simplejson.NewJson(js)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to create unsigned params", map[string]interface{}{
			"error": err.Error(),
		})
	}

	unsignedParams.Del("signature")

	message, err := ConvertSimpleJSONToString(unsignedParams)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to convert params to string", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return sign.ValidateSignature(message, signature)
}

func (sign *SignRSA) ValidateSignature(message, signature string) (bool, error) {
	// Валідація вхідних параметрів
	if err := sign.ValidateMessageFormat(message); err != nil {
		return false, err
	}

	if signature == "" {
		return false, NewSignatureError(ErrInvalidFormat, "signature is empty")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInvalidFormat, "invalid base64 signature", map[string]interface{}{
			"error": err.Error(),
		})
	}

	hashed := sha256.Sum256([]byte(message))

	err = rsa.VerifyPKCS1v15(sign.publicKey, crypto.SHA256, hashed[:], signatureBytes)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrValidationFailed, "RSA signature verification failed", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return true, nil
}

func (sign *SignRSA) GetAPIKey() string {
	return sign.apiKey
}

// Нова функція: валідація сили ключа
func (sign *SignRSA) ValidateKeyStrength() error {
	if sign.privateKey == nil {
		return NewSignatureError(ErrInvalidKey, "private key is nil")
	}

	if sign.publicKey == nil {
		return NewSignatureError(ErrInvalidKey, "public key is nil")
	}

	// RSA ключ має бути мінімум 2048 біт
	if sign.privateKey.N.BitLen() < 2048 {
		return NewSignatureErrorWithDetails(ErrKeyTooShort, "RSA key size is too small", map[string]interface{}{
			"current_size": sign.privateKey.N.BitLen(),
			"minimum_size": 2048,
		})
	}

	return nil
}

// Нова функція: валідація формату повідомлення
func (sign *SignRSA) ValidateMessageFormat(message string) error {
	if message == "" {
		return NewSignatureError(ErrEmptyMessage, "message cannot be empty")
	}

	if len(message) > 8192 {
		return NewSignatureErrorWithDetails(ErrMessageTooLong, "message is too long", map[string]interface{}{
			"current_length": len(message),
			"maximum_length": 8192,
		})
	}

	return nil
}

func NewSignRSA(apiKey string, publicKey string, privateKey string) (sign *SignRSA, err error) {
	private, err := loadRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, NewSignatureErrorWithDetails(ErrInvalidKey, "failed to load private key", map[string]interface{}{
			"error": err.Error(),
		})
	}

	public, err := loadRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, NewSignatureErrorWithDetails(ErrInvalidKey, "failed to load public key", map[string]interface{}{
			"error": err.Error(),
		})
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
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	var privateKey *rsa.PrivateKey
	var err error

	if block.Type == "RSA PRIVATE KEY" {
		// PKCS#1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		privateKey = rsaKey
	} else {
		return nil, errors.New("unsupported private key format")
	}

	if err != nil {
		return nil, err
	}

	return privateKey, nil
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
		return nil, errors.New("failed to parse RSA public key")
	}

	return rsaPublicKey, nil
}
