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

// Функція для створення підпису Ed25519 з обробкою помилок
func (sign *SignEd25519) CreateSignature(queryString string) (string, error) {
	// Валідація повідомлення
	if err := sign.ValidateMessageFormat(queryString); err != nil {
		return "", err
	}

	// Валідація ключа
	if err := sign.ValidateKeyStrength(); err != nil {
		return "", err
	}

	signature := ed25519.Sign(sign.privateKey, []byte(queryString))
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (sign *SignEd25519) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	return signParameters(params, sign)
}

// Функція для валідації підпису
func (sign *SignEd25519) ValidateSignatureParams(params *simplejson.Json) (bool, error) {
	// Витягування підпису з параметрів
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

	// Отримання строки параметрів
	message, err := ConvertSimpleJSONToString(unsignedParams)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to convert params to string", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Валідація підпису
	return sign.ValidateSignature(message, signature)
}

func (sign *SignEd25519) ValidateSignature(message, signature string) (bool, error) {
	// Валідація вхідних параметрів
	if err := sign.ValidateMessageFormat(message); err != nil {
		return false, err
	}

	if signature == "" {
		return false, NewSignatureError(ErrInvalidFormat, "signature is empty")
	}

	// Перетворення підпису з Base64 у байти
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInvalidFormat, "invalid base64 signature", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Валідація підпису
	return ed25519.Verify(sign.publicKey, []byte(message), signatureBytes), nil
}

func (sign *SignEd25519) GetAPIKey() string {
	return sign.apiKey
}

// Нова функція: валідація сили ключа
func (sign *SignEd25519) ValidateKeyStrength() error {
	if len(sign.privateKey) != ed25519.PrivateKeySize {
		return NewSignatureErrorWithDetails(ErrInvalidKey, "invalid private key size", map[string]interface{}{
			"current_size":  len(sign.privateKey),
			"expected_size": ed25519.PrivateKeySize,
		})
	}

	if len(sign.publicKey) != ed25519.PublicKeySize {
		return NewSignatureErrorWithDetails(ErrInvalidKey, "invalid public key size", map[string]interface{}{
			"current_size":  len(sign.publicKey),
			"expected_size": ed25519.PublicKeySize,
		})
	}

	return nil
}

// Нова функція: валідація формату повідомлення
func (sign *SignEd25519) ValidateMessageFormat(message string) error {
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

func NewSignEd25519(apiKey string, publicKey string, privateKey string) (signer *SignEd25519, err error) {
	private, err := loadEd25519PrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, NewSignatureErrorWithDetails(ErrInvalidKey, "failed to load private key", map[string]interface{}{
			"error": err.Error(),
		})
	}

	public, err := loadEd25519PublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, NewSignatureErrorWithDetails(ErrInvalidKey, "failed to load public key", map[string]interface{}{
			"error": err.Error(),
		})
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
		return nil, errors.New("failed to parse Ed25519 private key")
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
		return nil, errors.New("failed to parse Ed25519 public key")
	}

	return ed25519PublicKey, nil
}
