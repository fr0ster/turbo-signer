package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/bitly/go-simplejson"
)

// SignECDSA реалізація ECDSA підпису
type SignECDSA struct {
	apiKey     string
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	curve      elliptic.Curve
}

// NewSignECDSA створює новий ECDSA підпис
func NewSignECDSA(apiKey string, publicKey string, privateKey string) (*SignECDSA, error) {
	private, err := loadECDSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	public, err := loadECDSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}

	// Перевіряємо, що ключі відповідають однаковій кривій
	if private.Curve != public.Curve {
		return nil, errors.New("private and public keys must use the same curve")
	}

	signer := &SignECDSA{
		apiKey:     apiKey,
		privateKey: private,
		publicKey:  public,
		curve:      private.Curve,
	}

	return signer, nil
}

// CreateSignature створює ECDSA підпис
func (sign *SignECDSA) CreateSignature(queryString string) string {
	hashed := sha256.Sum256([]byte(queryString))
	r, s, err := ecdsa.Sign(rand.Reader, sign.privateKey, hashed[:])
	if err != nil {
		// У випадку помилки повертаємо порожній підпис
		return ""
	}

	// Кодуємо r та s в base64
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Додаємо ведучі нулі для правильного кодування
	keySize := (sign.curve.Params().BitSize + 7) / 8
	if len(rBytes) < keySize {
		rBytes = append(make([]byte, keySize-len(rBytes)), rBytes...)
	}
	if len(sBytes) < keySize {
		sBytes = append(make([]byte, keySize-len(sBytes)), sBytes...)
	}

	// Об'єднуємо r та s
	signature := append(rBytes, sBytes...)
	return base64.StdEncoding.EncodeToString(signature)
}

// SignParameters підписує параметри
func (sign *SignECDSA) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	// Створюємо підпис
	message, err := ConvertSimpleJSONToString(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding params: %w", err)
	}

	signature := sign.CreateSignature(message)

	// Копіюємо параметри
	js, err := params.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("error marshalling params: %w", err)
	}

	signedParams, err := simplejson.NewJson(js)
	if err != nil {
		return nil, fmt.Errorf("error creating new json: %w", err)
	}

	signedParams.Set("signature", signature)
	return signedParams, nil
}

// ValidateSignatureParams валідує параметри з підписом
func (sign *SignECDSA) ValidateSignatureParams(params *simplejson.Json) bool {
	signature, err := params.Get("signature").String()
	if err != nil {
		return false
	}

	// Видаляємо підпис з параметрів
	js, _ := params.MarshalJSON()
	unsignedParams, _ := simplejson.NewJson(js)
	unsignedParams.Del("signature")

	message, err := ConvertSimpleJSONToString(unsignedParams)
	if err != nil {
		return false
	}

	return sign.ValidateSignature(message, signature)
}

// ValidateSignature валідує ECDSA підпис
func (sign *SignECDSA) ValidateSignature(message, signature string) bool {
	if signature == "" {
		return false
	}

	// Декодуємо підпис
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	// Розділяємо r та s
	keySize := (sign.curve.Params().BitSize + 7) / 8
	if len(signatureBytes) != keySize*2 {
		return false
	}

	r := new(big.Int).SetBytes(signatureBytes[:keySize])
	s := new(big.Int).SetBytes(signatureBytes[keySize:])

	// Валідуємо підпис
	hashed := sha256.Sum256([]byte(message))
	return ecdsa.Verify(sign.publicKey, hashed[:], r, s)
}

// GetAPIKey повертає API ключ
func (sign *SignECDSA) GetAPIKey() string {
	return sign.apiKey
}

// GetCurveName повертає назву кривої
func (sign *SignECDSA) GetCurveName() string {
	switch sign.curve {
	case elliptic.P224():
		return "P-224"
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "Unknown"
	}
}

// GetKeySize повертає розмір ключа в бітах
func (sign *SignECDSA) GetKeySize() int {
	return sign.curve.Params().BitSize
}

// loadECDSAPrivateKeyFromPEM завантажує приватний ECDSA ключ з PEM
func loadECDSAPrivateKeyFromPEM(content string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var privateKey *ecdsa.PrivateKey
	var err error

	switch block.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
		privateKey = ecKey
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// loadECDSAPublicKeyFromPEM завантажує публічний ECDSA ключ з PEM
func loadECDSAPublicKeyFromPEM(content string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var publicKey *ecdsa.PublicKey

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an ECDSA public key")
		}
		publicKey = ecKey
	case "EC PUBLIC KEY":
		// EC PUBLIC KEY формат рідко використовується, але додаємо підтримку
		return nil, errors.New("EC PUBLIC KEY format not supported, use PUBLIC KEY instead")
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	return publicKey, nil
}
