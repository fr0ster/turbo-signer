package signature_test

import (
	"testing"

	"github.com/bitly/go-simplejson"
	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// Test 1: Sign HMAC
func TestParamsSignHMAC(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret")
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err := sign.SignParameters(params)
		assert.Nil(t, err)
		expected := `{"signature":"b9739a6b6322ff0490293f52807fc895cddf41cdb34c178b346589148fec3b66","timestamp":1610612740000}`
		result, err := params.MarshalJSON()
		assert.Nil(t, err)
		assert.Equal(t, expected, string(result))
	}()
}

// Test 2: Validate HMAC
func TestParamsValidateHMAC(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret")
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err := sign.SignParameters(params)
		assert.Nil(t, err)
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.True(t, valid)
	}()
}

// Test 3: Validate HMAC with wrong signature
func TestParamsValidateHMACWrongSignature(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret")
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err := sign.SignParameters(params)
		assert.Nil(t, err)
		// Зміна підпису
		params.Set("signature", "wrong_signature")
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.False(t, valid)
	}()
}

// Test 4: Sign Ed25519
func TestParamsSignEd25519(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignEd25519(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		expected := `{"signature":"pYQHhxozljZc0/wqTz4I1i1GmJbzQpdT8AHILc1ZZHF7YvjsUDRtTVBJpktdx10Z1Iy37wbJJjRtbMDpyx9BCQ==","timestamp":1610612740000}`
		result, err := params.MarshalJSON()
		assert.Nil(t, err)
		assert.Equal(t, expected, string(result))
	}()
}

// Test 5: Validate Ed25519
func TestParamsValidateEd25519(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignEd25519(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.True(t, valid)
	}()
}

// Test 6: Validate Ed25519 with wrong signature
func TestParamsValidateEd25519WrongSignature(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignEd25519(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		// Зміна підпису
		params.Set("signature", "wrong_signature")
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.False(t, valid)
	}()
}

// Test 7: Sign RSA
func TestParamsSignRSA(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBjXiXgAHU/pslRsD6wO
Ef4JFsYMHHgun0Q8PxKsukScwd1Eqpv0Gd0j6I/i/YtyAf6GmrMOUzIdCrULenDR
+xFtb+rBMQ+/JLiqsGm3Nc+glJsE4XVQOPZ3ILwqlvQ5K7LpSi3YO+Bko3vwCD7B
RpqfotBDi+SbK//3A8QyiiEVqh6XK2cG0qkhX3W4NahxOwc2LIpTKd6arZtg3DMc
RzG7fyGm/qbFXKH2Q3bjzO4uMUJhPUTUizGQH+vpMgIxfEgADtyr4J/Mz+UuzDWK
6akQi7UeE93aAEqTezqrUFhqc1sWXLB/8eE29H/HRW+mO0X0Oyv5Q8pDLiW8B42V
pwIDAQAB
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0GNeJeAAdT+my
VGwPrA4R/gkWxgwceC6fRDw/Eqy6RJzB3USqm/QZ3SPoj+L9i3IB/oaasw5TMh0K
tQt6cNH7EW1v6sExD78kuKqwabc1z6CUmwThdVA49ncgvCqW9DkrsulKLdg74GSj
e/AIPsFGmp+i0EOL5Jsr//cDxDKKIRWqHpcrZwbSqSFfdbg1qHE7BzYsilMp3pqt
m2DcMxxHMbt/Iab+psVcofZDduPM7i4xQmE9RNSLMZAf6+kyAjF8SAAO3Kvgn8zP
5S7MNYrpqRCLtR4T3doASpN7OqtQWGpzWxZcsH/x4Tb0f8dFb6Y7RfQ7K/lDykMu
JbwHjZWnAgMBAAECggEAMrK/kjpOxfGmFwZ++RZ1S4lY46lS5XzLmxgpYZQPPcxs
2IJCf0ixucov/prqyndD293b5Ja9VJxJ4qa+mXRDGEt6pEPQqNAG/f5iRpEr+yD8
0nilMhbFQ5PWS0fNMXuE0JFn7PLk6U4s5nzQQHHyFL8Ya0v3h90N9Z/z2IKVu55E
/BF3Gub0/xsnD1qRj4QAk/rh5DP6X5O0q9ItqA9t92OWsfKo11HjfEAJohJeUGLA
KlGxImSeYjSG8mErVwQoHfQ8jEJZqsn3DAe4/vwEQ3ow1R0Ra0+XAWriT0PnpOFW
eGYh71eoagMAw2aW9IgPPH/gL9gtRHnSL7ecXMdWYQKBgQDwzz6+6PjA+18B5EA6
S4uHtYaX7eEbT/fWLDroicrZqSDv4Vjk+7ZwXyJMIyZjnBdrT7ShfoFC3f5o4lrF
tyi3CzWjHY6M6R5+eq7m3i4iZn9A1rRTjMzYhgMg58cI59uwU/QCG+Ukm8L2Lb6D
o7tsmC7SnzbYEcDxE5il/ov3kQKBgQC/dSuXiUuK2IzZzWqDekcYHh6AiO17BIOJ
RmC2kRWZmGV+bhnd1VTzQk2PQraYfcDQxSMwLpS2bELNq++OLzfKz3rQt8MuQZ9W
DEvfLunSLAPiOjcGfqvYPOEBEUbw1rumdsIWd3jIlmLtzj49vxtz3gVDYzMD9p4l
f50ObPlNtwKBgHtomi1YU3MC37Omd8voPz9zJeDihcRrfQWDcUUOqKhXZovInrfq
z5pTBs6iDOBrdA0Isfc5T6EnB2RU7FP7A6Ca3AgV86H/LiN/V/b00gvLH1fpMEzJ
EYm9VAke/v9vY0TAIYKbLRlPweBLnSD1Xe3PJ9/EvGSK5KgndMlM5AohAoGAJnW2
HQnCeBDKMpJ2HBU7JNggDnfzJKwidDgEA4ifiyw27y/U2GAbYYZnKCkhnv5b9lQz
nmEtFHwo60HnrGtFzOLi6/yOI8Og61sq/plg9QxMd2x0U0Ss5pJMLLe4xXaNWYIv
uO2lAL5c/yJYFHVIYX0vF3tc6yXmXOgGt7giWH8CgYASD3KZTZugdqWuBE9HNepp
W7uJwSLfGQs47i/LkgHDBlSRZOqODY9Y4KIcWuCK7gSu1duCzF+y6KTx5jW5ZYgJ
bvhsA8v6qN+jkbA2DR2CVFStAJXGRmic0D/KJ1lrOTzBIXLw8ZAO/HtwqE7Z1/eK
bSPd4xwzzEbd4WCAodhFMw==
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignRSA(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		expected := `{"signature":"mEBDK0Ip4YIcvjMIEC2xEQ+1wNL4zdB4Qg8JM/KtR7gKvDzRNxhF/2UKVTyxEFfdmmk9bga+CHe5jotGsZUCKkMd2McFcDDNAmgjPWidvqzFImmb0m6mTIOwu4EaQYng4mR+EzRoiue3S/txy4iQIdkL/8W9995TVrBpysj46SCf1KeeBbYrRBPJTPBHCBqbApeMqDbBv0PBsvBMulJxwbZclVIX9OD457iQd07iFaMmKZ3WD+8AhQOqmDD0ecXTba//q2khyWMFXeIbXIoNUij2bN/GaMJO9wwdk2EUMqY3N/cVsyB/JmTVmbqmT98zH9ZSgQrnxB/RfUTUUwsS4A==","timestamp":1610612740000}`
		result, err := params.MarshalJSON()
		assert.Nil(t, err)
		assert.Equal(t, expected, string(result))
	}()
}

// Test 8: Validate RSA
func TestParamsValidateRSA(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBjXiXgAHU/pslRsD6wO
Ef4JFsYMHHgun0Q8PxKsukScwd1Eqpv0Gd0j6I/i/YtyAf6GmrMOUzIdCrULenDR
+xFtb+rBMQ+/JLiqsGm3Nc+glJsE4XVQOPZ3ILwqlvQ5K7LpSi3YO+Bko3vwCD7B
RpqfotBDi+SbK//3A8QyiiEVqh6XK2cG0qkhX3W4NahxOwc2LIpTKd6arZtg3DMc
RzG7fyGm/qbFXKH2Q3bjzO4uMUJhPUTUizGQH+vpMgIxfEgADtyr4J/Mz+UuzDWK
6akQi7UeE93aAEqTezqrUFhqc1sWXLB/8eE29H/HRW+mO0X0Oyv5Q8pDLiW8B42V
pwIDAQAB
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0GNeJeAAdT+my
VGwPrA4R/gkWxgwceC6fRDw/Eqy6RJzB3USqm/QZ3SPoj+L9i3IB/oaasw5TMh0K
tQt6cNH7EW1v6sExD78kuKqwabc1z6CUmwThdVA49ncgvCqW9DkrsulKLdg74GSj
e/AIPsFGmp+i0EOL5Jsr//cDxDKKIRWqHpcrZwbSqSFfdbg1qHE7BzYsilMp3pqt
m2DcMxxHMbt/Iab+psVcofZDduPM7i4xQmE9RNSLMZAf6+kyAjF8SAAO3Kvgn8zP
5S7MNYrpqRCLtR4T3doASpN7OqtQWGpzWxZcsH/x4Tb0f8dFb6Y7RfQ7K/lDykMu
JbwHjZWnAgMBAAECggEAMrK/kjpOxfGmFwZ++RZ1S4lY46lS5XzLmxgpYZQPPcxs
2IJCf0ixucov/prqyndD293b5Ja9VJxJ4qa+mXRDGEt6pEPQqNAG/f5iRpEr+yD8
0nilMhbFQ5PWS0fNMXuE0JFn7PLk6U4s5nzQQHHyFL8Ya0v3h90N9Z/z2IKVu55E
/BF3Gub0/xsnD1qRj4QAk/rh5DP6X5O0q9ItqA9t92OWsfKo11HjfEAJohJeUGLA
KlGxImSeYjSG8mErVwQoHfQ8jEJZqsn3DAe4/vwEQ3ow1R0Ra0+XAWriT0PnpOFW
eGYh71eoagMAw2aW9IgPPH/gL9gtRHnSL7ecXMdWYQKBgQDwzz6+6PjA+18B5EA6
S4uHtYaX7eEbT/fWLDroicrZqSDv4Vjk+7ZwXyJMIyZjnBdrT7ShfoFC3f5o4lrF
tyi3CzWjHY6M6R5+eq7m3i4iZn9A1rRTjMzYhgMg58cI59uwU/QCG+Ukm8L2Lb6D
o7tsmC7SnzbYEcDxE5il/ov3kQKBgQC/dSuXiUuK2IzZzWqDekcYHh6AiO17BIOJ
RmC2kRWZmGV+bhnd1VTzQk2PQraYfcDQxSMwLpS2bELNq++OLzfKz3rQt8MuQZ9W
DEvfLunSLAPiOjcGfqvYPOEBEUbw1rumdsIWd3jIlmLtzj49vxtz3gVDYzMD9p4l
f50ObPlNtwKBgHtomi1YU3MC37Omd8voPz9zJeDihcRrfQWDcUUOqKhXZovInrfq
z5pTBs6iDOBrdA0Isfc5T6EnB2RU7FP7A6Ca3AgV86H/LiN/V/b00gvLH1fpMEzJ
EYm9VAke/v9vY0TAIYKbLRlPweBLnSD1Xe3PJ9/EvGSK5KgndMlM5AohAoGAJnW2
HQnCeBDKMpJ2HBU7JNggDnfzJKwidDgEA4ifiyw27y/U2GAbYYZnKCkhnv5b9lQz
nmEtFHwo60HnrGtFzOLi6/yOI8Og61sq/plg9QxMd2x0U0Ss5pJMLLe4xXaNWYIv
uO2lAL5c/yJYFHVIYX0vF3tc6yXmXOgGt7giWH8CgYASD3KZTZugdqWuBE9HNepp
W7uJwSLfGQs47i/LkgHDBlSRZOqODY9Y4KIcWuCK7gSu1duCzF+y6KTx5jW5ZYgJ
bvhsA8v6qN+jkbA2DR2CVFStAJXGRmic0D/KJ1lrOTzBIXLw8ZAO/HtwqE7Z1/eK
bSPd4xwzzEbd4WCAodhFMw==
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignRSA(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.True(t, valid)
	}()
}

// Test 9: Validate RSA with wrong signature
func TestParamsValidateRSAWrongSignature(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBjXiXgAHU/pslRsD6wO
Ef4JFsYMHHgun0Q8PxKsukScwd1Eqpv0Gd0j6I/i/YtyAf6GmrMOUzIdCrULenDR
+xFtb+rBMQ+/JLiqsGm3Nc+glJsE4XVQOPZ3ILwqlvQ5K7LpSi3YO+Bko3vwCD7B
RpqfotBDi+SbK//3A8QyiiEVqh6XK2cG0qkhX3W4NahxOwc2LIpTKd6arZtg3DMc
RzG7fyGm/qbFXKH2Q3bjzO4uMUJhPUTUizGQH+vpMgIxfEgADtyr4J/Mz+UuzDWK
6akQi7UeE93aAEqTezqrUFhqc1sWXLB/8eE29H/HRW+mO0X0Oyv5Q8pDLiW8B42V
pwIDAQAB
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0GNeJeAAdT+my
VGwPrA4R/gkWxgwceC6fRDw/Eqy6RJzB3USqm/QZ3SPoj+L9i3IB/oaasw5TMh0K
tQt6cNH7EW1v6sExD78kuKqwabc1z6CUmwThdVA49ncgvCqW9DkrsulKLdg74GSj
e/AIPsFGmp+i0EOL5Jsr//cDxDKKIRWqHpcrZwbSqSFfdbg1qHE7BzYsilMp3pqt
m2DcMxxHMbt/Iab+psVcofZDduPM7i4xQmE9RNSLMZAf6+kyAjF8SAAO3Kvgn8zP
5S7MNYrpqRCLtR4T3doASpN7OqtQWGpzWxZcsH/x4Tb0f8dFb6Y7RfQ7K/lDykMu
JbwHjZWnAgMBAAECggEAMrK/kjpOxfGmFwZ++RZ1S4lY46lS5XzLmxgpYZQPPcxs
2IJCf0ixucov/prqyndD293b5Ja9VJxJ4qa+mXRDGEt6pEPQqNAG/f5iRpEr+yD8
0nilMhbFQ5PWS0fNMXuE0JFn7PLk6U4s5nzQQHHyFL8Ya0v3h90N9Z/z2IKVu55E
/BF3Gub0/xsnD1qRj4QAk/rh5DP6X5O0q9ItqA9t92OWsfKo11HjfEAJohJeUGLA
KlGxImSeYjSG8mErVwQoHfQ8jEJZqsn3DAe4/vwEQ3ow1R0Ra0+XAWriT0PnpOFW
eGYh71eoagMAw2aW9IgPPH/gL9gtRHnSL7ecXMdWYQKBgQDwzz6+6PjA+18B5EA6
S4uHtYaX7eEbT/fWLDroicrZqSDv4Vjk+7ZwXyJMIyZjnBdrT7ShfoFC3f5o4lrF
tyi3CzWjHY6M6R5+eq7m3i4iZn9A1rRTjMzYhgMg58cI59uwU/QCG+Ukm8L2Lb6D
o7tsmC7SnzbYEcDxE5il/ov3kQKBgQC/dSuXiUuK2IzZzWqDekcYHh6AiO17BIOJ
RmC2kRWZmGV+bhnd1VTzQk2PQraYfcDQxSMwLpS2bELNq++OLzfKz3rQt8MuQZ9W
DEvfLunSLAPiOjcGfqvYPOEBEUbw1rumdsIWd3jIlmLtzj49vxtz3gVDYzMD9p4l
f50ObPlNtwKBgHtomi1YU3MC37Omd8voPz9zJeDihcRrfQWDcUUOqKhXZovInrfq
z5pTBs6iDOBrdA0Isfc5T6EnB2RU7FP7A6Ca3AgV86H/LiN/V/b00gvLH1fpMEzJ
EYm9VAke/v9vY0TAIYKbLRlPweBLnSD1Xe3PJ9/EvGSK5KgndMlM5AohAoGAJnW2
HQnCeBDKMpJ2HBU7JNggDnfzJKwidDgEA4ifiyw27y/U2GAbYYZnKCkhnv5b9lQz
nmEtFHwo60HnrGtFzOLi6/yOI8Og61sq/plg9QxMd2x0U0Ss5pJMLLe4xXaNWYIv
uO2lAL5c/yJYFHVIYX0vF3tc6yXmXOgGt7giWH8CgYASD3KZTZugdqWuBE9HNepp
W7uJwSLfGQs47i/LkgHDBlSRZOqODY9Y4KIcWuCK7gSu1duCzF+y6KTx5jW5ZYgJ
bvhsA8v6qN+jkbA2DR2CVFStAJXGRmic0D/KJ1lrOTzBIXLw8ZAO/HtwqE7Z1/eK
bSPd4xwzzEbd4WCAodhFMw==
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignRSA(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		// Зміна підпису
		params.Set("signature", "wrong_signature")
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.False(t, valid)
	}()
}
