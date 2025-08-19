#!/bin/bash

echo "Fixing all test files..."

# Fix ed25519_string_test.go
sed -i 's/signature := sign.CreateSignature(message)/signature, err := sign.CreateSignature(message)/g' signature/ed25519_string_test.go
sed -i 's/valid := sign.ValidateSignature(message, signature)/valid, err := sign.ValidateSignature(message, signature)/g' signature/ed25519_string_test.go
sed -i 's/assert.True(t, valid)/assert.NoError(t, err)\n\t\tassert.True(t, valid)/g' signature/ed25519_string_test.go
sed -i 's/assert.False(t, valid)/assert.NoError(t, err)\n\t\tassert.False(t, valid)/g' signature/ed25519_string_test.go

# Fix ed25519_params_test.go
sed -i 's/valid := sign.ValidateSignatureParams(params)/valid, err := sign.ValidateSignatureParams(params)/g' signature/ed25519_params_test.go
sed -i 's/assert.True(t, valid)/assert.NoError(t, err)\n\t\tassert.True(t, valid)/g' signature/ed25519_params_test.go
sed -i 's/assert.False(t, valid)/assert.NoError(t, err)\n\t\tassert.False(t, valid)/g' signature/ed25519_params_test.go

# Fix rsa_string_test.go
sed -i 's/signature := sign.CreateSignature(message)/signature, err := sign.CreateSignature(message)/g' signature/rsa_string_test.go
sed -i 's/valid := sign.ValidateSignature(message, signature)/valid, err := sign.ValidateSignature(message, signature)/g' signature/rsa_string_test.go
sed -i 's/assert.True(t, valid)/assert.NoError(t, err)\n\t\tassert.True(t, valid)/g' signature/rsa_string_test.go
sed -i 's/assert.False(t, valid)/assert.NoError(t, err)\n\t\tassert.False(t, valid)/g' signature/rsa_string_test.go

# Fix rsa_params_test.go
sed -i 's/valid := sign.ValidateSignatureParams(params)/valid, err := sign.ValidateSignatureParams(params)/g' signature/rsa_params_test.go
sed -i 's/assert.True(t, valid)/assert.NoError(t, err)\n\t\tassert.True(t, valid)/g' signature/rsa_params_test.go
sed -i 's/assert.False(t, valid)/assert.NoError(t, err)\n\t\tassert.False(t, valid)/g' signature/rsa_params_test.go

echo "Tests fixed! Now run: go test ./signature/... -v"
