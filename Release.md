# Release Notes for Turbo-Signer v0.1.2

## Release Date: 2024-09-15

### Introduction
Turbo-Signer is a library designed to sign parameters for RESTful and WebSocket API calls. This library ensures secure and authenticated communication with various APIs by generating the necessary signatures for your requests.

### New Features
- **RSA and Ed25519 Key Handling**: Removed support for reading RSA and Ed25519 keys from files. Keys are now provided as text parameters.
- **Signature Verification**: Added functionality to verify signatures, ensuring the integrity and authenticity of the signed parameters.
- **Unit Tests**: Added comprehensive unit tests to ensure the reliability and correctness of the library.

### Usage
To use Turbo-Signer, import the library and call the appropriate functions to sign your API request parameters.

Example:
```go
package main

import (
    "fmt"
    turbosigner "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    sign := signature.NewSignHMAC("apy_key", "apy_secret")
    params := simplejson.New()
    // Add params
    params.Set("timestamp", 1610612740000)
    signedParams, err := sign.SignParameters(params)
    if err != nil {
        fmt.Println("Error signing parameters:", err)
        return
    }
    fmt.Println("Signed Parameters:", signedParams)

    // Verify signature
    valid, err := sign.ValidateSignature(signedParams)
    if err != nil {
        fmt.Println("Error validating signature:", err)
        return
    }
    fmt.Println("Signature valid:", valid)
}

```

---

# Release Notes for Turbo-Signer v0.1.1

## Release Date: 2024-08-14

### Introduction
Turbo-Signer is a library designed to sign parameters for RESTful and WebSocket API calls. This library ensures secure and authenticated communication with various APIs by generating the necessary signatures for your requests.

### New Features
- **Parameter Signing for RESTful API**: Provides functionality to sign parameters for RESTful API calls, ensuring secure and authenticated requests.
- **Parameter Signing for WebSocket API**: Supports signing parameters for WebSocket API calls, enabling secure real-time data streaming.
- **HMAC-SHA256 Signing**: Implements HMAC-SHA256 algorithm for generating signatures, providing a high level of security.
- **Easy Integration**: Simple and intuitive API for integrating parameter signing into your applications.

### Usage
To use Turbo-Signer, import the library and call the appropriate functions to sign your API request parameters.

Example:
```go
package main

import (
    "fmt"
    turbosigner "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    sign := signature.NewSignHMAC("apy_key", "apy_secret")
    params := simplejson.New()
    // Add params
    params.Set("timestamp", 1610612740000)
    signedParams, err := sign.SignParameters(params)
    fmt.Println("Signed Parameters:", signedParams)
}

```