# Release Notes for Turbo-Signer

## v0.1.6 - 2024-08-21

### Feat
- Made `convertSimpleJSONToString` function public by renaming it to `ConvertSimpleJSONToString`.

---

## v0.1.5

### Release Date: 2024-09-15

### Changes
- Refactor `signParameters` function in `signature/utils.go`.
  - This commit refactors the `signParameters` function in the `signature/utils.go` file. The function is renamed to `SignParameters` to follow the naming convention for exported functions in Go. This change ensures consistency and improves code readability.

---

## v0.1.4

### Release Date: 2024-09-15

### Changes
- **Refactored ValidateSignatureParams**: The function `ValidateSignatureParams` now uses parameter copying instead of modifying the parameter passed by pointer. This change prevents side effects and ensures that the original parameters remain unchanged.


---

# Release Notes for Turbo-Signer v0.1.3

## Release Date: 2024-09-15

## Changes
- **Renamed Function**: The function `ValidateSignature` has been renamed to `ValidateSignatureParams` to better reflect its purpose.
- **New Function**: Added a new function `ValidateSignature(string, string) bool` to provide a more straightforward way to validate signatures.

## Example Usage
### ValidateSignatureParams
```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer"
)

func main() {
    sign := signature.NewSignHMAC("apy_key", "apy_secret")
	params := simplejson.New()
    params := simplejson.New()
    params.Set("timestamp", 1610612740000)

    // Створення підпису
    params, err := sign.SignParameters(params)

    // Валідація підпису
    valid := sign.ValidateSignatureParams(params)
    fmt.Println("Signature valid:", valid)
}

```
### ValidateSignature
```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer"
)

func main() {
    sign := signature.NewSignHMAC("apy_key", "apy_secret")
    data := "example_data"

    // Створення підпису
    signature := sign.CreateSignature(data)

    valid := turbo_signer.ValidateSignature(data, signature)
    fmt.Println("Signature valid:", valid)
}

```

---

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