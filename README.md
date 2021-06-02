# pHash

`pHash` is a simple Go password hashing module. This module uses the `pbkdf2` algorithm along with a `sha256` digest. It is a one-way hash.

Apart from being a good password hasher, since it follows the exact same schematics the [default password hasher](https://docs.djangoproject.com/en/3.2/topics/auth/passwords/) in python's Django framework, it can be used to verify passwords when moving to a Go backend but with the same old database from Django.

<hr>

## API Reference : 

### 1. Encode

```go
func Encode(password string, salt []byte, iterations int) (string, error)
```

Returns a string in the format of `<algorithm>$<iterations>$<salt>$<hash>`. Here `<algorithm>` is `pbkdf2_sha256` and the number of iterations is `320000` by default.

### 2. Decode

```go
func Decode(encoded string) *decoded_hash
```
Where `decoded_hash` is a struct of the form :

```go

type decoded_hash struct {
	algorithm string 
	hash string
	iterations int
	salt string
}

```

### 3. Verify 

```go
func Verify(password string, encoded string) int
```

Returns `1` if they match, else `0`. Uses `subtle.ConstantTimeCompare`.

### 4. SafeView

```go
func SafeView(encoded string) (map[string]string)
```

Returns a map that contains the algorithm, iterations, salt and hash, however, the salt and the hash are masked with `*`.

```go
// snippet of code from "github.com/saurabh0719/pHash/pHash.go"

m["algorithm"] = decoded.algorithm
m["iterations"] = strconv.Itoa(decoded.iterations)
m["salt"] = mask_hash(decoded.salt)
m["hash"] = mask_hash(decoded.hash)

```

Read the `example.go` file in the Example folder of this repository for a clear understanding.


 