# pswHash

`pswHash` is a simple Go password hashing module. This module uses the `pbkdf2` algorithm along with a `sha256` digest. It is a one-way hash.

```sh
$ go get github.com/saurabh0719/pswHash
```

<div>
    <strong><a href="https://github.com/saurabh0719/pswHash">Github</a> | <a href="https://saurabh0719.github.io">Website</a> | <a href="https://github.com/saurabh0719/pswHash/releases">Releases</a> </strong>
</div>
<br>

Latest - `v1.0.1`

Since it follows the exact same schematics the [default password hasher](https://docs.djangoproject.com/en/3.2/topics/auth/passwords/) in python's Django framework, it can be used to verify passwords when moving to a Go backend but with the same old database from Django.

Read the `example.go` file in the Example folder of this repository for a clear understanding.

<hr>

## API Reference : 

### 1. Encode

```go
func Encode(password string, salt []byte, iterations int) string
```

Returns an `encoded` string in the format of `<algorithm>$<iterations>$<salt>$<hash>`. Here `<algorithm>` is `pbkdf2_sha256` and the number of iterations is `320000` by default.

### 2. Decode

```go
func Decode(encoded string) *DecodedHash
```
Where `DecodedHash` is a struct of the form :

```go

type DecodedHash struct {
	algorithm  string
	hash       string
	iterations int
	salt       string
}

```

### 3. Verify 

```go
func Verify(password string, encoded string) bool
```

Returns `true` if they match, else `false`. Uses `subtle.ConstantTimeCompare`.

### 4. SafeView

```go
func SafeView(encoded string) *DecodedHash
```

Returns a struct of type `DecodedHash` that contains the algorithm, iterations, salt and hash, however, the salt and the hash are masked with `*`.

```go
// snippet of code from "github.com/saurabh0719/pswHash/pswHash.go"

safeView := &DecodedHash{
		algorithm:  decoded.algorithm,
		iterations: decoded.iterations,
		salt:       maskHash(decoded.salt),
		hash:       maskHash(decoded.hash),
	}

```

### 5. Salt 

```go
func Salt(length int) ([]byte, error)
```
Generates and returns a random salt of the given length.

<hr>


 
