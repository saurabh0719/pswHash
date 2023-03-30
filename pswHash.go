package pswHash

/*

This package is an implementation of python's Django framework's default password hasher.
It's purpose is to help people porting their services from Django to Go, and can also be
used in simple projects.

However for industry grade protection, it is better to use the bcrypt library.

*/

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	b64 "encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const defaultIterations int = 320000 // Default
const defaultSaltLength int = 12

type DecodedHash struct {
	algorithm  string
	hash       string
	iterations int
	salt       string
}

// Mask all bits after the first 6 with *
func maskHash(hash string) string {

	mask := []rune(hash)
	for i := 6; i < len(mask); i++ {
		mask[i] = '*'
	}

	return string(mask)
}

// Generate a random salt of given length
func Salt(length int) ([]byte, error) {

	var saltLen int

	if length <= 0 {
		saltLen = defaultSaltLength
	} else {
		saltLen = length
	}

	salt := make([]byte, saltLen)

	_, err := rand.Read(salt[:])

	if err != nil {
		return nil, errors.New("error generating a random salt")
	}

	return []byte(b64.StdEncoding.EncodeToString(salt)), nil
}

// Generate the encoded string for the given password and salt
func Encode(password string, salt []byte, iterations int) string {

	var itr int
	var encoded string

	if iterations <= 0 {
		itr = defaultIterations
	} else {
		itr = iterations
	}

	hash := pbkdf2.Key([]byte(password), salt, itr, 32, sha256.New)
	stringHash := b64.StdEncoding.EncodeToString(hash)

	encoded = "pbkdf2_sha256$" + strconv.Itoa(itr) + "$" + string(salt) + "$" + stringHash

	return encoded

}

// Decode the previously Encoded String and return a struct of type DecodedHash
func Decode(encoded string) *DecodedHash {

	split := strings.Split(encoded, "$")
	itr, err := strconv.Atoi(split[1])

	if err != nil {
		panic(err)
	}

	decoded := &DecodedHash{
		algorithm:  split[0],
		iterations: itr,
		salt:       split[2],
		hash:       split[3],
	}

	return decoded

}

// Verify if the given password generates the same encoded string
func Verify(password string, encoded string) bool {

	decoded := Decode(encoded)

	newEncoded := Encode(password, []byte(decoded.salt), decoded.iterations)

	retVal := subtle.ConstantTimeCompare([]byte(encoded), []byte(newEncoded))

	if retVal == 1 {
		return true
	} else {
		return false
	}

}

// A safe view of the encoded string
func SafeView(encoded string) *DecodedHash {

	decoded := Decode(encoded)

	safeView := &DecodedHash{
		algorithm:  decoded.algorithm,
		iterations: decoded.iterations,
		salt:       maskHash(decoded.salt),
		hash:       maskHash(decoded.hash),
	}

	return safeView
}
