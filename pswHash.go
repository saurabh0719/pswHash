package pswHash

import (
	"strings"
	"strconv"
	"crypto/sha256"
	"crypto/rand"
	"golang.org/x/crypto/pbkdf2"
	"crypto/subtle"
	b64 "encoding/base64"
)

var default_iterations int = 320000 // Default 
var default_salt_length int = 12

type decoded_hash struct {
	algorithm string 
	hash string
	iterations int
	salt string
}

// Mask all bits after the first 6 with *
func mask_hash(hash string) string {

	mask := []rune(hash)
	for i:= 6; i<len(mask); i++ {
		mask[i] = '*'
	}

	return string(mask)
}

// Generate a random salt of given length
func Salt(length int) []byte {

	var salt_len int

	if length <= 0 {
		salt_len = default_salt_length
	} else {
		salt_len = length
	}

	var salt = make([]byte, salt_len)

	_, err := rand.Read(salt[:])

	if err != nil {
		panic(err)
	}

	return salt
}

// Generate the encoded string for the given password and salt
func Encode(password string, salt []byte, iterations int) (string, error) {
	
	var itr int
	var encoded string 

	if iterations <= 0 {
		itr = default_iterations
	} else {
		itr = iterations
	}

	hash := pbkdf2.Key([]byte(password), salt, itr, 32, sha256.New)
	string_hash := b64.StdEncoding.EncodeToString(hash)
	
	encoded = "pbkdf2_sha256$" + strconv.Itoa(itr) + "$" + string(salt) + "$" + string_hash
	// fmt.Println(encoded)
	return encoded, nil
	 
}

// Decode the previously Encoded String and return a struct of type decoded_hash
func Decode(encoded string) *decoded_hash {

	split := strings.Split(encoded, "$")
	itr, err := strconv.Atoi(split[1])

	if err != nil {
		panic(err)
	}
	
	decoded := decoded_hash{
		algorithm: split[0],
		iterations: itr,
		salt: split[2],
		hash: split[3],
	}

	// fmt.Println(decoded)
	return &decoded
	
}

// Verify if the given password generates the same encoded string
func Verify(password string, encoded string) int {

	var decoded = Decode(encoded)

	var new_encoded, err = Encode(password, []byte(decoded.salt), decoded.iterations)

	if err != nil {
		panic(err)
	}

	return subtle.ConstantTimeCompare([]byte(encoded), []byte(new_encoded))

}

// A safe view of the encoded string
func SafeView(encoded string) (map[string]string) {

	var decoded = Decode(encoded)

	var m = make(map[string]string)
	
	m["algorithm"] = decoded.algorithm
	m["iterations"] = strconv.Itoa(decoded.iterations)
	m["salt"] = mask_hash(decoded.salt)
	m["hash"] = mask_hash(decoded.hash)

	return m
}

