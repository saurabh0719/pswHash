package main

import (
	"fmt"

	"github.com/tdeni/pswHash"
)

// Example code
func main() {
	str := pswHash.Encode("somerandompassword", []byte("somerandomsalt"), 216000)

	fmt.Println(str)
	fmt.Println(pswHash.SafeView(str))

	fmt.Println(pswHash.Verify("somepassword", str))
	// false

	fmt.Println(pswHash.Verify("somerandompassword", str))
	// true
}
