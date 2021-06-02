package main 

import (
	"fmt"
	"github.com/saurabh0719/pHash"
)

// Example code

func main() {

	str, err := pHash.Encode("somerandompassword", []byte("somerandomsalt"), 216000)

	if err != nil {
		fmt.Println("Some error occured")
	}

	fmt.Println(str)
	fmt.Println(pHash.SafeView(str))

	fmt.Println(pHash.Verify("somepassword", str))
	// 0

	fmt.Println(pHash.Verify("somerandompassword", str))
	// 1

}

