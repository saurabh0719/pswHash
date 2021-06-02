package main 

import (
	"fmt"
	"github.com/saurabh0719/pswHash"
)

// Example code

func main() {

	str, err := pswHash.Encode("somerandompassword", []byte("somerandomsalt"), 216000)

	if err != nil {
		fmt.Println("Some error occured")
	}

	fmt.Println(str)
	fmt.Println(pswHash.SafeView(str))

	fmt.Println(pswHash.Verify("somepassword", str))
	// 0

	fmt.Println(pswHash.Verify("somerandompassword", str))
	// 1

}

