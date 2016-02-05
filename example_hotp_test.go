package otp_test

import (
	"fmt"

	"github.com/heliorosa/otp"
)

func ExampleHotp() {
	k, err := otp.ImportHotp("otpauth://hotp/mydomain.com?secret=UYMIODYLDUSYMBVV&counter=0")
	if err != nil {
		fmt.Println(err)
		return
	}
	if err = k.SetKey32("UYMIODYLDUSYMBVV"); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(k.Counter, k.Code())
	fmt.Println(k.CodeCounter(0))
	fmt.Println(k.CodeCounter(1))
	fmt.Println(k.CodeCounter(2))
	// Output: 0 453613
	// 453613
	// 511108
	// 686989
}
