package otp_test

import (
	"fmt"

	"github.com/heliorosa/otp"
)

func ExampleTotp() {
	k, err := otp.ImportTotp("otpauth://totp/mydomain.com?secret=UYMIODYLDUSYMBVV")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(k.CodePeriod(0))
	fmt.Println(k.CodePeriod(1))
	fmt.Println(k.CodePeriod(2))
	// Output: 453613
	// 511108
	// 686989
}
