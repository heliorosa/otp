package otp_test

import (
	"fmt"
	"net/url"

	"github.com/heliorosa/otp"
)

func Example() {
	// create a new key
	k, err := otp.NewKeyWithDefaults(otp.TypeHotp, "mydomain.com", "", url.Values{"counter": []string{"1"}})
	if err != nil {
		fmt.Println(err)
		return
	}
	// set key from a base32 string
	if err = k.SetKey32("UYMIODYLDUSYMBVV"); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(k.Code(), k)

	// import key from url
	k, err = otp.ImportKey("otpauth://totp/mydomain.com?secret=UYMIODYLDUSYMBVV")
	if err != nil {
		fmt.Println(err)
		return
	}
	kt := k.(*otp.Totp)
	fmt.Println(kt.CodePeriod(0), kt)
	// Output: 511108 otpauth://hotp/mydomain.com?counter=1&secret=UYMIODYLDUSYMBVV
	// 453613 otpauth://totp/mydomain.com?secret=UYMIODYLDUSYMBVV
}
