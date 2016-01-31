package otp_test

import (
	"fmt"
	"net/url"

	"github.com/heliorosa/otp"
)

func ExampleNewKey() {
	k, err := otp.NewKey(
		otp.TypeHotp,   // key type
		0,              // key length, defaults to 10 bytes
		"mydomain.com", // label
		"",             // issuer
		"",             // algorithm, defaults to sha1
		0,              // code length, defaults to 6
		url.Values{"period": []string{"0"}}, // period is required
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(k)
}
