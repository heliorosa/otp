package otp

import "testing"

func TestHotp(t *testing.T) {
	// counter is missing
	k, err := ImportKey("otpauth://hotp/mydomain.com?secret=ADS2OR6Q6K3OJZDW")
	if err == nil {
		t.Error("an error was expected")
		return
	} else if !checkError(err, ECMissingCounter) {
		t.Error("got the wrong error")
		return
	}
	// bad counter provided
	if k, err = ImportKey("otpauth://hotp/mydomain.com?secret=ADS2OR6Q6K3OJZDW&counter=asd"); err == nil {
		t.Error("an error was expected")
		return
	} else if !checkError(err, ECInvalidCounter) {
		t.Error("got the wrong error")
		return
	}
	// create a new key
	if k, err = NewHotp(DefaultKeyLength, "mydomain.com", "", "", DefaultDigits, 0); err != nil {
		t.Error(err)
		return
	}
	// import an url
	if k, err = ImportHotp("otpauth://hotp/mydomain.com?counter=120&digits=8&secret=S4X6VOHUOGQD7ZNC"); err != nil {
		t.Error(err)
		return
	}
	// check values
	kh := k.(*Hotp)
	// same label ?
	if kh.Label != "mydomain.com" {
		t.Error("got a different label")
		return
	}
	// same digits ?
	if kh.Digits != 8 {
		t.Error("digits should be 8")
		return
	}
	// same counter ?
	if kh.Counter != 120 {
		t.Error("counter should be 120")
		return
	}
	// same key ?
	if kh.Key32() != "S4X6VOHUOGQD7ZNC" {
		t.Error("got a bad key")
		return
	}
	// import non hotp url
	if k, err = ImportHotp("otpauth://totp/mydomain.com?counter=120&digits=8&secret=S4X6VOHUOGQD7ZNC"); err == nil {
		t.Error(err)
		return
	} else if !checkError(err, ECNotHotp) {
		t.Error("got the wrong error")
		return
	}
	const otpUrl = "otpauth://hotp/myKey?counter=0&secret=5STMOV5AVXA2IYVU"
	if kh, err = ImportHotp(otpUrl); err != nil {
		t.Error(err)
		return
	}
	if kh.String() != otpUrl {
		t.Error("got a different url")
		return
	}
	// check some codes
	codes := []int{
		100502,
		801920,
		311346,
		815149,
		222375,
		783409,
	}
	for _, c := range codes {
		if cc := kh.Code(); cc != c {
			t.Error("got wrong code: exp:", c, "got:", cc)
			return
		}
		kh.Counter++
	}
	if kh.CodeCounter(0) != codes[0] {
		t.Error("got the wrong code")
		return
	}
	kh.Counter = 0
	if kh.CodeN(5) != codes[5] {
		t.Error("got the wrong code")
		return
	}
}
