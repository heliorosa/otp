package otp

import (
	"testing"
	"time"
)

func TestTotp(t *testing.T) {
	// invalid period provided
	k, err := ImportKey("otpauth://totp/mydomain.com?secret=ADS2OR6Q6K3OJZDW&period=asd")
	if err == nil {
		t.Error("an error was expected")
		return
	} else if !checkError(err, ECInvalidPeriod) {
		t.Error("got the wrong error")
		return
	}
	// create a new key
	if k, err = NewTotp(10, "mydomain.com", "", "", 6, 30); err != nil {
		t.Error(err)
		return
	}
	// import error
	if k, err = ImportTotp(""); err == nil {
		t.Error("an error was expected, got nil")
		return
	}
	// import
	if k, err = ImportTotp("otpauth://totp/mydomain.com?digits=8&period=60&secret=ADS2OR6Q6K3OJZDW"); err != nil {
		t.Error(err)
		return
	}
	// check values
	kt := k.(*Totp)
	// same label ?
	if kt.Label != "mydomain.com" {
		t.Error("got a different label")
		return
	}
	// same digits ?
	if kt.Digits != 8 {
		t.Error("digits should be 8")
		return
	}
	// same period ?
	if kt.Period != 60 {
		t.Error("period should be 60")
		return
	}
	// same key ?
	if kt.Key32() != "ADS2OR6Q6K3OJZDW" {
		t.Error("got a bad key")
		return
	}
	// try to import a non totp url
	if k, err = ImportTotp("otpauth://hotp/mydomain.com?digits=8&period=60&secret=ADS2OR6Q6K3OJZDW"); err == nil {
		t.Error("an error was expected, got nil")
		return
	} else if !checkError(err, ECNotTotp) {
		t.Error("got the wrong error")
		return
	}
	const otpUrl = "otpauth://totp/mydomain.com?secret=ADS2OR6Q6K3OJZDW"
	if kt, err = ImportTotp(otpUrl); err != nil {
		t.Error(err)
		return
	}
	if kt.String() != otpUrl {
		t.Error("the url is different than expected")
		return
	}
	// check some codes
	periodCodes := []struct{ p, c int }{
		{1, 848969},
		{2, 292828},
		{50, 154941},
		{100, 676687},
	}
	for _, pc := range periodCodes {
		if code := kt.CodePeriod(pc.p); code != pc.c {
			t.Error("got different codes. expected:", pc.c, "got:", code)
			return
		}
	}
	timeNow = func() time.Time { return time.Unix(int64(kt.Period), 0) }
	if kt.Code() != periodCodes[0].c {
		t.Error("got the wrong code")
		return
	}
	timeNow = func() time.Time { return time.Unix(0, 0) }
	if kt.CodeN(periodCodes[0].p) != periodCodes[0].c {
		t.Error("got the wrong code")
		return
	}
}
