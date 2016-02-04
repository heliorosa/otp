package otp

import (
	"net/url"
	"testing"
)

func checkError(err error, code int) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == code
	}
	return false
}

func TestOtp(t *testing.T) {
	k, err := NewKey(TypeTotp, 10, "", "", "", DefaultDigits, url.Values{})
	if err == nil {
		t.Error("an error was expected")
		return
	} else if !checkError(err, ECMissingLabel) {
		t.Error("got the wrong error")
		return
	}
	if k, err = NewKey(TypeTotp, 10, "mydomain.com", "", "md5", DefaultDigits, url.Values{}); err == nil {
		t.Error("an error was expected")
		return
	} else if !checkError(err, ECInvalidAlgorithm) {
		t.Error("got the wrong error")
		return
	}
	checkImport := func(u string, ec int) bool {
		if _, err := ImportKey(u); err == nil {
			t.Error("an error was expected")
			return false
		} else if !checkError(err, ec) {
			t.Error("got the wrong error")
			return false
		}
		return true
	}
	badUrls := []struct {
		u  string
		ec int
	}{
		// check for bad authentication type
		{"otpauth://asdad/mydomain.com?secret=ADS2OR6Q6K3OJZDW", ECInvalidOtpType},
		{"otpauth://totp/mydomain.com?secret=A!S2OR6Q6K3OJZDW", ECBase32Decoding},
		{"otpauth://totp/mydomain.com?secret=ADS2OR6Q6K3OJZDW&digits=ad", ECInvalidDigits},
		{"otpauth://totp/mydomain.com?secret=ADS2OR6Q6K3OJZDW&algorithm=asd", ECInvalidAlgorithm},
		{"otpauth://totp/mydomain.com", ECMissingSecret},
	}
	for _, bu := range badUrls {
		if !checkImport(bu.u, bu.ec) {
			return
		}
	}
	if k, err = ImportKey("otpauth://totp/mydomain.com?secret=ADS2OR6Q6K3OJZDW&algorithm=sha1&issuer=aassdd"); err != nil {
		t.Error(err)
		return
	}
	kt := k.(*Totp)
	if kt.Algorithm != "sha1" {
		t.Error("got a different algorithm")
		return
	}
	if kt.Issuer != "aassdd" {
		t.Error("got a different issuer")
		return
	}
	if err = k.SetKey32("A!S2OR6Q6K3OJZDW"); err == nil {
		t.Error("an error was expected")
		return
	} else if e, ok := err.(*Error); !ok || e.Code != ECBase32Decoding {
		t.Error("got the wrong error")
		return
	}
	checkNew := func(typ string, args url.Values, ec int) bool {
		if _, err := NewKeyWithDefaults(typ, "mydomain.com", "", args); err == nil {
			t.Error("an error was expected")
			return false
		} else if e, ok := err.(*Error); !ok || e.Code != ec {
			t.Error("got the wrong error:", e)
			return false
		}
		return true
	}
	badArgs := []struct {
		t  string
		a  url.Values
		ec int
	}{
		{TypeTotp, url.Values{"period": []string{"asd"}}, ECInvalidPeriod},
		{TypeHotp, url.Values{}, ECMissingCounter},
		{TypeHotp, url.Values{"counter": []string{"asd"}}, ECInvalidCounter},
		{"invalid", url.Values{}, ECInvalidOtpType},
	}
	for _, ba := range badArgs {
		if !checkNew(ba.t, ba.a, ba.ec) {
			return
		}
	}
}
