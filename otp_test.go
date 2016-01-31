package otp

import (
	"net/url"
	"testing"
)

func TestOtp(t *testing.T) {
	_, err := NewKeyWithDefaults(TypeTotp, "mydomain.com", "", url.Values{})
	if err != nil {
		t.Error(err)
		return
	}
	if _, err = NewKeyWithDefaults(TypeHotp, "mydomain.com", "", url.Values{}); err != nil {
		t.Error(err)
		return
	}
	var k Key
	if k, err = ImportKey("otpauth://totp/mydomain.com?digits=8&period=60&secret=ADS2OR6Q6K3OJZDW"); err != nil {
		t.Error(err)
		return
	}
	if k.Type() != TypeTotp {
		t.Error("wrong type returned")
		return
	}
	if k, err = ImportKey("otpauth://hotp/myKey?counter=120&digits=8&secret=S4X6VOHUOGQD7ZNC"); err != nil {
		t.Error(err)
		return
	}
	if k.Type() != TypeHotp {
		t.Error("wrong type returned")
		return
	}
}
