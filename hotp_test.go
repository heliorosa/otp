package otp

import "testing"

func TestHotp(t *testing.T) {
	k, err := NewHotpWithDefaults("myKey", "")
	if err != nil {
		t.Error(err)
		return
	}
	if k, err = ImportHotp("otpauth://hotp/myKey?counter=120&digits=8&secret=S4X6VOHUOGQD7ZNC"); err != nil {
		t.Error(err)
		return
	}
	if k.Label != "myKey" {
		t.Error("got a different label")
		return
	}
	if k.Digits != 8 {
		t.Error("digits should be 8")
		return
	}
	if k.Counter != 120 {
		t.Error("counter should be 120")
		return
	}
	if k.Key32() != "S4X6VOHUOGQD7ZNC" {
		t.Error("got a bad key")
		return
	}
	if k, err = ImportHotp("otpauth://hotp/myKey?counter=0&digits=6&secret=5STMOV5AVXA2IYVU"); err != nil {
		t.Error(err)
		return
	}
	codes := []int{
		100502,
		801920,
		311346,
		815149,
		222375,
		783409,
	}
	for _, c := range codes {
		if cc := k.Code(); cc != c {
			t.Error("got wrong code: exp:", c, "got:", cc)
			return
		}
		k.Counter++
	}
}
