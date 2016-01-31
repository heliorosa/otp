package otp

import "testing"

func TestTotp(t *testing.T) {
	k, err := NewTotpWithDefaults("myKey", "")
	if err != nil {
		t.Error(err)
		return
	}
	if k, err = ImportTotp("otpauth://totp/myKey?digits=8&period=60&secret=ADS2OR6Q6K3OJZDW"); err != nil {
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
	if k.Period != 60 {
		t.Error("period should be 60")
		return
	}
	if k.Key32() != "ADS2OR6Q6K3OJZDW" {
		t.Error("got a bad key")
		return
	}
	if k, err = ImportTotp("otpauth://totp/myKey?digits=6&period=30&secret=ADS2OR6Q6K3OJZDW"); err != nil {
		t.Error(err)
		return
	}
	periodCodes := []struct{ p, c int }{
		{1, 848969},
		{2, 292828},
		{50, 154941},
		{100, 676687},
	}
	for _, pc := range periodCodes {
		if code := k.CodePeriod(pc.p); code != pc.c {
			t.Error("got different codes. expected:", pc.c, "got:", code)
			return
		}
	}
}
