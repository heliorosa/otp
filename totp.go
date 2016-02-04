package otp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"
)

// TOTP specific defaults
const (
	// default period is 30 seconds
	DefaultPeriod = 30
)

// Totp is a totp key
type Totp struct {
	*otpKey
	Period int
}

// NewTotp creates a new TOTP key
// keyLen <= 0, defaults to 10
// digits <= 0, defaults to 6
// period <= 0, defaults to 30
// algorithm == "", defaults to "sha1"
func NewTotp(keyLen int, label, issuer, algorithm string, digits, period int) (*Totp, error) {
	k, err := newOtpKey(keyLen, label, issuer, algorithm, digits)
	if err != nil {
		return nil, err
	}
	// default period
	p := DefaultPeriod
	if period > 0 {
		p = period
	}
	return &Totp{k, p}, nil
}

// NewTotpWithDefaults calls NewTotp() with the default values
func NewTotpWithDefaults(label, issuer string) (*Totp, error) {
	return NewTotp(0, label, issuer, "", 0, 0)
}

func importTotp(k *otpKey, p url.Values) (*Totp, error) {
	r := &Totp{otpKey: k}
	td := p.Get("period")
	if td == "" {
		r.Period = DefaultPeriod
	} else if i, err := strconv.Atoi(td); err != nil {
		return nil, &Error{ECInvalidPeriod, fmt.Sprintf("invalid period: %v", td), err}
	} else {
		r.Period = i
	}
	return r, nil
}

// ImportTotp imports an url in the otpauth format
func ImportTotp(u string) (*Totp, error) {
	k, t, p, err := importOtpKey(u)
	if err != nil {
		return nil, err
	}
	if t != TypeTotp {
		return nil, &Error{ECNotTotp, "not a totp key", nil}
	}
	return importTotp(k, p)
}

// Url returns the key in otpauth format
func (t *Totp) Url() string { return t.url(TypeTotp, url.Values{}) }

// String returns the same as Url()
func (t *Totp) String() string { return t.Url() }

// CodePeriod returns the code for the period p
func (t *Totp) CodePeriod(p int) int {
	c := t.hashTruncateInt(p)
	return int(binary.BigEndian.Uint32(c)) % int(math.Pow10(t.Digits))
}

// CodeTime returns the code for the time tm
func (t *Totp) CodeTime(tm time.Time) int { return t.CodePeriod(int(tm.Unix() / int64(t.Period))) }

var timeNow = time.Now

// Code returns the current code
func (t *Totp) Code() int { return t.CodeTime(timeNow()) }

// Type returns "totp"
func (t *Totp) Type() string { return TypeTotp }
