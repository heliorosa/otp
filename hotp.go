package otp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
)

// Hotp key.
type Hotp struct {
	// Common fields
	*otpKey
	// Counter
	Counter int
}

// NewHotp creates a new HOTP key.
// keyLen <= 0, defaults to 10. digits <= 0, defaults to 6.
// algorithm == "", defaults to "sha1".
func NewHotp(keyLen int, label, issuer, algorithm string, digits, counter int) (*Hotp, error) {
	k, err := newOtpKey(keyLen, label, issuer, algorithm, digits)
	if err != nil {
		return nil, err
	}
	return &Hotp{otpKey: k, Counter: counter}, nil
}

// NewHotpWithDefaults calls NewHotp with the default values.
func NewHotpWithDefaults(label, issuer string) (*Hotp, error) {
	return NewHotp(0, label, issuer, "", 0, 0)
}

// import hotp key
func importHotp(k *otpKey, params url.Values) (*Hotp, error) {
	r := &Hotp{otpKey: k}
	// verify counter
	ctr := params.Get("counter")
	if ctr == "" {
		return nil, &Error{ECMissingCounter, "counter parameter is missing", nil}
	}
	if i, err := strconv.Atoi(ctr); err != nil {
		return nil, &Error{ECInvalidCounter, fmt.Sprintf("invalid counter: %v", ctr), nil}
	} else {
		r.Counter = i
	}
	return r, nil
}

// ImportHotp imports an url in the otpauth format.
func ImportHotp(u string) (*Hotp, error) {
	// import url
	k, t, p, err := importOtpKey(u)
	if err != nil {
		return nil, err
	}
	// check for HOTP
	if t != TypeHotp {
		return nil, &Error{ECNotHotp, "not a hotp key", nil}
	}
	return importHotp(k, p)
}

// Url returns the key in the otpauth format.
func (h *Hotp) Url() string {
	return h.url(TypeHotp, url.Values{"counter": []string{strconv.Itoa(h.Counter)}})
}

// String returns the same as Url().
func (h *Hotp) String() string { return h.Url() }

// Code returns the current code.
func (h *Hotp) Code() int { return h.codeCounter(h.Counter) }

// CodeN returns the code for counter+n.
func (h *Hotp) CodeN(n int) int { return h.codeCounter(h.Counter + n) }

// CodeCounter returns the code for the counter c.
func (h *Hotp) CodeCounter(c int) int { return h.codeCounter(c) }

// returns the code for counter c.
func (h *Hotp) codeCounter(c int) int {
	return int(binary.BigEndian.Uint32(h.hashTruncateInt(c))) % int(math.Pow10(h.Digits))
}

// Type returns TypeHotp
func (h *Hotp) Type() string { return TypeHotp }
