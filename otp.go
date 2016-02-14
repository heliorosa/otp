/*
The otp package provides support for TOTP and HOTP authentication
*/
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
)

// Types of OTP auth supported.
const (
	TypeTotp = "totp" //TOTP
	TypeHotp = "hotp" // HOTP
)

// Common defaults for TOTP and HOTP
const (
	DefaultDigits    = 6      // 6 digit code.
	DefaultKeyLength = 10     // 10 bytes (16 base32 characters).
	DefaultAlgorithm = "sha1" // SHA1 is the only supported.
)

// Error codes.
const (
	// Common errors for TOTP and HOTP.
	ECMissingLabel     = iota // Missing (or empty) label.
	ECInvalidAlgorithm        // Invalid algorithm.
	ECCantReadRandom          // Something went wrong while reading random bytes.
	ECNotEnoughRandom         // Didn't read enough random bytes.
	ECUrlParseError           // Error parsing the url.
	ECWrongScheme             // Url scheme != "otpauth".
	ECInvalidOtpType          // Host in the url must be either "totp" or "hotp".
	ECBase32Decoding          // Base32 decoding error.
	ECInvalidDigits           // Invalid number of digits.
	ECMissingSecret           // Secret parameter is missing.

	// HOTP specific errors.
	ECNotHotp        // Url is not HOTP.
	ECMissingCounter // Counter parameter is missing.
	ECInvalidCounter // Can't parse counter.

	// TOTP specific errors.
	ECNotTotp       // Url is not TOTP.
	ECInvalidPeriod // Can't parse period parameter.
)

// Error is a common error struct returned by new/import functions.
type Error struct {
	// The field Code can hold any of the EC* error codes.
	Code int
	// The field Desc is a description of the error.
	Desc string
	// The field Err holds the original error if any.
	Err error
}

// Implement error.
func (g *Error) Error() string {
	var (
		f = "%v"
		a = []interface{}{g.Desc}
	)
	if g.Err != nil {
		f += ": %v"
		a = append(a, g.Err.Error())
	}
	return fmt.Sprintf(f, a...)
}

// Common OTP fields.
type otpKey struct {
	// Secret key. Required.
	Key []byte
	// Label. Required.
	Label string
	// Issuer. Not required but recommended.
	Issuer string
	// Algorithm. Only SHA1.
	Algorithm string
	// Digits. Usually 6 or 8.
	Digits int
}

// Create a new *otpKey.
func newOtpKey(keyLen int, label, issuer, algorithm string, digits int) (*otpKey, error) {
	// label is required
	if label == "" {
		return nil, &Error{ECMissingLabel, "must provide a label", nil}
	}
	// default for digits
	d := DefaultDigits
	if digits > 0 {
		d = digits
	}
	// default key length
	kl := DefaultKeyLength
	if keyLen > 0 {
		kl = keyLen
	}
	// valid algorithm ?
	var a string
	switch aa := strings.ToLower(algorithm); aa {
	case "", "sha1", "sha256", "sha512":
		a = algorithm
	default:
		return nil, &Error{ECInvalidAlgorithm, fmt.Sprintf("unknown algorithm: %v", algorithm), nil}
	}
	// generate key
	b := make([]byte, kl)
	if n, err := rand.Read(b); err != nil {
		return nil, &Error{ECCantReadRandom, "error reading random bytes", nil}
	} else if n != kl {
		return nil, &Error{ECNotEnoughRandom, "couldn't read enough random bytes", nil}
	}
	return &otpKey{
		Key:       b,
		Label:     label,
		Issuer:    issuer,
		Algorithm: a,
		Digits:    d,
	}, nil
}

// Import otpauth url.
func importOtpKey(u string) (k *otpKey, typ string, params url.Values, err error) {
	// parse and check scheme and host
	var otpUrl *url.URL
	otpUrl, err = url.Parse(u)
	if err != nil {
		err = &Error{ECUrlParseError, fmt.Sprintf("can't parse url: %v", err.Error()), err}
	} else if otpUrl.Scheme != "otpauth" {
		err = &Error{ECWrongScheme, fmt.Sprintf("bad scheme: %s", otpUrl.Scheme), nil}
	} else {
		switch otpUrl.Host {
		case TypeHotp, TypeTotp:
		default:
			err = &Error{ECInvalidOtpType, fmt.Sprintf("invalid OTP authentication type: %v", otpUrl.Host), nil}
		}
	}
	if err != nil {
		return
	}
	// set OTP type
	typ = otpUrl.Host
	k = &otpKey{
		Label:  strings.TrimPrefix(otpUrl.Path, "/"),
		Digits: DefaultDigits,
	}
	// parse url parameters
	params = url.Values{}
	for name, vals := range otpUrl.Query() {
		switch n := strings.ToLower(name); n {
		case "secret":
			// base32 secret key
			var b []byte
			b, err = base32.StdEncoding.DecodeString(vals[0])
			if err != nil {
				err = &Error{ECBase32Decoding, fmt.Sprintf("can't decode base32 key: %v", err.Error()), err}
				return
			}
			k.Key = b
		case "digits":
			// number of digits
			if k.Digits, err = strconv.Atoi(vals[0]); err != nil {
				err = &Error{ECInvalidDigits, fmt.Sprintf("invalid digits: %v", vals[0]), err}
				return
			}
		case "algorithm":
			// algorithm
			switch a := strings.ToLower(vals[0]); a {
			case "sha1", "sha256", "sha512":
				k.Algorithm = vals[0]
			default:
				err = &Error{ECInvalidAlgorithm, fmt.Sprintf("unknown algorithm: %v", vals[0]), err}
				return
			}
		case "issuer":
			// issuer
			k.Issuer = vals[0]
		default:
			// other parameters will be returned to the caller
			params.Set(name, vals[0])
		}
	}
	// secret is required and was not provided
	if k.Key == nil {
		err = &Error{ECMissingSecret, "the secret parameter is required", nil}
		return
	}
	return
}

// Key32 returns the Key field encoded in base32.
func (k *otpKey) Key32() string { return base32.StdEncoding.EncodeToString(k.Key) }

// SetKey32 sets the Key field from a base32 string.
func (k *otpKey) SetKey32(key string) error {
	var err error
	if k.Key, err = base32.StdEncoding.DecodeString(key); err != nil {
		return &Error{ECBase32Decoding, fmt.Sprintf("can't decode base32 key: %v", err.Error()), err}
	}
	return nil
}

// Return an otpauth url.
func (k *otpKey) url(otpType string, params url.Values) string {
	// check otp type
	switch otpType {
	case TypeTotp, TypeHotp:
	default:
		panic("bad otp type. only totp and hotp allowed.")
	}
	// add url parameters
	params.Set("secret", k.Key32())
	if k.Digits != DefaultDigits {
		params.Set("digits", strconv.Itoa(k.Digits))
	}
	// include algorithm ?
	switch a := strings.ToLower(k.Algorithm); a {
	case "", "sha1":
	case "sha256", "sha512":
		params.Set("algorithm", k.Algorithm)
	default:
		panic("do not mess with the algorithm")
	}
	// include issuer ?
	if k.Issuer != "" {
		params.Set("issuer", k.Issuer)
	}
	// url.URL plays nice with otpauth urls
	u := &url.URL{
		Scheme:   "otpauth",
		Host:     otpType,
		Path:     "/" + k.Label,
		RawQuery: params.Encode(),
	}
	return u.String()
}

// hashing and truncation
func (k *otpKey) hashTruncateInt(i int) []byte {
	var sha func() hash.Hash
	switch a := strings.ToLower(k.Algorithm); a {
	case "", "sha1":
		sha = sha1.New
	case "sha256":
		sha = sha256.New
	case "sha512":
		sha = sha512.New
	default:
		panic("don't mess with the algorithm")
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	hm := hmac.New(sha, k.Key)
	if _, err := hm.Write(b); err != nil {
		panic(err)
	}
	b = hm.Sum(nil)
	ofs := int(b[19] & 0xf)
	c := make([]byte, 4)
	copy(c, b[ofs:ofs+4])
	c[0] = c[0] & 0x7f
	return c
}

// Key represents an OTP key.
type Key interface {
	Code() int
	CodeN(n int) int
	Key32() string
	SetKey32(string) error
	Url() string
	Type() string
	fmt.Stringer
}

// NewKey creates a new OTP key.
// keyType must be either TypeTotp or TypeHotp.
// label is required. keyLen <= 0, defaults to 10.
// algorithm == "", defaults to "sha1".
// digits <= 0, defaults to 6
func NewKey(keyType string, keyLen int, label, issuer, algorithm string, digits int, extraParams url.Values) (Key, error) {
	switch keyType {
	case TypeTotp:
		// TOTP
		// parse period parameter
		p := extraParams.Get("period")
		var (
			err error
			pp  int
		)
		if p != "" {
			pp, err = strconv.Atoi(p)
			if err != nil {
				return nil, &Error{ECInvalidPeriod, fmt.Sprintf("invalid period: %v", p), err}
			} else if pp == 0 {
				pp = DefaultPeriod
			}
		}
		return NewTotp(keyLen, label, issuer, algorithm, digits, pp)
	case TypeHotp:
		// HOTP
		// check for counter parameter
		c := extraParams.Get("counter")
		if c == "" {
			return nil, &Error{ECMissingCounter, "counter parameter is missing", nil}
		}
		cc, err := strconv.Atoi(c)
		if err != nil {
			return nil, &Error{ECInvalidCounter, fmt.Sprintf("bad counter: %v", c), err}
		}
		return NewHotp(keyLen, label, issuer, algorithm, digits, cc)
	default:
		return nil, &Error{ECInvalidOtpType, fmt.Sprintf("invalid OTP authentication type: %v", keyType), nil}
	}
}

// NewKeyWithDefaults calls NewKey with the default values.
func NewKeyWithDefaults(keyType, label, issuer string, extraParams url.Values) (Key, error) {
	return NewKey(keyType, 0, label, issuer, "", 0, extraParams)
}

// Import an OTP key from an otpauth url.
func ImportKey(u string) (Key, error) {
	k, typ, args, err := importOtpKey(u)
	if err != nil {
		return nil, err
	}
	if typ == TypeTotp {
		return importTotp(k, args)
	}
	return importHotp(k, args)
}

// ensure that we implement Key in Totp and Hotp
var (
	_ Key = (*Totp)(nil)
	_ Key = (*Hotp)(nil)
)
