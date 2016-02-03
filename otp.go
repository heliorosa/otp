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

// types of OTP auth supported
const (
	TypeTotp = "totp"
	TypeHotp = "hotp"
)

// common defaults for TOTP and HOTP
const (
	DefaultDigits    = 6      // 6 digit code
	DefaultKeyLength = 10     // 10 bytes == 16 base32 digits
	DefaultAlgorithm = "sha1" // google authenticator only implements sha1
)

// key generation error codes
const (
	// missing (or empty) label
	ECMissingLabel = iota
	// invalid algorithm
	ECInvalidAlgorithm
	// something went wrong while reading random bytes
	ECCantReadRandom
	// didn't read enough random bytes
	ECNotEnoughRandom
	// error parsing the url
	ECUrlParseError
	// url scheme != "otpauth"
	ECWrongScheme
	// host in the url must be either "totp" or "hotp"
	ECInvalidType
	// base32 decoding error
	ECBase32Decoding
	// number of digits
	ECInvalidDigits
	// secret parameter in url is required
	ECMissingSecret

	// HOTP specific errors
	// url is not HOTP
	ECNotHotp
	// counter parameter is required for HOTP
	ECMissingCounter
	// can't parse counter
	ECInvalidCounter

	// TOTP specific errors
	// url is not TOTP
	ECNotTotp
	// can't parse period
	ECInvalidPeriod
)

// Error is a common error struct returned by generate/import functions.
// The Code can hold any of the EC* error codes.
// The Desc is a description of the error.
// The Err holds the original error if any.
type Error struct {
	Code int
	Desc string
	Err  error
}

// implement error
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

// common otp fields
type otpKey struct {
	Key       []byte // key
	Label     string // label
	Issuer    string // issuer
	Algorithm string // used algorithm
	Digits    int    // number of digits
}

// create a new *otpKey
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

// import otpauth url
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
			err = &Error{ECInvalidType, fmt.Sprintf("invalid OTP authentication type: %v", otpUrl.Host), nil}
		}
	}
	if err != nil {
		return
	}
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
			params.Set(name, vals[0])
		}
	}
	// secret is required and was not provided
	if k.Key == nil {
		err = &Error{ECMissingSecret, "the secret argument is required", nil}
		return
	}
	return
}

// Key32 returns the Key field encoded in base32
func (k *otpKey) Key32() string { return base32.StdEncoding.EncodeToString(k.Key) }

// SetKey32 sets the key from a base32 string
func (k *otpKey) SetKey32(key string) (err error) {
	k.Key, err = base32.StdEncoding.DecodeString(key)
	return
}

// return an otpauth url
func (k *otpKey) url(otpType string, params url.Values) string {
	// check otp type
	switch otpType {
	case TypeTotp, TypeHotp:
	default:
		panic("bad otp type. only totp and hotp allowed.")
	}
	// add url parameters
	params.Set("secret", k.Key32())
	params.Set("digits", strconv.Itoa(k.Digits))
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

// Key represents an OTP key
type Key interface {
	Code() int
	Key32() string
	SetKey32(string) error
	Url() string
	Type() string
	fmt.Stringer
}

// NewKey creates a new OTP key
// keyType must be either "totp" or "hotp"
// label is required
// keyLen <= 0, defaults to 10
// algorithm == "", defaults to "sha1"
// digits <= 0, defaults to 6
func NewKey(keyType string, keyLen int, label, issuer, algorithm string, digits int, extraParams url.Values) (Key, error) {
	switch keyType {
	case TypeTotp:
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
		c := extraParams.Get("counter")
		cc := 0
		var err error
		if c != "" {
			cc, err = strconv.Atoi(c)
			if err != nil {
				return nil, &Error{ECInvalidCounter, fmt.Sprintf("bad counter: %v", c), err}
			}
		}
		return NewHotp(keyLen, label, issuer, algorithm, digits, cc)
	default:
		return nil, &Error{ECInvalidType, fmt.Sprintf("invalid OTP authentication type: %v", keyType), nil}
	}
}

// NewKeyWithDefaults calls NewKey with the default values
func NewKeyWithDefaults(keyType, label, issuer string, extraParams url.Values) (Key, error) {
	return NewKey(keyType, 0, label, issuer, "", 0, extraParams)
}

// import an OTP key from an otpauth url
func ImportKey(u string) (Key, error) {
	k, typ, args, err := importOtpKey(u)
	if err != nil {
		return nil, err
	}
	switch typ {
	case TypeTotp:
		return importTotp(k, args)
	case TypeHotp:
		return importHotp(k, args)
	default:
		return nil, &Error{ECInvalidType, fmt.Sprintf("invalid OTP authentication type: %v", typ), nil}
	}
}

// ensure that we implement Key in Totp and Hotp
var (
	_ Key = (*Totp)(nil)
	_ Key = (*Hotp)(nil)
)
