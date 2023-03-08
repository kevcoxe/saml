package samlsp

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/kevcoxe/saml"
)

const defaultSessionCookieName = "token"

var _ SessionProvider = CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Codec    SessionCodec
}

var ErrEnvVarEmpty = errors.New("getenv: environment variable empty")

func getenvStr(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return v, ErrEnvVarEmpty
	}
	return v, nil
}

func getenvInt(key string) (int, error) {
	s, err := getenvStr(key)
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	// remove extra attributes from assertion
	myAttributes := saml.AttributeStatement{}
	for _, as := range assertion.AttributeStatements {
		for _, aa := range as.Attributes {

			if aa.Name == "email" {
				myAttributes.Attributes = []saml.Attribute{aa}
			}
		}
	}
	assertion.AttributeStatements = []saml.AttributeStatement{myAttributes}

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	// value size limit is 4096
	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
	}

	if len(value) > 4096 {
		return fmt.Errorf("value length is to long, must be under 4096, current length: %v", len(value))
	}

	start, err := getenvInt("START")
	if err != nil {
		return err
	}

	end, err := getenvInt("END")
	if err != nil {
		return err
	}

	jump, err := getenvInt("JUMP")
	if err != nil {
		return err
	}

	l := []int{}
	for i := start; i < end; i += jump {
		l = append(l, i)
	}

	fmt.Printf("START: %v\nEND: %v\nJUMP: %v\nl: %v\n", start, end, jump, l)

	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	for _, n := range l {
		fmt.Printf("creating cookie with value length of: %v\n", n)

		b := make([]byte, n)
		for i := range b {
			b[i] = letterBytes[rand.Intn(len(letterBytes))]
		}

		// find how many parts we need for the session size
		_value := string(b)
		const MAX_PART_SIZE int = 4000
		session_parts := int(math.Floor(float64(len(_value)/MAX_PART_SIZE) + 0.5))

		fmt.Printf("number of parts for (%v): %v\n", n, session_parts)

		for session_part_number := 0; session_part_number < session_parts; session_part_number++ {
			start := MAX_PART_SIZE * session_part_number

			length := MAX_PART_SIZE

			asRunes := []rune(_value)

			if start+length > len(asRunes) {
				length = len(asRunes) - start
			}

			_value_part := string(_value[start : start+length])

			cookie_part := http.Cookie{
				Name:     fmt.Sprintf("kevin-test-%v-%v", n, session_part_number),
				Domain:   c.Domain,
				Value:    _value_part,
				MaxAge:   int(c.MaxAge.Seconds()),
				HttpOnly: c.HTTPOnly,
				Secure:   c.Secure || r.URL.Scheme == "https",
				SameSite: c.SameSite,
				Path:     "/",
			}

			http.SetCookie(w, &cookie_part)
		}

	}

	cookie := http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    value,
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	}

	// if cookie is valid size continue
	if len(cookie.String()) <= 4096 {
		http.SetCookie(w, &cookie)
		return nil
	}

	// find how many parts we need for the session size
	const MAX_PART_SIZE int = 4000
	session_parts := int(math.Ceil(float64(len(value) / MAX_PART_SIZE)))

	for session_part_number := 0; session_part_number < session_parts; session_part_number++ {
		start := MAX_PART_SIZE * session_part_number

		length := MAX_PART_SIZE

		asRunes := []rune(value)

		if start+length > len(asRunes) {
			length = len(asRunes) - start
		}

		value_part := string(value[start : start+length])

		cookie_part := http.Cookie{
			Name:     fmt.Sprintf("%v-%v", c.Name, session_part_number),
			Domain:   c.Domain,
			Value:    value_part,
			MaxAge:   int(c.MaxAge.Seconds()),
			HttpOnly: c.HTTPOnly,
			Secure:   c.Secure || r.URL.Scheme == "https",
			SameSite: c.SameSite,
			Path:     "/",
		}

		http.SetCookie(w, &cookie_part)
	}

	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	cookie, err := r.Cookie(c.Name)

	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = "/"
	cookie.Domain = c.Domain
	http.SetCookie(w, cookie)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c CookieSessionProvider) GetSession(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(c.Name)
	if err == http.ErrNoCookie {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}

	session, err := c.Codec.Decode(cookie.Value)
	if err != nil {
		return nil, ErrNoSession
	}
	return session, nil
}
