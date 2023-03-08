package samlsp

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
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

	l := []int{4096, 4097, 6000, 10000, 15000, 150000}
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	for _, n := range l {
		b := make([]byte, n)
		for i := range b {
			b[i] = letterBytes[rand.Intn(len(letterBytes))]
		}
		test_value, err := c.Codec.Encode(string(b))
		if err != nil {
			return err
		}
		http.SetCookie(w, &http.Cookie{
			Name:     fmt.Sprintf("kevin-test-%v", n),
			Domain:   c.Domain,
			Value:    test_value,
			MaxAge:   int(c.MaxAge.Seconds()),
			HttpOnly: c.HTTPOnly,
			Secure:   c.Secure || r.URL.Scheme == "https",
			SameSite: c.SameSite,
			Path:     "/",
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    value,
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	})
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
