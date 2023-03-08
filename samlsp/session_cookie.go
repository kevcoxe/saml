package samlsp

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
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

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
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

	split_session, _ := getenvBool("SPLIT_SESSION")
	if !split_session {
		// if cookie is valid size continue
		if len(cookie.String()) <= MAX_COOKIE_SIZE {
			http.SetCookie(w, &cookie)
			return nil
		}

		return errors.New("invalid cookie length")
	}

	// find how many parts we need for the session size
	_value := string(value)
	const MAX_PART_SIZE int = 4000
	session_parts := int(math.Ceil(float64(len(_value)/MAX_PART_SIZE) + 0.5))

	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    fmt.Sprint(session_parts),
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	})

	for session_part_number := 0; session_part_number < session_parts; session_part_number++ {
		start := MAX_PART_SIZE * session_part_number

		length := MAX_PART_SIZE

		asRunes := []rune(_value)

		if start+length > len(asRunes) {
			length = len(asRunes) - start
		}

		_value_part := string(_value[start : start+length])

		cookie_part := http.Cookie{
			Name:     fmt.Sprintf("%v-%v", c.Name, session_part_number),
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

	if err == nil {
		return session, nil
	}

	split_session, _ := getenvBool("SPLIT_SESSION")

	if !split_session {
		return nil, ErrNoSession
	}

	// find part number
	num_parts, err := strconv.Atoi(cookie.Value)
	if err != nil {
		return nil, ErrNoSession
	}

	encoded_session := ""

	for i := 0; i < num_parts; i++ {
		cookie_part, err := r.Cookie(fmt.Sprintf("%v-%v", c.Name, i))
		if err == http.ErrNoCookie {
			return nil, ErrNoSession
		} else if err != nil {
			return nil, err
		}

		encoded_session = encoded_session + cookie_part.Value

	}

	new_session, err := c.Codec.Decode(encoded_session)

	if err != nil {
		return nil, ErrNoSession
	}

	return new_session, nil
}
