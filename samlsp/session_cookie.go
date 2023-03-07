package samlsp

import (
	"fmt"
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

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	fmt.Printf("assertion attribute statements: %v\n", assertion.AttributeStatements)

	sessionWithAttributes := session.(SessionWithAttributes)
	attributes := sessionWithAttributes.GetAttributes()

	myAttributes := []saml.Attribute{}

	for _, as := range assertion.AttributeStatements {
		fmt.Printf("attribute statement: %v\n", as)
		for _, aa := range as.Attributes {
			fmt.Printf("attribute FriendlyName: %v\n", aa.FriendlyName)
			fmt.Printf("attribute Name: %v\n", aa.Name)
			fmt.Printf("attribute NameFormat: %v\n", aa.NameFormat)
			fmt.Printf("attribute Values: %v\n", aa.Values)

			if aa.Name == "email" {
				myAttributes = append(myAttributes, aa)
			}
		}

		as.Attributes = myAttributes

	}

	for _, as := range assertion.AttributeStatements {
		fmt.Printf("post attribute statement: %v\n", as)
		for _, aa := range as.Attributes {
			fmt.Printf("post attribute FriendlyName: %v\n", aa.FriendlyName)
			fmt.Printf("post attribute Name: %v\n", aa.Name)
			fmt.Printf("post attribute NameFormat: %v\n", aa.NameFormat)
			fmt.Printf("post attribute Values: %v\n", aa.Values)
		}
	}

	for k, v := range attributes {
		fmt.Printf("attribute (%v): %v\n", k, v)
	}

	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
	}

	fmt.Printf("Session: %v\n", session)
	fmt.Printf("Name: %v\n", c.Name)
	fmt.Printf("Domain: %v\n", c.Domain)
	fmt.Printf("Value: %v\n", value)
	fmt.Printf("MaxAge: %v\n", int(c.MaxAge.Seconds()))
	fmt.Printf("HttpOnly: %v\n", c.HTTPOnly)
	fmt.Printf("Secure: %v\n", c.Secure || r.URL.Scheme == "https")
	fmt.Printf("SameSite: %v\n", c.SameSite)
	fmt.Printf("Path: %v\n", "/")

	new_session, err := c.Codec.Decode(value)
	if err != nil {
		fmt.Println("Error decoding session: " + err.Error())
		return ErrNoSession
	}

	fmt.Printf("new_session: %v\n", new_session)

	cookie := http.Cookie{
		Name:     "token",
		Domain:   c.Domain,
		Value:    value,
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	}

	if v := cookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v)
	} else {
		fmt.Println("cookie not set because of invalid")
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
