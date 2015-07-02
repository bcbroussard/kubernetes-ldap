package ldap

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"github.com/kismatic/kubernetes-ldap/authproxy"
)

// LDAPPoool is currently not a pool at all.
type LDAPPool struct {
	// BaseDN is the base used for all LDAP subtree queries.
	BaseDN string

	// LDAP server connection configuration
	Network   string
	Address   string
	Insecure  bool
	TLSConfig *tls.Config
	c         *ldap.Conn

	Username string
	Password []byte // a byte-slice, per the LDAP specification

	Errorf func(string, ...interface{})
}

func NewLDAPService(address string) (c *LDAPPool) {
	return &LDAPPool{
		BaseDN: "dn=" + strings.Join(strings.Split(address, "."), ",dn="),
		Errorf: glog.Errorf,
	}
}

func (l *LDAPPool) dial() (c *ldap.Conn, err error) {
	if l.Network == "" {
		l.Network = "tcp"
	}
	// TODO(dlg): remove support for non-TLS LDAP connections entirely
	switch {
	case !l.Insecure && l.TLSConfig == nil:
		err = fmt.Errorf("insecure not set, but no TLS configuration provided")
	case l.Insecure && l.TLSConfig == nil:
		c, err = ldap.Dial(l.Network, l.Address)
	default:
		c, err = ldap.DialTLS(l.Network, l.Address, l.TLSConfig)
	}
	if err != nil {
		if c != nil {
			c.Close()
			c = nil
		}
	}
	return
}

func (l *LDAPPool) CantBind(username string, password []byte) (err error) {
	c, err := l.dial()
	if err != nil {
		return
	}
	defer c.Close()
	return c.Bind(username, string(password))
}

/*
func (l *LDAPPool) CantFind(username string) (userdn string, err error) {
	c, err := l.dial()
	if err != nil {
		return
	}
	defer c.Close()
	err = c.Bind(l.Username, string(l.Password))
	if err != nil {
		l.Errorf("error binding as app user %s: %s", l.Username, err)
		return
	}
	req := &ldap.SearchRequest{
		BaseDN:       l.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       fmt.Sprintf("cn=%s", username), // TODO(dlg): input sanitizization for LDAP!!!!!!
	}
	result, err := c.Search(req)
	if result {
		// for testing
		l.Errorf("%s", result.PrettyPrint(2))
	}
	if len(result.Entries) == 1 {
		userdn = result.Entries[0].DN
		err = nil
		return
	}

	return
}
*/
func isAlreadyAuthorized(cookieName, headerName string, r *http.Request) (token []byte, err error) {
	// Check whether the auth token is set in a header,
	var tokens []string
	var ok bool
	if headerName != "" {
		tokens, ok = r.Header[headerName]
		if len(tokens) != 1 {
			err = &authproxy.StatusError{
				StatusCode: http.StatusUnauthorized,
				Message:    fmt.Sprintf("expected one %s header, but got %d", headerName, len(tokens)),
			}
			return
		}
		// TODO, actually use token
		token = []byte(tokens[0])

		// or if cookieName is set, in a cookie.
		if !ok && cookieName != "" {
			cookie, cookierr := r.Cookie(cookieName)
			switch err {
			case nil:
				token = []byte(cookie.Value)
			default: // case http.ErrNoCookie:
				// is any other error possible, and would it be worth logging?
				err = cookierr
				return
			}
		}

		// We either have a token in a header, or set via cookie.
		if ok {
			// TODO(pluggable logging for the request here, somehow?)
			tokenOK, scope := true, "" //verifyToken(token)
			/*switch tokenStatus {
			case TokenExpired:
				err = &authproxy.StatusError{
					StatusCode: http.StatusProxyAuthRequired,
					Message:    "token expired",
				}
			case TokenInvalid:
				err = &authproxy.StatusError{StatusCode: http.StatusUnauthorized}
			case TokenValid:
				err = nil
			}*/
		}
	}
	return
}

func (l *LDAPPool) LDAPAuthDirector(cookieName, headerName string) func(r *http.Request) (err error) {
	return func(r *http.Request) (err error) {
		token, err := []byte{}, nil // isAlreadyAuthorized(cookieName, headerName, r)
		token = nil
		if username, password, ok := r.BasicAuth(); token == nil && ok {
			// TODO: pool LDAP connections
			// CRITICAL: If both lookups are not performed, it is trivial for
			// an attacker to scrape valid usernames from this endpoint. You
			// must ensure that BOTH queries are executed against the LDAP
			// server, regardless of whether the user exists.
			//
			// (And this is clearly not sufficient to rule out the attack,
			// because we have to do some parsing. We can fix this by adding
			// an RT bound, if we really need to.)
			//			cantFind := l.CantFind(r.Username)
			var cantFind *error
			cantBind := l.CantBind(username, []byte(password))

			// Return an error, taking care not to indicate whether the username
			// is valid.
			if cantFind != nil || cantBind != nil {
				// TODO(pluggable logger, again, should execute in constant time,
				// which likely requires *always* spawning a goroutine and waiting
				// before logging)
				err = &authproxy.StatusError{StatusCode: http.StatusUnauthorized}
				return
			}

			// Issue the token.
			/*	token = l.iss.Issue(r.Username, &pb.Token{
				Username: r.Username,
				StringAssertions: map[string]string{
					"ldap_server": lconn.Server.String(),
					"userexists":  "yes",
					"usercanbind": "yes",
				},
			})*/

			token = []byte(username)
			err = nil
			return
		}

		// Probably want a special case to handle returning the token as the body,
		// depending on route.

		// All attempts at finding a way to authorize this access have failed.
		// So we deny the request.
		return &authproxy.StatusError{StatusCode: http.StatusUnauthorized}
	}
}
