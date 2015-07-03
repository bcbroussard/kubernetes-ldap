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
	// BaseDN is the DN of the subtree to query
	BaseDN string

	// LDAP server connection configuration
	Address   string
	Insecure  bool
	TLSConfig *tls.Config

	// Username is the RDN (to BaseDN) of the administrator
	Username string
	// Password is the LDAP basic auth bind password which, per the
	// LDAP specification, is an orbitrary octet string.
	Password []byte

	// FilterString specifies the query -- if any -- that must be
	// performed to lookup the DN to attempt binding with.
	FilterString string

	Errorf func(string, ...interface{})

	// Opaque members of the structure
	c *ldap.Conn // an LDAP server connection
}

func NewLDAPPool(address string) (c *LDAPPool) {
	return &LDAPPool{
		BaseDN: "dn=" + strings.Join(strings.Split(address, "."), ",dn="),
		Errorf: glog.Errorf,
	}
}

func (l *LDAPPool) dial() (c *ldap.Conn, err error) {
	// TODO(dlg): remove support for non-TLS LDAP connections entirely
	switch {
	case !l.Insecure && l.TLSConfig == nil:
		err = fmt.Errorf("insecure not set, but no TLS configuration provided")
	case l.Insecure && l.TLSConfig == nil:
		c, err = ldap.Dial("tcp", l.Address)
	default:
		c, err = ldap.DialTLS("tcp", l.Address, l.TLSConfig)
	}
	return
}

func (l *LDAPPool) CantBind(userDN string, password []byte) (err error) {
	c, err := l.dial()
	if err != nil {
		return
	}
	defer c.Close()
	return c.Bind(userDN, string(password))
}

// filter checks that the username is safe to pass to an LDAP server
// as an attribute value, and interpolates it into the provided filter
// string
func (l *LDAPPool) filter(username string) (filter string, err error) {
	if ok := isLDAPSafe(username); !ok {
		err = fmt.Errorf("provided username %s is not LDAP-safe", username)
		return
	}
	filter = strings.Replace(l.FilterString, "{{username}}", username)
	return
}

func (l *LDAPPool) SetFilter(filter string) (err error) {
	if strings.Count("{{username}}") < 1 {
		return fmt.Errorf("no {{username}} to interpolate in the filter: %s", filter)
	}
	l.FilterString = filter
	return
}

func (l *LDAPPool) CantFind(username string) (userDN string, err error) {
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

	userFilter, err := l.filter(username)
	if err != nil {
		return
	}

	req := &ldap.SearchRequest{
		BaseDN:       l.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    10, // make configurable?
		TypesOnly:    false,
		Filter:       userFilter,
	}
	result, err := c.Search(req)
	if err != nil {
		return
	}

	switch {
	case len(result.Entries) == 1:
		userDN = result.Entries[0].DN
		err = nil
	case len(result.Entries) == 0:
		err = fmt.Errorf("no result for the query %s", req.Filter)
	case len(result.Entries) > 1:
		err = fmt.Errorf("multiple results for the query %s: %+v", req.Filter, result.Entries)
	}
	return
}

// TODO(dlg): MOVE TO ANOTHER FILE
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

func (l *LDAPPool) RequireLDAPAuth(cookieName, headerName string) func(r *http.Request) (err error) {
	return func(r *http.Request) (err error) {
		token, err := []byte{}, nil // isAlreadyAuthorized(cookieName, headerName, r)
		token = nil
		if username, password, ok := r.BasicAuth(); token == nil && ok {
			// This leads to a timing vulnerability that an attacker can use
			// to guess valid usernames, in order to find targets to guess
			// passwords against.
			var cantFind *error
			userDN := username
			if l.FilterString != "" {
				userDN, err = l.CantFind(username)
			}
			cantBind := l.CantBind(username, []byte(password))

			// Return an error, taking care not to indicate whether the username
			// is valid.
			if cantFind != nil || cantBind != nil {
				// TODO(pluggable logger which again should execute in constant time,
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
