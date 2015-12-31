package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/kismatic/kubernetes-ldap/ldap"
	"github.com/kismatic/kubernetes-ldap/token"
	"github.com/kismatic/kubernetes-ldap/token/pb"

	log "github.com/golang/glog"
	google_protobuf "go.pedge.io/google-protobuf"
)

// LdapAuth represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type LdapAuth struct {
	BaseDN             string
	Insecure           bool
	LdapServer         string
	LdapPort           uint
	UserLoginAttribute string
	SearchUserDN       string
	SearchUserPassword string

	HeaderName string
	CookieName string

	// TLSConfig *tls.Config
	Issuer *token.Issuer
}

func (a *LdapAuth) setAuthToken(w http.ResponseWriter, username, userDN string) {
	var expiresAt int64
	if a.Issuer.TokenExpiresAfter != 0 {
		expiresAt = time.Now().Unix() + a.Issuer.TokenExpiresAfter*60
	}

	token, err := a.Issuer.Issue(username, &pb.Token{
		Username:  username,
		ExpiresAt: expiresAt,
		// StringAssertions: map[string]string{
		// 	"ldapServer": a.LdapServer,
		// 	"userDN":     userDN,
		// },
		Assertions: []Token_StructuredAssertions{
			&Token_StructuredAssertions{
				StructuredAssertions: map[string]*google_protobuf.Any{
					"LDAP": &LDAPAssertion{
						LdapAttributes: &StringAssertions{
							Assertions: map[string]string{
								"ldapServer": a.LdapServer,
								"userDN":     userDN,
							},
						},
					},
				},
			},
		},
	})

	cookie = &http.Cookie{
		Name:     a.CookieName,
		Value:    token,
		HttpOnly: true,
		Secure:   !a.Insecure,
	}
	http.SetCookie(w, cookie)
	return
}

func writeBasicAuthError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))

	return
}

// RequireAuthorization is middleware that requires LDAP authentication to
// make a request. It either uses a token provided as a header or a cookie,
// or prompts for basic auth as required.
func (a *LdapAuth) RequireAuthorization(next http.HandlerFunc) HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok = r.BasicAuth(); ok {
			err = a.authenticate(w, r)
			if err != nil {
				log.Errorf("error authenticating user %s: %s", username, err)
				writeBasicAuthError(w)
				return
			}
			// Success, so go on to the next handler.
			next(w, r)
			return
		}

		var token *pb.Token
		var s0 string
		var iss = a.Issuer

		if header, ok := r.Header[a.HeaderName]; ok && len(header) == 1 {
			token, err = iss.Verify(header[0])
		}
		if cookie, ok := r.Cookie(a.CookieName); token == nil && err == nil && ok && cookie.Value != "" {
			token, err = iss.Verify(cookie.Value)
		}
		if err != nil {
			glog.Warningf("error authenticating a purported authorization")
		}
		if token == nil || err != nil {
			writeBasicAuthError(w)
			return
		}
		// Check expiresAt
		if token == nil || err != nil {
			writeBasicAuthError(w)
			return
		}

		// TODO(someone): whatever access control middleware is necessary; this probably means that we
		// should pass around an http.Context to handle the token
		glog.V(2).Infof("verified authorization bearer token: %s", token)

		next(w, r)
		return
	})
}

// Authenticate returns middleware that tries to bind to an LDAP server
// in order to authenticate a user via credentials provided via basic
// auth.
func (a *LdapAuth) authenticate(w http.ResponseWriter, r *http.Request) (err error) {
	log.Infof("connecting to: %s\n", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort))

	if a.Insecure && !a.TLSConfig {
		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort))
	} else {
		l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", a.LdapServer, a.LdapPort), nil)
	}

	if err != nil {
		log.Errorf("%s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error\n"))
		return
	}
	defer l.Close()

	var username, password string
	if username, password, ok := r.BasicAuth(); !ok {
		log.Errorf("basic auth was not used; this should be impossible: %s\n", err)
		writeBasicAuthError(w)
		return
	}
	if username == "" || password == "" {
		log.Warningf("username or password missing from request")
		return
	}
	log.V(2).Infof("trying auth of: %s\n", username)

	if l.SearchForUser {
		// Test search username and password
		err = l.Bind(a.SearchUserDN, a.SearchUserPassword)
		if err != nil {
			log.Errorf("Cannot authenticate search user: %s\n", err)
			writeBasicAuthError(w)
			return
		}

		// Find username
		// TODO(dlg): this is still unsanitized
		ldapfilter := fmt.Sprintf("(%s=%s)", a.UserLoginAttribute, uid)
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

		sr, err := l.Search(search)
		if err != nil {
			log.Fatalf("%s\n", err.Error())
			writeBasicAuthError(w)
			return
		}

		log.Infof("search: %s -> num of entries = %d", search.Filter, len(sr.Entries))
		log.V(2).Infof("search: +#v", sr.SPrettyPrint(0))

		if len(sr.Entries) == 0 {
			log.Errorf("user not found: %s\n", uid)
			writeBasicAuthError(w)
			return
		}

		if len(sr.Entries) > 1 {
			log.Errorf("more than one user found for: %s\n", uid)
			writeBasicAuthError(w)
			return
		}

		//Bind as user to test password
		userDN = sr.Entries[0].DN
	} else {
		// TODO(dlg): sanitize!!!
		userDN = fmt.Sprintf("cn=%s,%s", username, l.BaseDN)
	}
	err = l.Bind(userDN, userPassword)

	if err != nil {
		log.Errorf(`cannot authenticate user "%s" with dn="%s": %s\n`, username, userDN, err)
		writeBasicAuthError(w)
		return
	}

	setAuthToken(w, username, userDN)
}
