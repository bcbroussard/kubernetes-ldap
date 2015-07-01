package main

import (
	"github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"github.com/kismatic/ldap-auth/authproxy"
	"net/http"
)

// TODO tlsconfig.yaml

var (
	serverDomain = "localhost"
)

const (
	headerName = "Kube-Auth-Token"
	cookieName = "kubewebauth"
)

func SetAuthCookie(w ResponseWriter, token []byte) {
	SetCookie(w, &Cookie{
		Name:     cookieName,
		Value:    base64.Encode(token),
		Domain:   serverDomain,
		Expires:  time.Now().Add(expireSeconds * time.Seconds),
		Secure:   true,
		HttpOnly: true,
	})
}

func main() {
	flags.Parse() // for glog

	certfile, keyfile := "cert.pem", "key.pem"

	// TODO(dlg): split out to serveTLS helper function,
	// and fetch certs from some distributed keystore
	srv := &http.Server{
		Addr:           "127.0.0.1:https",
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1024,
		// An extremely stringent TLS configuration; YMMV.
		TLSConfig: &tls.Config{
			// The ECDSA options are only used if you happen to have an ECDSA
			// certificate.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				// If you enable these, most browsers will always choose the
				// lower security strength option. TODO(dlg): check that Chrome
				// can still connect...
				// tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			},
			SessionTicketsDisabled: true, // Go's session tickets compromise forward secrecy
			MinVersion:             tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256, // constant-time, but twist does not have cofactor 1
				tls.CurveP384, // NB: Go's implementation isn't constant time as of this writing (but hopefully will be), but this is hopefully not relevant for its use in ECDHE (since at most one fixed-base and one variable-base scalar multiplication are performed)
			},
		},
	}

	// TODO(dlg): This deserves its own function, obviously.
	prox := authproxy.ReverseProxy{
		Director: ldap.LDAPAuthDirector,
	}

	srv.Handler = prox

	glog.Fatalf(srv.ListenAndServeTLS(certfile, keyfile))

}
