package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/kismatic/kubernetes-ldap/auth"

	flag "github.com/spf13/pflag"
)

const (
	usage            = "kubernetes-ldap <options>"
	ReadWriteTimeout = time.Minute * 60
)

var flPort = flag.Uint("port", 4000, "Local port this proxy server will run on")

var flInsecure = flag.Bool("ldap-insecure", false, "Disable LDAP TLS")
var flLdapHost = flag.String("ldap-host", "", "Host or IP of the LDAP server")
var flLdapPort = flag.Uint("ldap-port", 389, "LDAP server port")
var flBaseDN = flag.String("ldap-base-dn", "", "LDAP user base DN in the form 'dc=example,dc=com'")
var flUserLoginAttribute = flag.String("ldap-user-attribute", "uid", "LDAP Username attribute for login")
var flSearchUserDN = flag.String("ldap-search-user-dn", "", "Search user DN for this app to find users (e.g.: cn=admin,dc=example,dc=com).")
var flSearchUserPassword = flag.String("ldap-search-user-password", "", "Search user password")

var flTLSCertFile = flag.String("tls-cert-file", "",
	"File containing x509 Certificate for HTTPS.  (CA cert, if any, concatenated after server cert).")
var flTLSPrivateKeyFile = flag.String("tls-private-key-file", "", "File containing x509 private key matching --tls-cert-file.")

// var flCertDirectory = flag.String("cert-dir", "", "The directory where the TLS certs are located (by default /var/run/kubernetes). "+
// 	"If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored.")

// TODO(bc): Change to consistent format (host/port)
var flApiserver = flag.String("apiserver", "", "Address of Kubernetes API server (e.g.: http://k8smaster.kismatic.com:8080")

var flTokenExpiresAfter = flag.Uint("token-expires-after", 0, "Number of minutes a token will expire after. A value of 0 means tokens will never expire.")

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s\n", usage)
		flag.PrintDefaults()
	}
}

func NewSingleHostReverseProxy(url *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(url)
	// Rewrite the host
	oldDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		oldDirector(r)
		r.Host = url.Host
		rdump, _ := httputil.DumpRequest(r, true)
		glog.Infof("proxy.Director:\n%s\n", rdump)
	}
	return proxy
}

func main() {
	flag.Parse()

	if *flLdapHost == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-host arg is required")
	}

	if *flBaseDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-base-dn arg is required")
	}

	if *flSearchUserDN == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-search-user-dn arg is required")
	}

	if *flSearchUserPassword == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --ldap-search-user-password arg is required")
	}

	if *flApiserver == "" {
		flag.Usage()
		glog.Fatal("kubernetes-ldap: --apiserver arg is required")
	}

	var issuerDir = "/etc/kismatic/auth"
	var issuerFileName = issuerDir + "/ldapAuth"

	if _, err := os.Stat(issuerDir); os.IsNotExist(err) {
		e := os.MkdirAll(issuerDir, 0777)
		if e != nil {
			glog.Fatal("Could not create directory for keypair %s", e)
		}
	}

	_, privKeyErr := os.Stat(issuerFileName + ".priv")
	_, pubKeyErr := os.Stat(issuerFileName + ".pub")

	if (privKeyErr != nil && os.IsNotExist(privKeyErr)) || (pubKeyErr != nil && os.IsNotExist(pubKeyErr)) {

		e = token.GenerateKeypair(issuerFileName)
		if e != nil {
			glog.Fatal("Could not generate jose keypair %s", e)
		}
	}

	issuer, err := token.NewIssuer(issuerFileName)
	issuer.TokenExpiresAfter = flTokenExpiresAfter

	l := &auth.LdapAuth{
		LdapServer:         *flLdapHost,
		LdapPort:           *flLdapPort,
		Insecure:           *flInsecure,
		BaseDN:             *flBaseDN,
		UserLoginAttribute: *flUserLoginAttribute,
		SearchUserDN:       *flSearchUserDN,
		SearchUserPassword: *flSearchUserPassword,
		HeaderName:         "k8s-auth",
		CookieName:         "k8s-auth",
		Issuer:             *issuer,
		// TLSConfig
	}

	// pb = (pb payload)

	// token, err = issuer.Issue(pb)

	// reading token
	// verifier = NewVerifier reads jwt using public key file

	// ExpiresAt
	// now := time.Now()
	// secs := now.Unix()

	target, err := url.Parse(*flApiserver)
	if err != nil {
		glog.Fatal(err)
	}
	proxy := NewSingleHostReverseProxy(target)

	server := &http.Server{Addr: fmt.Sprintf(":%d", *flPort)}

	http.Handle("/", l.RequireAuthorization(proxy))

	glog.Infof("Serving on %s", fmt.Sprintf(":%d", *flPort))

	// TODO(bc): enable cert-dir flag

	if *flTLSCertFile != "" && *flTLSPrivateKeyFile != "" {

		server.TLSConfig = &tls.Config{
			// Change default from SSLv3 to TLSv1.0 (because of POODLE vulnerability)
			MinVersion: tls.VersionTLS10,
		}
		glog.Fatal(server.ListenAndServeTLS(*flTLSCertFile, *flTLSPrivateKeyFile))

	} else {
		glog.Fatal(server.ListenAndServe())
	}

}
