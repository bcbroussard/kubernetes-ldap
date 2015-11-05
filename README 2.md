Development

```
docker build -t kismatic/openldap .
# with data-container
docker run --name ldap-data --entrypoint /bin/echo kismatic/openldap "Data-only container"

docker run -d -p 389:389 -e SLAPD_PASSWORD=admin -e SLAPD_CONFIG_PASSWORD=passw0rd -e SLAPD_DOMAIN=kismatic.com -e SLAPD_ORGANIZATION=Kismatic --volumes-from ldap-data kismatic/openldap
```

Or run it straight
```
docker run -d -p 389:389 -e SLAPD_PASSWORD=admin -e SLAPD_CONFIG_PASSWORD=passw0rd -e SLAPD_DOMAIN=kismatic.com -e SLAPD_ORGANIZATION=Kismatic kismatic/openldap
```

```
export GO15VENDOREXPERIMENT=1
godep go build cmd/...

go run k8s-ldap.go --ldap-insecure=true --apiserver=http://173.255.114.28:8080
```

# LDAP Testing Setup
- If on a mac, open port 389 on boot2docker vm
