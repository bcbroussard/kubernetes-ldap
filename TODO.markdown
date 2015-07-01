Rethink the design of authproxy, which is still a very
lightly modified version of a design from Go's standard
library which has an interface that isn't great for this.

Split out token-issuance into another microservice.

Split out LDAP queries into another microservice, and require
signed requests to that microservice.
