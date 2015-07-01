package ldap

// This is of dubious correctness.

type BindRequest struct {
	BindRequestSequence `asn1:"application,tag:0"`
}

type BindRequestSequence struct {
	Version int
	DN      DistinguishedName `asn1:"utf8"`
	Simple  []byte            `asn1:"optional,explicit,tag:0"`
	Sasl    []SaslCredential  `asn1:"optional,explicit,tag:3"`
}

type DistinguishedName string

//func (d DistinguishedName) AttributeTypeAndValueSet() []AttributeTypeAndValue {
//	// TODO(maybe, probably just want go-ldap's parser, assuming it's correct)
//}

type SaslCredential struct {
	Mechanism   string
	Credentials []byte `asn1:"optional"`
}

type Request struct {
}
