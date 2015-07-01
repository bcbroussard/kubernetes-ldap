// Code generated by protoc-gen-go.
// source: token.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	token.proto

It has these top-level messages:
	Token
	StringAssertions
	StructuredAssertions
	LDAPAssertion
*/
package pb

import proto "github.com/golang/protobuf/proto"
import google_protobuf "google/protobuf"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal

type TOKEN_VERSION int32

const (
	TOKEN_VERSION_UNKNOWN TOKEN_VERSION = 0
	TOKEN_VERSION_V1      TOKEN_VERSION = 1
)

var TOKEN_VERSION_name = map[int32]string{
	0: "UNKNOWN",
	1: "V1",
}
var TOKEN_VERSION_value = map[string]int32{
	"UNKNOWN": 0,
	"V1":      1,
}

func (x TOKEN_VERSION) String() string {
	return proto.EnumName(TOKEN_VERSION_name, int32(x))
}

// Token represents a set of assertions relative to a
// username. The bearer of the token can sign requests
// for authorization rights that are implied by the
// underlying assertions.
type Token struct {
	Version              TOKEN_VERSION         `protobuf:"varint,1,opt,name=version,enum=kismatic.token.TOKEN_VERSION" json:"version,omitempty"`
	Username             string                `protobuf:"bytes,2,opt,name=username" json:"username,omitempty"`
	StringAssertions     *StringAssertions     `protobuf:"bytes,4,opt,name=string_assertions" json:"string_assertions,omitempty"`
	StructuredAssertions *StructuredAssertions `protobuf:"bytes,5,opt,name=structured_assertions" json:"structured_assertions,omitempty"`
}

func (m *Token) Reset()         { *m = Token{} }
func (m *Token) String() string { return proto.CompactTextString(m) }
func (*Token) ProtoMessage()    {}

func (m *Token) GetStringAssertions() *StringAssertions {
	if m != nil {
		return m.StringAssertions
	}
	return nil
}

func (m *Token) GetStructuredAssertions() *StructuredAssertions {
	if m != nil {
		return m.StructuredAssertions
	}
	return nil
}

// StringAssertions is a stupid wrapper required by
// proto3 syntax.
type StringAssertions struct {
	Assertions map[string]string `protobuf:"bytes,1,rep,name=assertions" json:"assertions,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *StringAssertions) Reset()         { *m = StringAssertions{} }
func (m *StringAssertions) String() string { return proto.CompactTextString(m) }
func (*StringAssertions) ProtoMessage()    {}

func (m *StringAssertions) GetAssertions() map[string]string {
	if m != nil {
		return m.Assertions
	}
	return nil
}

// StructuredAssertions is idem, but for assertions
// that may take the form of some other protobuf.
type StructuredAssertions struct {
	StructuredAssertions map[string]*google_protobuf.Any `protobuf:"bytes,1,rep,name=structured_assertions" json:"structured_assertions,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *StructuredAssertions) Reset()         { *m = StructuredAssertions{} }
func (m *StructuredAssertions) String() string { return proto.CompactTextString(m) }
func (*StructuredAssertions) ProtoMessage()    {}

func (m *StructuredAssertions) GetStructuredAssertions() map[string]*google_protobuf.Any {
	if m != nil {
		return m.StructuredAssertions
	}
	return nil
}

// LDAPAssertion
type LDAPAssertion struct {
	LdapAttributes *StringAssertions `protobuf:"bytes,1,opt,name=ldap_attributes" json:"ldap_attributes,omitempty"`
}

func (m *LDAPAssertion) Reset()         { *m = LDAPAssertion{} }
func (m *LDAPAssertion) String() string { return proto.CompactTextString(m) }
func (*LDAPAssertion) ProtoMessage()    {}

func (m *LDAPAssertion) GetLdapAttributes() *StringAssertions {
	if m != nil {
		return m.LdapAttributes
	}
	return nil
}

func init() {
	proto.RegisterEnum("kismatic.token.TOKEN_VERSION", TOKEN_VERSION_name, TOKEN_VERSION_value)
}