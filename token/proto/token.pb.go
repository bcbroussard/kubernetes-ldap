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
import fmt "fmt"
import math "math"
import google_protobuf "go.pedge.io/google-protobuf"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

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
func (TOKEN_VERSION) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// Token represents a set of assertions relative to a
// username. The bearer of the token can sign requests
// for authorization rights that are implied by the
// underlying assertions.
type Token struct {
	Version   TOKEN_VERSION `protobuf:"varint,1,opt,name=version,enum=kismatic.token.TOKEN_VERSION" json:"version,omitempty"`
	Username  string        `protobuf:"bytes,2,opt,name=username" json:"username,omitempty"`
	ExpiresAt int64         `protobuf:"varint,3,opt,name=expiresAt" json:"expiresAt,omitempty"`
	// Types that are valid to be assigned to Assertions:
	//	*Token_StringAssertions
	//	*Token_StructuredAssertions
	Assertions isToken_Assertions `protobuf_oneof:"assertions"`
}

func (m *Token) Reset()                    { *m = Token{} }
func (m *Token) String() string            { return proto.CompactTextString(m) }
func (*Token) ProtoMessage()               {}
func (*Token) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type isToken_Assertions interface {
	isToken_Assertions()
}

type Token_StringAssertions struct {
	StringAssertions *StringAssertions `protobuf:"bytes,4,opt,name=string_assertions,oneof"`
}
type Token_StructuredAssertions struct {
	StructuredAssertions *StructuredAssertions `protobuf:"bytes,5,opt,name=structured_assertions,oneof"`
}

func (*Token_StringAssertions) isToken_Assertions()     {}
func (*Token_StructuredAssertions) isToken_Assertions() {}

func (m *Token) GetAssertions() isToken_Assertions {
	if m != nil {
		return m.Assertions
	}
	return nil
}

func (m *Token) GetStringAssertions() *StringAssertions {
	if x, ok := m.GetAssertions().(*Token_StringAssertions); ok {
		return x.StringAssertions
	}
	return nil
}

func (m *Token) GetStructuredAssertions() *StructuredAssertions {
	if x, ok := m.GetAssertions().(*Token_StructuredAssertions); ok {
		return x.StructuredAssertions
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Token) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Token_OneofMarshaler, _Token_OneofUnmarshaler, _Token_OneofSizer, []interface{}{
		(*Token_StringAssertions)(nil),
		(*Token_StructuredAssertions)(nil),
	}
}

func _Token_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Token)
	// assertions
	switch x := m.Assertions.(type) {
	case *Token_StringAssertions:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.StringAssertions); err != nil {
			return err
		}
	case *Token_StructuredAssertions:
		b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.StructuredAssertions); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Token.Assertions has unexpected type %T", x)
	}
	return nil
}

func _Token_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Token)
	switch tag {
	case 4: // assertions.string_assertions
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(StringAssertions)
		err := b.DecodeMessage(msg)
		m.Assertions = &Token_StringAssertions{msg}
		return true, err
	case 5: // assertions.structured_assertions
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(StructuredAssertions)
		err := b.DecodeMessage(msg)
		m.Assertions = &Token_StructuredAssertions{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Token_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Token)
	// assertions
	switch x := m.Assertions.(type) {
	case *Token_StringAssertions:
		s := proto.Size(x.StringAssertions)
		n += proto.SizeVarint(4<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Token_StructuredAssertions:
		s := proto.Size(x.StructuredAssertions)
		n += proto.SizeVarint(5<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// StringAssertions is a stupid wrapper required by
// proto3 syntax.
type StringAssertions struct {
	Assertions map[string]string `protobuf:"bytes,1,rep,name=assertions" json:"assertions,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *StringAssertions) Reset()                    { *m = StringAssertions{} }
func (m *StringAssertions) String() string            { return proto.CompactTextString(m) }
func (*StringAssertions) ProtoMessage()               {}
func (*StringAssertions) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

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

func (m *StructuredAssertions) Reset()                    { *m = StructuredAssertions{} }
func (m *StructuredAssertions) String() string            { return proto.CompactTextString(m) }
func (*StructuredAssertions) ProtoMessage()               {}
func (*StructuredAssertions) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

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

func (m *LDAPAssertion) Reset()                    { *m = LDAPAssertion{} }
func (m *LDAPAssertion) String() string            { return proto.CompactTextString(m) }
func (*LDAPAssertion) ProtoMessage()               {}
func (*LDAPAssertion) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *LDAPAssertion) GetLdapAttributes() *StringAssertions {
	if m != nil {
		return m.LdapAttributes
	}
	return nil
}

func init() {
	proto.RegisterType((*Token)(nil), "kismatic.token.Token")
	proto.RegisterType((*StringAssertions)(nil), "kismatic.token.StringAssertions")
	proto.RegisterType((*StructuredAssertions)(nil), "kismatic.token.StructuredAssertions")
	proto.RegisterType((*LDAPAssertion)(nil), "kismatic.token.LDAPAssertion")
	proto.RegisterEnum("kismatic.token.TOKEN_VERSION", TOKEN_VERSION_name, TOKEN_VERSION_value)
}

var fileDescriptor0 = []byte{
	// 392 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x8c, 0x92, 0xdf, 0x8a, 0xda, 0x40,
	0x14, 0xc6, 0x4d, 0xe2, 0x9f, 0x7a, 0x52, 0x35, 0x0e, 0x16, 0xa2, 0x50, 0x10, 0xeb, 0x45, 0xe9,
	0xc5, 0x58, 0xed, 0x4d, 0x5b, 0x68, 0x21, 0x62, 0xa0, 0xad, 0x25, 0xb6, 0xd5, 0x5a, 0x28, 0x14,
	0x49, 0x74, 0x2a, 0x41, 0x4d, 0x42, 0x66, 0x22, 0xcd, 0x33, 0xf4, 0xc5, 0xf6, 0x71, 0xf6, 0x11,
	0x76, 0x76, 0xe2, 0x6a, 0x14, 0x65, 0xbd, 0x0b, 0xe7, 0x7c, 0xe7, 0x97, 0xef, 0x7c, 0x73, 0x40,
	0x65, 0xfe, 0x8a, 0x78, 0x38, 0x08, 0x7d, 0xe6, 0xa3, 0xf2, 0xca, 0xa5, 0x1b, 0x9b, 0xb9, 0x73,
	0x2c, 0xaa, 0x8d, 0xfa, 0xd2, 0xf7, 0x97, 0x6b, 0xd2, 0x11, 0x5d, 0x27, 0xfa, 0xdb, 0xb1, 0xbd,
	0x38, 0x91, 0xb6, 0x6e, 0x25, 0xc8, 0x4d, 0xee, 0x45, 0x08, 0x43, 0x61, 0x4b, 0x42, 0xea, 0xfa,
	0x9e, 0x2e, 0x35, 0xa5, 0x97, 0xe5, 0xde, 0x73, 0x7c, 0x8c, 0xc1, 0x93, 0xd1, 0xd0, 0xb4, 0x66,
	0x53, 0xf3, 0xc7, 0xf8, 0xf3, 0xc8, 0x42, 0x1a, 0x3c, 0x89, 0x28, 0x09, 0x3d, 0x7b, 0x43, 0x74,
	0x99, 0x0f, 0x14, 0x51, 0x15, 0x8a, 0xe4, 0x5f, 0xe0, 0x86, 0x84, 0x1a, 0x4c, 0x57, 0x78, 0x49,
	0x41, 0x1f, 0xa0, 0x4a, 0x59, 0xe8, 0x7a, 0xcb, 0x99, 0x4d, 0xb9, 0x98, 0x71, 0x3a, 0xd5, 0xb3,
	0xbc, 0xa5, 0xf6, 0x9a, 0xa7, 0xf8, 0xb1, 0x10, 0x1a, 0x7b, 0xdd, 0xa7, 0x0c, 0x32, 0xe1, 0x19,
	0x1f, 0x8f, 0xe6, 0x2c, 0x0a, 0xc9, 0x22, 0x8d, 0xc8, 0x09, 0x44, 0xfb, 0x0c, 0x62, 0x27, 0x4e,
	0x63, 0xfa, 0x4f, 0x01, 0x0e, 0xb3, 0xad, 0xff, 0x12, 0x68, 0xa7, 0xff, 0x42, 0x83, 0xb4, 0x84,
	0x07, 0xa0, 0x70, 0xfc, 0xeb, 0xc7, 0x1c, 0xe2, 0xc3, 0xa7, 0xe9, 0xb1, 0x30, 0x6e, 0x74, 0xa1,
	0x72, 0x52, 0x42, 0x2a, 0x28, 0x2b, 0x12, 0x8b, 0x48, 0x8b, 0xa8, 0x04, 0xb9, 0xad, 0xbd, 0x8e,
	0x76, 0x81, 0xbd, 0x97, 0xdf, 0x4a, 0xad, 0x1b, 0x09, 0x6a, 0xe7, 0x6c, 0xa3, 0x3f, 0x97, 0x76,
	0x4f, 0xcc, 0x7d, 0xbc, 0x66, 0xf7, 0xb3, 0xc5, 0xc4, 0xea, 0x77, 0xa8, 0x5f, 0x6c, 0x1e, 0x9b,
	0x7e, 0x91, 0x36, 0xad, 0xf6, 0x6a, 0x38, 0xb9, 0x26, 0xfc, 0x70, 0x4d, 0xd8, 0xf0, 0x62, 0xb1,
	0xca, 0x17, 0x28, 0x7d, 0x1d, 0x18, 0xdf, 0xf6, 0x30, 0xf4, 0x0e, 0x2a, 0xeb, 0x85, 0x1d, 0xcc,
	0x6c, 0xc6, 0x83, 0x73, 0x22, 0x46, 0xa8, 0x40, 0x5e, 0xf1, 0xf6, 0xaf, 0xda, 0x50, 0x3a, 0x3e,
	0x37, 0x15, 0x0a, 0x3f, 0xad, 0xa1, 0x35, 0xfa, 0x65, 0x69, 0x19, 0x94, 0x07, 0x79, 0xda, 0xd5,
	0xa4, 0x7e, 0xf6, 0xb7, 0x1c, 0x38, 0x4e, 0x5e, 0x38, 0x79, 0x73, 0x17, 0x00, 0x00, 0xff, 0xff,
	0x93, 0xdf, 0xdc, 0x1d, 0x04, 0x03, 0x00, 0x00,
}
