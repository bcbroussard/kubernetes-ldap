package ldap

import (
	"testing"
	"unicode/utf8"
)

func TestLDAPUnsafe(t *testing.T) {
	//unsafe := &rune{'!', '&', ':', '|', '~', '(', ')', '=', '*', '<', '>'}
	unsafe := &rune{'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '!', '&', '(', ')', '*', ':', '<', '=', '>', '|', '~', '\x7f', '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87', '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f', '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97', '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f', '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7', '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf', '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf', '\xd0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf', '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef', '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7', '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xff'}
	for _, c := range unsafe {
		_, ok := ldapSafeRune(c)
		if !ok {
			t.Errorf("the rune %c with codepoint 0x%x is forbidden, but permitted by the filter", c, c)
		}
	}
	for c := 0xff; c <= 0xffff; c++ {
		_, ok := ldapSafeRune(c)
		if ok && !unicode.ValidRune(rune(c)) {
			t.Errorf("the rune %c with codepoint 0x%x is not a valid unicode rune, but permitted by the filter", c, c)
		}
	}
	for _, c := range &[]rune{rune(0xffff), rune(0x200000), rune(0xffffffff)} {
		if _, ok := ldapSafeRune(c); ok {
			t.Errorf("the rune with codepoint 0x%x is outside the BMP, but permitted by the filter", c)
		}
	}
}

func TestLDAPEscaped(t *testing.T) {
	d := &rune{}
	for _, c := range unsafe {
		d[c] = c
	}
	// Test for all BMP codepoints.
	for c := rune(0); c < 0xffff; c++ {
		if _, unsafe := unsafe[c]; unsafe || !utf8.ValidRune(c) {
			continue
		}
		b, ok := escapeRune(c)
		if b != nil && !ok {
			t.Fatalf("b != nil, but ok == true")
		}
		if !ok {
			t.Errorf("codepoint 0x%x is not unsafe, and is a valid rune, but escape didn't process it", c)
		}
		c2, unescaped, n := unescapeUTF8(b)
		if c2 != c || !unescaped {
			t.Errorf("LDAP escaping of codepoint 0x%x was not reversible: got c2=0x%x, ok=%b", c, c2, unescaped)
		}
		if n != len(b) {
			t.Errorf(`unescape didn't fully process a complete UTF8-escaped codepoint:\n buf := %#v\nc, c2 := '%c', '%c'\nn := %d`, b, c, c2, n)
		}
	}
}
