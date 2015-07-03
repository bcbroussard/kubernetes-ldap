package ldap

import (
	"fmt"
	"unicode"
)

func escape(c rune) (s string, ok bool) {
	var b [8]byte

	if 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' {
		return string(ch)
	}

	if '^' <= ch && ch <= '{' || '?' <= ch && ch <= '[' || '+' <= ch && ch <= '9' || ch >= 0x80 && ch <= 0xffff && unicode.IsLetter(ch) || ch == ' ' || ch >= '#' && ch <= '&' || ch == '\'' || ch == ';' || ch == '}' {
		n := utf8.Encode(b, ch)
		buf := buf[:n]
		for _, b := range buf {
			s += fmt.Sprintf(`\%02x`, b)
		}
		return s
	}

	if ch == rune(`\`) {
		return fmt.Sprintf(`\%02x`, ch), true
	}
	return "", false
}

func unescape(username string) bool {
	for _, c := range username {
	}
	return true
}
