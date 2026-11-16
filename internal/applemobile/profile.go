// Package applemobile builds the configuration profile (.mobileconfig) that sets up
// a mail account on iPhone and Mac, and serves the form that requests it.
//
// The profile carries server settings only. It never contains a password: the device
// asks for it when the profile is installed.
package applemobile

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- RFC 4122 name-based UUID (v5), not used for security
	"encoding/xml"
	"errors"
	"fmt"

	"mailadmin/internal/valid"
)

// profileNamespace is the fixed namespace for name-based account UUIDs. The same
// address always gets the same UUID, so installing the profile again replaces the
// account instead of adding a second one.
var profileNamespace = [16]byte{0x5b, 0x1e, 0x6d, 0x0a, 0x7c, 0x3f, 0x4e, 0x21, 0x9a, 0x8d, 0x2c, 0x61, 0x44, 0xb0, 0x7e, 0x90}

// ErrBadAddress is returned for an address that is not a valid mailbox address.
var ErrBadAddress = errors.New("applemobile: invalid mail address")

// accountUUID returns an RFC 4122 version 5 UUID for name.
func accountUUID(name string) string {
	h := sha1.New() // #nosec G401 -- name-based UUID, see import comment
	h.Write(profileNamespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// BuildProfile returns the .mobileconfig for address. host is the mail server name
// used for IMAP (993, TLS) and SMTP submission (465, TLS).
func BuildProfile(address, host string) ([]byte, error) {
	if _, _, err := valid.Address(address); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadAddress, err)
	}
	if _, err := valid.Domain(host); err != nil {
		return nil, fmt.Errorf("applemobile: invalid mail host: %w", err)
	}
	account := accountUUID("account:" + address)
	profile := accountUUID("profile:" + address)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0"><dict>` + "\n")
	b.WriteString("<key>PayloadContent</key>\n<array>\n<dict>\n")
	dict(&b, [][2]any{
		{"EmailAccountDescription", host},
		{"EmailAccountName", address},
		{"EmailAccountType", "EmailTypeIMAP"},
		{"EmailAddress", address},
		{"IncomingMailServerAuthentication", "EmailAuthPassword"},
		{"IncomingMailServerHostName", host},
		{"IncomingMailServerPortNumber", 993},
		{"IncomingMailServerUseSSL", true},
		{"IncomingMailServerUsername", address},
		{"OutgoingMailServerAuthentication", "EmailAuthPassword"},
		{"OutgoingMailServerHostName", host},
		{"OutgoingMailServerPortNumber", 465},
		{"OutgoingMailServerUseSSL", true},
		{"OutgoingMailServerUsername", address},
		{"OutgoingPasswordSameAsIncomingPassword", true},
		{"PayloadDescription", "Mail account " + address},
		{"PayloadDisplayName", address},
		{"PayloadIdentifier", "mailadmin.mail." + account},
		{"PayloadType", "com.apple.mail.managed"},
		{"PayloadUUID", account},
		{"PayloadVersion", 1},
	})
	b.WriteString("</dict>\n</array>\n")
	dict(&b, [][2]any{
		{"PayloadDescription", "Mail settings for " + address + ". No password is stored in this profile."},
		{"PayloadDisplayName", "Mail: " + address},
		{"PayloadIdentifier", "mailadmin.profile." + profile},
		{"PayloadRemovalDisallowed", false},
		{"PayloadType", "Configuration"},
		{"PayloadUUID", profile},
		{"PayloadVersion", 1},
	})
	b.WriteString("</dict></plist>\n")
	return b.Bytes(), nil
}

// dict writes the key/value pairs of one plist dictionary body (the outer <dict> is
// written by the caller). Values are limited to string, int and bool.
func dict(b *bytes.Buffer, pairs [][2]any) {
	for _, p := range pairs {
		b.WriteString("<key>")
		escape(b, p[0].(string))
		b.WriteString("</key>")
		switch v := p[1].(type) {
		case string:
			b.WriteString("<string>")
			escape(b, v)
			b.WriteString("</string>")
		case int:
			fmt.Fprintf(b, "<integer>%d</integer>", v)
		case bool:
			if v {
				b.WriteString("<true/>")
			} else {
				b.WriteString("<false/>")
			}
		default:
			panic(fmt.Sprintf("applemobile: unsupported plist value %T", v))
		}
		b.WriteString("\n")
	}
}

func escape(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}
