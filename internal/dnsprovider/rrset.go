package dnsprovider

import (
	"fmt"
	"strconv"
	"strings"
)

// This file holds the record<->value helpers shared by the RRset-oriented
// backends (deSEC and servfail.network/PowerDNS), which store a name+type set of
// string values with no per-record id. A synthetic ID (slot\x1ftype\x1fvalue)
// lets those providers satisfy the per-record Provider interface.

const rrIDSep = "\x1f"

// rrID encodes a synthetic record id for an RRset value.
func rrID(slot, typ, value string) string {
	return slot + rrIDSep + strings.ToUpper(typ) + rrIDSep + value
}

// parseRRID reverses rrID.
func parseRRID(id string) (slot, typ, value string, ok bool) {
	parts := strings.SplitN(id, rrIDSep, 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// rrsetValue renders a Record as an RFC-1035 presentation value: inline
// priority for MX/SRV, trailing-dot FQDN for host targets, and quoted TXT. This
// is the wire format both deSEC and PowerDNS expect.
func rrsetValue(r Record) string {
	switch strings.ToUpper(r.Type) {
	case "MX":
		return fmt.Sprintf("%d %s", r.Prio, fqdn(r.Content))
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", r.Prio, r.Weight, r.Port, fqdn(r.Content))
	case "CNAME", "NS", "PTR":
		return fqdn(r.Content)
	case "TXT":
		return quoteTXT(r.Content)
	default:
		return r.Content
	}
}

// rrsetParse turns one presentation value back into a Record's structured
// fields (Prio/Weight/Port/Content), the inverse of rrsetValue.
func rrsetParse(r *Record, value string) {
	switch strings.ToUpper(r.Type) {
	case "MX":
		r.Prio, r.Content = splitPrio(value)
	case "SRV":
		fields := strings.Fields(value)
		if len(fields) == 4 {
			r.Prio, _ = strconv.Atoi(fields[0])
			r.Weight, _ = strconv.Atoi(fields[1])
			r.Port, _ = strconv.Atoi(fields[2])
			r.Content = fields[3]
		} else {
			r.Content = value
		}
	case "TXT":
		r.Content = unquoteTXT(value)
	default:
		r.Content = value
	}
}
