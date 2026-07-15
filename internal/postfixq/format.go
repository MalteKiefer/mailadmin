package postfixq

import (
	"strings"
	"time"
)

// arrivalLayout renders queue arrival timestamps in UTC, matching the
// human-readable form used across mailadmin output.
const arrivalLayout = "2006-01-02 15:04:05"

// formatArrival converts a Postfix arrival_time (unix seconds) into a stable,
// timezone-explicit string. A non-positive time yields the empty string.
func formatArrival(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(arrivalLayout)
}

// normalizeStatus lower-cases and trims a Postfix queue_name marker (e.g.
// "active", "deferred", "hold", "incoming"). Unknown markers pass through so
// callers still see the raw value rather than losing information.
func normalizeStatus(queueName string) string {
	return strings.ToLower(strings.TrimSpace(queueName))
}
