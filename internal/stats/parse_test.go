package stats

import (
	"reflect"
	"testing"
)

func TestSplitSyslog(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantTS    string
		wantIdent string
		wantMsg   string
		wantOK    bool
	}{
		{
			name:      "postfix smtp",
			line:      "2026-07-14T10:00:00+0200 mail postfix/smtp[123]: ABC1: to=<a@b.de>, status=sent",
			wantTS:    "2026-07-14T10:00:00+0200",
			wantIdent: "postfix/smtp",
			wantMsg:   "ABC1: to=<a@b.de>, status=sent",
			wantOK:    true,
		},
		{
			name:      "no pid",
			line:      "2026-07-14T10:00:00+0200 mail rspamd: something (no action)",
			wantTS:    "2026-07-14T10:00:00+0200",
			wantIdent: "rspamd",
			wantMsg:   "something (no action)",
			wantOK:    true,
		},
		{name: "empty", line: "", wantOK: false},
		{name: "one field", line: "hello", wantOK: false},
		{name: "no colon", line: "2026-07-14 mail postfix/smtp[1] no colon here", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts, ident, msg, ok := splitSyslog(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ts != tc.wantTS || ident != tc.wantIdent || msg != tc.wantMsg {
				t.Errorf("got (%q,%q,%q), want (%q,%q,%q)", ts, ident, msg, tc.wantTS, tc.wantIdent, tc.wantMsg)
			}
		})
	}
}

func TestFieldValue(t *testing.T) {
	msg := "ABC1: to=<user@example.com>, relay=127.0.0.1[127.0.0.1]:24, delay=0.1, status=sent (250 2.0.0 OK)"
	tests := []struct {
		key, want string
	}{
		{"to=", "<user@example.com>"},
		{"relay=", "127.0.0.1[127.0.0.1]:24"},
		{"status=", "sent (250 2.0.0 OK)"},
		{"missing=", ""},
	}
	for _, tc := range tests {
		if got := fieldValue(msg, tc.key); got != tc.want {
			t.Errorf("fieldValue(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestDomainOfAndUnbracket(t *testing.T) {
	if got := unbracket("<a@b.de>"); got != "a@b.de" {
		t.Errorf("unbracket = %q", got)
	}
	tests := map[string]string{
		"user@Example.COM": "example.com",
		"nobody":           "",
		"@nolocal.de":      "nolocal.de",
		"trailing@":        "",
	}
	for in, want := range tests {
		if got := domainOf(in); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPostfixProg(t *testing.T) {
	tests := []struct {
		ident  string
		want   string
		wantOK bool
	}{
		{"postfix/smtp", "smtp", true},
		{"postfix/smtpd", "smtpd", true},
		{"postfix-inbound/lmtp", "lmtp", true},
		{"dovecot/lmtp", "", false},
		{"postfix", "", false},
		{"postfix/", "", false},
	}
	for _, tc := range tests {
		got, ok := postfixProg(tc.ident)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("postfixProg(%q) = (%q,%v), want (%q,%v)", tc.ident, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestParsePostfixMsg(t *testing.T) {
	tests := []struct {
		name string
		prog string
		msg  string
		want postfixEvent
		ok   bool
	}{
		{
			name: "local sent via lmtp",
			prog: "lmtp",
			msg:  "ABC1: to=<u@ex.de>, relay=dovecot, status=sent (250 OK)",
			want: postfixEvent{Prog: "lmtp", Status: "sent", To: "u@ex.de", ToDom: "ex.de", Local: true},
			ok:   true,
		},
		{
			name: "outbound sent via smtp",
			prog: "smtp",
			msg:  "DEF2: to=<x@remote.org>, relay=mx.remote.org[1.2.3.4]:25, status=sent (250)",
			want: postfixEvent{Prog: "smtp", Status: "sent", To: "x@remote.org", ToDom: "remote.org", Local: false},
			ok:   true,
		},
		{
			name: "smtp to loopback dovecot is local",
			prog: "smtp",
			msg:  "GHI3: to=<u@ex.de>, relay=127.0.0.1[127.0.0.1]:24, status=sent",
			want: postfixEvent{Prog: "smtp", Status: "sent", To: "u@ex.de", ToDom: "ex.de", Local: true},
			ok:   true,
		},
		{
			name: "deferred",
			prog: "smtp",
			msg:  "JKL4: to=<y@remote.org>, relay=none, delay=1, status=deferred (connect timeout)",
			want: postfixEvent{Prog: "smtp", Status: "deferred", To: "y@remote.org", ToDom: "remote.org", Local: false},
			ok:   true,
		},
		{
			name: "smtpd reject",
			prog: "smtpd",
			msg:  "NOQUEUE: reject: RCPT from unknown[9.9.9.9]: 554 5.7.1 blocked",
			want: postfixEvent{Prog: "smtpd", Status: "reject"},
			ok:   true,
		},
		{
			name: "smtpd non-reject ignored",
			prog: "smtpd",
			msg:  "connect from unknown[9.9.9.9]",
			ok:   false,
		},
		{
			name: "no status ignored",
			prog: "qmgr",
			msg:  "ABC1: removed",
			ok:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parsePostfixMsg(tc.prog, tc.msg)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// sampleLines is a mixed postfix journal excerpt used across summary tests.
var sampleLines = []string{
	`2026-07-01T08:00:00+0200 mail postfix/lmtp[10]: A1: to=<alice@ex.de>, relay=dovecot, status=sent (250 OK)`,
	`2026-07-01T09:00:00+0200 mail postfix/lmtp[10]: A2: to=<bob@ex.de>, relay=dovecot, status=sent (250 OK)`,
	`2026-07-02T09:00:00+0200 mail postfix/lmtp[10]: A3: to=<alice@ex.de>, relay=dovecot, status=sent (250 OK)`,
	`2026-07-02T09:05:00+0200 mail postfix/lmtp[10]: A4: to=<carol@ex.de>, relay=dovecot, status=deferred (temp)`,
	`2026-07-02T09:06:00+0200 mail postfix/smtpd[11]: NOQUEUE: reject: RCPT from bad[9.9.9.9]: 554 blocked`,
	`2026-07-02T10:00:00+0200 mail postfix/smtp[12]: B1: to=<x@remote.org>, relay=mx.remote.org[1.2.3.4]:25, status=sent (250)`,
	`2026-07-02T10:01:00+0200 mail postfix/smtp[12]: B2: to=<y@remote.org>, relay=none, status=deferred (timeout)`,
	`2026-07-02T10:02:00+0200 mail postfix/smtp[12]: B3: to=<z@remote.org>, relay=mx[1.2.3.4]:25, status=bounced (550)`,
	`this is not a syslog line and must be skipped`,
}

func TestSummarizeInbound(t *testing.T) {
	got := summarizeInbound(parsePostfix(sampleLines))
	if got.Kind != "inbound" {
		t.Fatalf("kind = %q", got.Kind)
	}
	if got.Accepted != 3 { // A1,A2,A3
		t.Errorf("accepted = %d, want 3", got.Accepted)
	}
	if got.Deferred != 1 { // A4
		t.Errorf("deferred = %d, want 1", got.Deferred)
	}
	if got.Rejected != 1 { // smtpd reject
		t.Errorf("rejected = %d, want 1", got.Rejected)
	}
	wantSeries := []Point{{Label: "2026-07-01", Value: 2}, {Label: "2026-07-02", Value: 1}}
	if len(got.Series) != 1 || !reflect.DeepEqual(got.Series[0].Points, wantSeries) {
		t.Errorf("series = %+v, want %+v", got.Series, wantSeries)
	}
}

func TestSummarizeOutbound(t *testing.T) {
	got := summarizeOutbound(parsePostfix(sampleLines))
	if got.Accepted != 1 { // B1
		t.Errorf("accepted = %d, want 1", got.Accepted)
	}
	if got.Deferred != 1 { // B2
		t.Errorf("deferred = %d, want 1", got.Deferred)
	}
	if got.Rejected != 1 { // B3 bounced
		t.Errorf("rejected = %d, want 1", got.Rejected)
	}
}

func TestSummarizeDomain(t *testing.T) {
	got := summarizeDomain(parsePostfix(sampleLines), "ex.de", 10)
	if got.Accepted != 3 {
		t.Errorf("accepted = %d, want 3", got.Accepted)
	}
	if got.Deferred != 1 {
		t.Errorf("deferred = %d, want 1", got.Deferred)
	}
	want := []Point{
		{Label: "alice@ex.de", Value: 2},
		{Label: "bob@ex.de", Value: 1},
	}
	if len(got.Series) != 1 || !reflect.DeepEqual(got.Series[0].Points, want) {
		t.Errorf("top recipients = %+v, want %+v", got.Series, want)
	}
}

func TestTopPointsTruncationAndOrder(t *testing.T) {
	counts := map[string]int64{"a": 1, "b": 5, "c": 5, "d": 2}
	got := topPoints(counts, 2)
	want := []Point{{Label: "b", Value: 5}, {Label: "c", Value: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseRspamdAndSummarizeSpam(t *testing.T) {
	lines := []string{
		`2026-07-01T08:00:00+0200 mail rspamd[1]: <a>; task; result: (default: F (no action): [1.0/15])`,
		`2026-07-01T08:01:00+0200 mail rspamd[1]: <b>; task; result: (default: T (reject): [20.0/15])`,
		`2026-07-01T08:02:00+0200 mail rspamd[1]: <c>; task; result: (default: T (soft reject): [16/15])`,
		`2026-07-01T08:03:00+0200 mail rspamd[1]: <d>; task; result: (default: T (greylist): [5/15])`,
		`2026-07-01T08:04:00+0200 mail rspamd[1]: <e>; task; result: (default: T (add header): [8/15])`,
		`2026-07-01T08:05:00+0200 mail rspamd[1]: action=rewrite_subject for msg`,
		`2026-07-01T08:06:00+0200 mail dovecot[2]: unrelated line`,
		`2026-07-01T08:07:00+0200 mail rspamd[1]: proxy connected, no verdict here`,
	}
	acts := parseRspamd(lines)
	if len(acts) != 6 {
		t.Fatalf("parsed %d actions, want 6: %+v", len(acts), acts)
	}
	got := summarizeSpam(acts)
	if got.Accepted != 1 { // no action
		t.Errorf("accepted = %d, want 1", got.Accepted)
	}
	if got.Spam != 2 { // reject + soft reject
		t.Errorf("spam = %d, want 2", got.Spam)
	}
	if got.Deferred != 1 { // greylist
		t.Errorf("deferred = %d, want 1", got.Deferred)
	}
	// series must be in canonical order and only include seen actions.
	wantSeries := []Point{
		{Label: actRewrite, Value: 1},
		{Label: actAddHeader, Value: 1},
		{Label: actSoftRej, Value: 1},
		{Label: actNoAction, Value: 1},
		{Label: actGreylist, Value: 1},
		{Label: actReject, Value: 1},
	}
	if len(got.Series) != 1 || !reflect.DeepEqual(got.Series[0].Points, wantSeries) {
		t.Errorf("series = %+v, want %+v", got.Series[0].Points, wantSeries)
	}
}

func TestRspamdActionOfSoftRejectNotShadowed(t *testing.T) {
	if a, ok := rspamdActionOf("verdict (soft reject) applied"); !ok || a != actSoftRej {
		t.Errorf("got (%q,%v), want soft reject", a, ok)
	}
}

func TestPickUnit(t *testing.T) {
	units := []string{"postfix", "dovecot", "rspamd.service", "caddy"}
	if u := postfixUnit(units); u != "postfix" {
		t.Errorf("postfixUnit = %q", u)
	}
	if u := rspamdUnit(units); u != "rspamd.service" {
		t.Errorf("rspamdUnit = %q", u)
	}
	if u := rspamdUnit([]string{"caddy"}); u != "rspamd" {
		t.Errorf("rspamdUnit fallback = %q", u)
	}
}

func TestSplitLines(t *testing.T) {
	got := splitLines("a\r\n\nb\n")
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
