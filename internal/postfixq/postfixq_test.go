package postfixq

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseQueueJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []Mail
		wantErr bool
	}{
		{
			name:  "empty output",
			input: "",
			want:  nil,
		},
		{
			name:  "blank lines only",
			input: "\n   \n\t\n",
			want:  nil,
		},
		{
			name: "single deferred message",
			input: `{"queue_name":"deferred","queue_id":"3F1A2B4C5D","arrival_time":1700000000,` +
				`"message_size":2048,"sender":"alice@example.com",` +
				`"recipients":[{"address":"bob@example.net","delay_reason":"connection timed out"}]}`,
			want: []Mail{{
				QueueID: "3F1A2B4C5D",
				Size:    2048,
				Arrival: "2023-11-14 22:13:20",
				Sender:  "alice@example.com",
				Rcpts:   []string{"bob@example.net"},
				Status:  "deferred",
				Reason:  "connection timed out",
			}},
		},
		{
			name: "multiple lines multiple recipients",
			input: `{"queue_name":"active","queue_id":"AAAA11","arrival_time":1700000000,"message_size":10,"sender":"a@x.de","recipients":[{"address":"r1@y.de","delay_reason":""},{"address":"r2@y.de","delay_reason":"deferred: greylisted"}]}
{"queue_name":"hold","queue_id":"BBBB22","arrival_time":0,"message_size":0,"sender":"","recipients":[]}`,
			want: []Mail{
				{
					QueueID: "AAAA11",
					Size:    10,
					Arrival: "2023-11-14 22:13:20",
					Sender:  "a@x.de",
					Rcpts:   []string{"r1@y.de", "r2@y.de"},
					Status:  "active",
					Reason:  "deferred: greylisted",
				},
				{
					QueueID: "BBBB22",
					Status:  "hold",
				},
			},
		},
		{
			name: "unknown fields tolerated",
			input: `{"queue_name":"deferred","queue_id":"CAFE01","arrival_time":1700000000,` +
				`"message_size":5,"sender":"s@d.de","recipients":[],"forced_expire":false}`,
			want: []Mail{{
				QueueID: "CAFE01",
				Size:    5,
				Arrival: "2023-11-14 22:13:20",
				Sender:  "s@d.de",
				Status:  "deferred",
			}},
		},
		{
			name:    "malformed json fails closed",
			input:   `{"queue_id":"BADJSON"`,
			wantErr: true,
		},
		{
			name:  "recipient with empty address skipped",
			input: `{"queue_name":"deferred","queue_id":"DEAD10","message_size":1,"sender":"s@d.de","recipients":[{"address":"  ","delay_reason":"x"},{"address":"ok@d.de","delay_reason":""}]}`,
			want: []Mail{{
				QueueID: "DEAD10",
				Size:    1,
				Sender:  "s@d.de",
				Rcpts:   []string{"ok@d.de"},
				Status:  "deferred",
				Reason:  "x",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseQueueJSON([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

func TestFormatArrival(t *testing.T) {
	tests := []struct {
		name string
		unix int64
		want string
	}{
		{"zero", 0, ""},
		{"negative", -5, ""},
		{"known epoch", 1700000000, "2023-11-14 22:13:20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatArrival(tt.unix); got != tt.want {
				t.Fatalf("formatArrival(%d) = %q, want %q", tt.unix, got, tt.want)
			}
		})
	}
}

func TestNormalizeStatus(t *testing.T) {
	tests := map[string]string{
		"active":     "active",
		"DEFERRED":   "deferred",
		"  Hold  ":   "hold",
		"incoming":   "incoming",
		"":           "",
		"MutantMode": "mutantmode",
	}
	for in, want := range tests {
		if got := normalizeStatus(in); got != want {
			t.Errorf("normalizeStatus(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEntryToMail(t *testing.T) {
	e := queueEntry{
		QueueName:   " Deferred ",
		QueueID:     "  ABC123  ",
		ArrivalTime: 1700000000,
		MessageSize: 42,
		Sender:      "s@d.de",
	}
	e.Recipients = append(e.Recipients, struct {
		Address     string `json:"address"`
		DelayReason string `json:"delay_reason"`
	}{Address: "one@d.de", DelayReason: ""})
	e.Recipients = append(e.Recipients, struct {
		Address     string `json:"address"`
		DelayReason string `json:"delay_reason"`
	}{Address: "two@d.de", DelayReason: "reason"})

	got := entryToMail(e)
	if got.QueueID != "ABC123" {
		t.Errorf("QueueID not trimmed: %q", got.QueueID)
	}
	if got.Status != "deferred" {
		t.Errorf("Status not normalized: %q", got.Status)
	}
	if strings.Join(got.Rcpts, ",") != "one@d.de,two@d.de" {
		t.Errorf("recipients mismatch: %v", got.Rcpts)
	}
	if got.Reason != "reason" {
		t.Errorf("Reason mismatch: %q", got.Reason)
	}
}
