package sieve

import (
	"errors"
	"strings"
	"testing"

	"mailadmin/internal/valid"
)

func TestGenerateVacationAlwaysOn(t *testing.T) {
	got, err := GenerateVacation(VacationOptions{
		Subject: "Out of office",
		Message: "I am away.\nBack soon.",
	})
	if err != nil {
		t.Fatalf("GenerateVacation: %v", err)
	}
	want := "require [\"vacation\"];\n\n" +
		"vacation\n" +
		"    :days 7\n" +
		"    :subject \"Out of office\"\n" +
		"    text:\n" +
		"I am away.\n" +
		"Back soon.\n" +
		".\n" +
		";\n"
	if got != want {
		t.Errorf("GenerateVacation() =\n%s\nwant\n%s", got, want)
	}
}

func TestGenerateVacationWindowed(t *testing.T) {
	got, err := GenerateVacation(VacationOptions{
		Start:   "2026-09-01",
		End:     "2026-09-10",
		Subject: "Away",
		Message: "back on the 11th",
		Days:    2,
	})
	if err != nil {
		t.Fatalf("GenerateVacation: %v", err)
	}
	for _, want := range []string{
		"require [\"vacation\", \"date\", \"relational\"];",
		`if allof(currentdate :value "ge" "date" "2026-09-01",`,
		`         currentdate :value "le" "date" "2026-09-10")`,
		"{",
		"    vacation",
		"    :days 2",
		`    :subject "Away"`,
		"}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("GenerateVacation() missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateVacationDefaultsAndClamps(t *testing.T) {
	got, err := GenerateVacation(VacationOptions{Message: "hi"})
	if err != nil {
		t.Fatalf("GenerateVacation: %v", err)
	}
	if !strings.Contains(got, ":days 7") {
		t.Errorf("default days not applied:\n%s", got)
	}

	if _, err := GenerateVacation(VacationOptions{Message: "hi", Days: 9999}); err == nil {
		t.Fatalf("expected error for excessive --days")
	} else if !errors.Is(err, valid.ErrInvalid) {
		t.Errorf("error = %v, want wrapping valid.ErrInvalid", err)
	}
}

func TestGenerateVacationNoSubject(t *testing.T) {
	got, err := GenerateVacation(VacationOptions{Message: "hi"})
	if err != nil {
		t.Fatalf("GenerateVacation: %v", err)
	}
	if strings.Contains(got, ":subject") {
		t.Errorf("did not expect a :subject tag when Subject is empty:\n%s", got)
	}
}

func TestGenerateVacationErrors(t *testing.T) {
	tests := []struct {
		name string
		opts VacationOptions
	}{
		{"empty message", VacationOptions{Message: "   "}},
		{"start without end", VacationOptions{Message: "hi", Start: "2026-09-01"}},
		{"end without start", VacationOptions{Message: "hi", End: "2026-09-01"}},
		{"bad start format", VacationOptions{Message: "hi", Start: "09/01/2026", End: "2026-09-10"}},
		{"end before start", VacationOptions{Message: "hi", Start: "2026-09-10", End: "2026-09-01"}},
		{"end equal start", VacationOptions{Message: "hi", Start: "2026-09-01", End: "2026-09-01"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := GenerateVacation(tt.opts); err == nil {
				t.Fatalf("expected error")
			} else if !errors.Is(err, valid.ErrInvalid) {
				t.Errorf("error = %v, want wrapping valid.ErrInvalid", err)
			}
		})
	}
}

func TestGenerateVacationEscapesSubject(t *testing.T) {
	got, err := GenerateVacation(VacationOptions{
		Message: "hi",
		Subject: `She said "hi" \ bye`,
	})
	if err != nil {
		t.Fatalf("GenerateVacation: %v", err)
	}
	want := `:subject "She said \"hi\" \\ bye"`
	if !strings.Contains(got, want) {
		t.Errorf("GenerateVacation() missing escaped subject %q in:\n%s", want, got)
	}
}

func TestGenerateVacationDotStuffing(t *testing.T) {
	got, err := GenerateVacation(VacationOptions{
		Message: "line one\n.\n.leading dot\nline three",
	})
	if err != nil {
		t.Fatalf("GenerateVacation: %v", err)
	}
	if !strings.Contains(got, "\n..\n") {
		t.Errorf("expected dot-stuffed terminator-lookalike line, got:\n%s", got)
	}
	if !strings.Contains(got, "\n..leading dot\n") {
		t.Errorf("expected dot-stuffed leading-dot line, got:\n%s", got)
	}
	// The real terminator "." must still be present exactly once as its own line.
	if strings.Count(got, "\n.\n") != 1 {
		t.Errorf("expected exactly one bare terminator line, got:\n%s", got)
	}
}

func TestGenerateDisabled(t *testing.T) {
	got := GenerateDisabled()
	if !strings.Contains(got, "keep;") {
		t.Errorf("GenerateDisabled() = %q, want it to contain keep;", got)
	}
}
