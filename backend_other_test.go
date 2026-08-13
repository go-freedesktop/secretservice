//go:build !linux

package secretservice

import (
	"errors"
	"testing"
)

// On non-Linux platforms the real (non-overridden) openBackend must report
// ErrUnavailable through every entry point, so consumers get a clear failure
// and never a silent success.
func TestOtherStubUnavailable(t *testing.T) {
	if _, err := openBackend(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("openBackend() err = %v, want ErrUnavailable", err)
	}
	if err := Set("s", "a", []byte("x")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Set = %v, want ErrUnavailable", err)
	}
	if _, err := Get("s", "a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get = %v, want ErrUnavailable", err)
	}
	if err := Delete("s", "a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Delete = %v, want ErrUnavailable", err)
	}
	if Available() {
		t.Fatal("Available() = true off Linux, want false")
	}
}
