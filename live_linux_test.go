//go:build linux

package secretservice

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestLiveSecretService drives the real godbus backend against a running
// Secret Service daemon (e.g. gnome-keyring-daemon). It is gated on the outer
// env var SECRETSERVICE_LIVE=1 only: once opted in, an unreachable daemon is a
// FAILURE, never a skip — a skip in a lane whose job is to prove the backend
// would look like proof and be none (see the "a skip is not a pass" rule).
//
//	dbus-run-session -- sh -c 'printf "" | gnome-keyring-daemon --unlock \
//	  --components=secrets >/dev/null 2>&1; SECRETSERVICE_LIVE=1 go test -run Live'
func TestLiveSecretService(t *testing.T) {
	if os.Getenv("SECRETSERVICE_LIVE") != "1" {
		t.Skip("set SECRETSERVICE_LIVE=1 to run the live Secret Service round-trip")
	}

	if !Available() {
		t.Fatal("Available() = false with SECRETSERVICE_LIVE=1: no reachable Secret Service daemon")
	}

	const service = "go-freedesktop/secretservice live-test"
	account := fmt.Sprintf("acct-%d", time.Now().UnixNano())
	// Ensure a clean slate and always clean up.
	_ = Delete(service, account)
	t.Cleanup(func() { _ = Delete(service, account) })

	// Missing item reads as ErrNotFound.
	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}

	// Store and read back.
	want := []byte("s3cr3t-\x00-value-with-NUL-and-binary-\xff")
	if err := Set(service, account, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := Get(service, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get = %q, want %q", got, want)
	}

	// Overwrite in place (replace=true) — the value updates, no duplicate item.
	want2 := []byte("rotated-secret")
	if err := Set(service, account, want2); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}
	got, err = Get(service, account)
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if !bytes.Equal(got, want2) {
		t.Fatalf("Get after overwrite = %q, want %q", got, want2)
	}

	// Delete, then confirm it is gone and that deleting again is not an error.
	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(service, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := Delete(service, account); err != nil {
		t.Fatalf("Delete of absent item = %v, want nil", err)
	}
}
