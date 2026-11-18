//go:build linux

package secretservice

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// TestLiveSecretService drives the real godbus backend against a running
// Secret Service daemon (e.g. gnome-keyring-daemon). It is gated on the outer
// env var SECRETSERVICE_LIVE=1 only: once opted in, an unreachable daemon is a
// FAILURE, never a skip — a skip in a lane whose job is to prove the backend
// would look like proof and be none (see the "a skip is not a pass" rule).
//
//	dbus-run-session -- sh -c 'printf "" | gnome-keyring-daemon --unlock \
//	  --components=secrets >/dev/null 2>&1; SECRETSERVICE_LIVE=1 go test -run Live'
//
// deleteByAttrsForTest removes every item carrying attrs (test cleanup).
func deleteByAttrsForTest(attrs map[string]string) error {
	b, err := dialDBus()
	if err != nil {
		return err
	}
	defer b.close()
	d := b.(*dbusBackend)
	items, err := d.searchAttrs(attrs)
	if err != nil {
		return err
	}
	for _, it := range items {
		var prompt dbus.ObjectPath
		if err := d.conn.Object(ssBus, it).Call(ifaceItem+".Delete", 0).Store(&prompt); err != nil {
			return err
		}
	}
	return nil
}

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

	// Lookup by arbitrary attributes: the item carries service and account;
	// asking for the account alone finds it, a subset need not be the whole key.
	if got, err = GetByAttributes(map[string]string{"account": account}); err != nil || !bytes.Equal(got, want2) {
		t.Fatalf("GetByAttributes = %q, %v", got, err)
	}
	if _, err := GetByAttributes(map[string]string{"account": account + "-absent"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByAttributes(absent) = %v, want ErrNotFound", err)
	}
	// An item with arbitrary attributes: created, read back, replaced in place.
	attrs := map[string]string{"Title": "live " + account, "UserName": "me"}
	t.Cleanup(func() { _ = deleteByAttrsForTest(attrs) })
	if err := SetByAttributes("live", attrs, []byte("first")); err != nil {
		t.Fatalf("SetByAttributes: %v", err)
	}
	if err := SetByAttributes("live", attrs, []byte("second")); err != nil {
		t.Fatalf("SetByAttributes (replace): %v", err)
	}
	if got, err := GetByAttributes(map[string]string{"Title": attrs["Title"]}); err != nil || string(got) != "second" {
		t.Fatalf("after replace: %q %v (one item, the second value)", got, err)
	}
	// Two items sharing one attribute are ambiguous, never picked between.
	other := account + "-twin"
	t.Cleanup(func() { _ = Delete(service, other) })
	if err := Set(service, other, []byte("x")); err != nil {
		t.Fatalf("Set twin: %v", err)
	}
	if _, err := GetByAttributes(map[string]string{"service": service}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("GetByAttributes(two items) = %v, want ErrAmbiguous", err)
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
