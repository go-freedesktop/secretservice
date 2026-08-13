// Package secretservice is a pure-Go (CGO_ENABLED=0) client for the
// freedesktop Secret Service API (org.freedesktop.Secret.Service) spoken over
// D-Bus via github.com/godbus/dbus/v5. It talks to GNOME Keyring, KWallet, or
// any conforming secret daemon and never shells out to secret-tool.
//
// The public surface is three byte-oriented calls over a (service, account)
// pair, each mapping to a Secret Service item whose lookup attributes are
// {service, account}, plus an availability probe:
//
//	err          := secretservice.Set(service, account, secret)
//	secret, err  := secretservice.Get(service, account)   // ErrNotFound if absent
//	err          := secretservice.Delete(service, account)
//	ok           := secretservice.Available()
//
// Each call opens a fresh D-Bus connection, opens a plain-algorithm session,
// resolves and unlocks the default collection, performs the operation and
// closes the connection. When no session bus or no Secret Service daemon is
// reachable — for example a headless machine with no login keyring — every
// entry point returns [ErrUnavailable] rather than silently succeeding or
// leaking a plaintext secret elsewhere.
//
// On non-Linux platforms the package still builds and cross-compiles; every
// entry point returns [ErrUnavailable] there (the Secret Service is a
// freedesktop/Linux facility).
package secretservice

import "errors"

// Sentinel errors. They are stable and may be compared with [errors.Is].
var (
	// ErrUnavailable is returned when no Secret Service is reachable: no
	// D-Bus session bus, no daemon owning org.freedesktop.secrets, or a
	// non-Linux platform. It never masks a stored secret — a caller seeing
	// ErrUnavailable knows nothing was read or written.
	ErrUnavailable = errors.New("secretservice: no Secret Service daemon available")
	// ErrNotFound is returned by [Get] when no item matches the
	// (service, account) attributes.
	ErrNotFound = errors.New("secretservice: item not found")
)

// backend is the seam between the OS-independent logic below and the D-Bus
// implementation. On Linux it is a live connection to the daemon
// (backend_linux.go); off Linux openBackend always fails with [ErrUnavailable]
// (backend_other.go). Tests swap openBackend for a fake to drive every branch
// of the logic without a live daemon.
type backend interface {
	set(service, account string, secret []byte) error
	get(service, account string) ([]byte, error)
	delete(service, account string) error
	close() error
}

// openBackend dials the Secret Service and returns a ready backend, or
// [ErrUnavailable] when none can be reached. It is assigned in an init().
var openBackend func() (backend, error)

// Set stores secret under the item identified by the attributes
// {service, account}, replacing any existing value. It returns [ErrUnavailable]
// when no Secret Service is reachable.
func Set(service, account string, secret []byte) error {
	b, err := openBackend()
	if err != nil {
		return err
	}
	defer b.close()
	return b.set(service, account, secret)
}

// Get returns the secret stored under {service, account}. It returns
// [ErrNotFound] when no such item exists and [ErrUnavailable] when no Secret
// Service is reachable.
func Get(service, account string) ([]byte, error) {
	b, err := openBackend()
	if err != nil {
		return nil, err
	}
	defer b.close()
	return b.get(service, account)
}

// Delete removes the item identified by {service, account}. Deleting an absent
// item is not an error. It returns [ErrUnavailable] when no Secret Service is
// reachable.
func Delete(service, account string) error {
	b, err := openBackend()
	if err != nil {
		return err
	}
	defer b.close()
	return b.delete(service, account)
}

// Available reports whether a Secret Service daemon can be reached (a session
// bus exists, a daemon owns org.freedesktop.secrets, and a plain session
// opens). It never blocks on a prompt and writes nothing.
func Available() bool {
	b, err := openBackend()
	if err != nil {
		return false
	}
	_ = b.close()
	return true
}
