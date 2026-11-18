package secretservice

import (
	"bytes"
	"errors"
	"testing"
)

// fakeBackend is an in-memory backend implementing the backend interface, used
// to drive every branch of the OS-independent logic without a live daemon.
type fakeBackend struct {
	store    map[string][]byte
	setErr   error
	getErr   error
	delErr   error
	closed   bool
	closeErr error
}

func key(service, account string) string { return service + "\x00" + account }

func (f *fakeBackend) set(service, account string, secret []byte) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.store[key(service, account)] = append([]byte(nil), secret...)
	return nil
}

func (f *fakeBackend) get(service, account string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.store[key(service, account)]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (f *fakeBackend) getAttrs(attrs map[string]string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if len(attrs) == 1 && attrs["Title"] == "two" {
		return nil, ErrAmbiguous
	}
	if attrs["Title"] == "Yubikey PIN" {
		return []byte("246810"), nil
	}
	return nil, ErrNotFound
}

func (f *fakeBackend) delete(service, account string) error {
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.store, key(service, account))
	return nil
}

func (f *fakeBackend) close() error { f.closed = true; return f.closeErr }

// withBackend points openBackend at a factory returning fb (or openErr) and
// restores the original seam afterwards.
func withBackend(t *testing.T, fb *fakeBackend, openErr error) {
	t.Helper()
	orig := openBackend
	t.Cleanup(func() { openBackend = orig })
	openBackend = func() (backend, error) {
		if openErr != nil {
			return nil, openErr
		}
		return fb, nil
	}
}

func newFake() *fakeBackend { return &fakeBackend{store: map[string][]byte{}} }

func TestRoundTripLogic(t *testing.T) {
	fb := newFake()
	withBackend(t, fb, nil)

	if err := Set("svc", "acct", []byte("hunter2")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := Get("svc", "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("hunter2")) {
		t.Fatalf("Get = %q, want hunter2", got)
	}
	if err := Delete("svc", "acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func TestUnavailableFromOpen(t *testing.T) {
	withBackend(t, nil, ErrUnavailable)

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
		t.Fatal("Available() = true, want false when the bus cannot be opened")
	}
}

func TestSetGetDeleteBackendErrors(t *testing.T) {
	sentinel := errors.New("boom")

	fb := newFake()
	fb.setErr = sentinel
	withBackend(t, fb, nil)
	if err := Set("s", "a", []byte("x")); !errors.Is(err, sentinel) {
		t.Fatalf("Set = %v, want sentinel", err)
	}

	fb = newFake()
	fb.getErr = sentinel
	withBackend(t, fb, nil)
	if _, err := Get("s", "a"); !errors.Is(err, sentinel) {
		t.Fatalf("Get = %v, want sentinel", err)
	}

	fb = newFake()
	fb.delErr = sentinel
	withBackend(t, fb, nil)
	if err := Delete("s", "a"); !errors.Is(err, sentinel) {
		t.Fatalf("Delete = %v, want sentinel", err)
	}
}

func TestGetNotFoundLogic(t *testing.T) {
	withBackend(t, newFake(), nil)
	if _, err := Get("absent", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}
}

func TestAvailableTrueClosesBackend(t *testing.T) {
	fb := newFake()
	withBackend(t, fb, nil)
	if !Available() {
		t.Fatal("Available() = false, want true")
	}
	if !fb.closed {
		t.Fatal("Available() must close the probe backend")
	}
}

func TestGetByAttributes(t *testing.T) {
	fb := newFake()
	withBackend(t, fb, nil)
	if got, err := GetByAttributes(map[string]string{"Title": "Yubikey PIN", "UserName": "me"}); err != nil || string(got) != "246810" {
		t.Fatalf("GetByAttributes = %q, %v", got, err)
	}
	if !fb.closed {
		t.Error("the backend must be closed")
	}
	if _, err := GetByAttributes(map[string]string{"Title": "none"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("no match: %v", err)
	}
	if _, err := GetByAttributes(map[string]string{"Title": "two"}); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("several: %v", err)
	}
	fb.getErr = errors.New("boom")
	if _, err := GetByAttributes(map[string]string{"a": "b"}); err == nil {
		t.Error("backend error")
	}
	// An empty set would match every item: refused before the bus is opened.
	called := false
	orig := openBackend
	t.Cleanup(func() { openBackend = orig })
	openBackend = func() (backend, error) { called = true; return fb, nil }
	if _, err := GetByAttributes(nil); !errors.Is(err, ErrNoAttributes) || called {
		t.Errorf("nil: %v called=%v", err, called)
	}
	big := map[string]string{}
	for i := 0; i <= MaxAttributes; i++ {
		big[string(rune('a'+i%26))+string(rune('A'+i/26))] = "x"
	}
	if _, err := GetByAttributes(big); !errors.Is(err, ErrNoAttributes) || called {
		t.Errorf("oversized: %v", err)
	}
	withBackend(t, nil, ErrUnavailable)
	if _, err := GetByAttributes(map[string]string{"a": "b"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("unavailable: %v", err)
	}
}

func TestSentinelsDistinct(t *testing.T) {
	if errors.Is(ErrNotFound, ErrUnavailable) || errors.Is(ErrUnavailable, ErrNotFound) {
		t.Fatal("ErrNotFound and ErrUnavailable must be distinct sentinels")
	}
}
