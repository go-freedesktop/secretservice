# secretservice — pure-Go freedesktop Secret Service client

`github.com/go-freedesktop/secretservice` is a pure-Go, **CGO=0** client for the
freedesktop [Secret Service API](https://specifications.freedesktop.org/secret-service/)
(`org.freedesktop.Secret.Service`) over D-Bus, using `github.com/godbus/dbus/v5`.
It talks to GNOME Keyring, KWallet, or any conforming secret daemon.

Scope: open a session, unlock the default collection, and create / lookup /
delete secret items keyed by attributes (service + account) — the surface the
`go-keyring` façade needs on Linux. No cgo, no CLI `exec`.

## License
BSD-3-Clause — copyright the go-freedesktop authors.
