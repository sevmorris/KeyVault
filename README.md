# KeyVault

<p align="center">
  <strong>Key manager and Keychain-backed secret store</strong>
  <br />
  <strong>Version:</strong> 1.5.0
  <br />
  <a href="https://github.com/sevmorris/KeyVault/releases/latest/download/KeyVault-v1.5.0.dmg"><strong>Download Latest (DMG)</strong></a>
  ·
  <a href="https://sevmorris.github.io/KeyVault/manual/">Manual</a>
  ·
  <a href="https://github.com/sevmorris/KeyVault/releases">Releases</a>
</p>

A native macOS app for managing SSH, GPG, and Age keys, and for storing secrets
in the macOS Keychain.

## What it is

Two different jobs behind one window, and the distinction matters:

- **SSH, GPG, Age** — a *manager* over key material that already exists on disk
  or in the GPG keyring. KeyVault finds it, shows it, and can generate more. It
  is not the only copy of any of it.
- **API Keys and Notes** — a *store*. These live in the Keychain because
  KeyVault put them there, and for a Note, nothing else holds a copy.

That second category is the one to be careful with, and everything below is
about it.

## Backup

Notes are stored in the macOS Keychain, which is encrypted at rest and tied to
your login. That protects them from another person using the Mac. It does not
protect them from software: a process running with your privileges can read
Keychain items, so a note is only as private as the code you run.

Nor does any of it protect them from a dead Mac — Keychain items are local to
one machine.

So: **export, and then read the export back.**

Backup & Restore (the toolbar button) writes a passphrase-encrypted archive:
OpenPGP, AES-256, ASCII-armored. Two properties are deliberate.

It is **plain text**, so it survives a password manager field, an email to
yourself, or a printer — none of which a binary blob does reliably.

It is **readable without KeyVault**:

```bash
gpg --decrypt keyvault-export.asc > vault.json
```

Any GnuPG on any platform will open it. Inside is a JSON document with each
item's value in the clear. That is the exit: this app is not a place your
secrets can get stuck.

The passphrase is stored nowhere and cannot be reset. Lose it and the archive is
unreadable by you as well as by everyone else.

### The rule

Restore is idempotent — it adds what is missing and updates what already exists
— so rehearsing costs nothing. Do it. **Nothing should exist only in KeyVault
until you have restored an archive somewhere else and read the value back.** An
untested backup is not a backup.

The [manual](https://sevmorris.github.io/KeyVault/manual/#backup) covers this in
more detail, including what the archive contains and how to read it back.

## Requirements

- macOS 15.0+
- `gnupg` for export and import — `brew install gnupg`
- `ssh-keygen` (ships with macOS) for SSH; `gpg` for GPG keys
- `age` is optional — Age key generation is offered only when `age-keygen` is
  installed (`brew install age`), and says so plainly when it is not
- App sandbox is disabled: it shells out to these tools

## Install

```bash
./build.sh
```

Builds Release and installs to `/Applications`. Releases are signed and
notarized; `release.sh <version>` cuts one.

## Storage

Items are `kSecClassGenericPassword` entries under the service
`io.github.sevmorris.KeyVault`, and each one is **self-describing** — the name,
type, and metadata live in the Keychain item's own attributes rather than in a
side table. An earlier design kept the index in UserDefaults, which meant losing
that plist turned every secret into an anonymous blob keyed by a UUID nothing
referenced. Items written under that scheme are migrated on first launch.

## License

Copyright © 2026 Seven Morris.
Distributed under the [MIT License](LICENSE).
