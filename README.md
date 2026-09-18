# KeyVault

<p align="center">
  <strong>Key manager, and an encrypted store for secrets and files</strong>
  <br />
  <strong>Version:</strong> 1.9.2
  <br />
  <a href="https://github.com/sevmorris/KeyVault/releases/latest/download/KeyVault-v1.9.2.dmg"><strong>Download Latest (DMG)</strong></a>
  ·
  <a href="https://sevmorris.github.io/KeyVault/manual/">Manual</a>
  ·
  <a href="https://github.com/sevmorris/KeyVault/releases">Releases</a>
</p>

A native macOS app for managing SSH, GPG, and Age keys, and for storing secrets
and files under a master passphrase.

## What it is

Two different jobs behind one window, and the distinction matters:

- **SSH, GPG, Age** — a *manager* over key material that already exists on disk
  or in the GPG keyring. KeyVault finds it, shows it, and can generate more. It
  is not the only copy of any of it.
- **Notes, API Keys and Files** — a *store*. Notes and API keys live in the
  Keychain because KeyVault put them there; files live encrypted in KeyVault's
  own folder. For a note, or a file whose original is gone, nothing else holds a
  copy.

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

Stored files are in the same archive, each one's contents in base64 beside the
name it had, and they come back out without KeyVault too:

```bash
jq -r '.items[] | select(.fileName == "export.csv") | .secret' \
  vault.json | base64 --decode > export.csv
```

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

Files are not in the Keychain, which is one database every app on the Mac shares
and is made for secrets measured in bytes. Each stored file is a single
encrypted file in `~/Library/Application Support/KeyVault/Files`, sealed with
AES-256-GCM under the key the master passphrase derives, with its name and notes
sealed inside it — self-describing, like a Keychain item, and with nothing about
it readable without the passphrase. Files are stored only once a passphrase is
set, and the encrypted export is how they move to another Mac: the folder on its
own is useless without the salt the Keychain holds.

## License

Copyright © 2026 Seven Morris.
Distributed under the [MIT License](LICENSE).
