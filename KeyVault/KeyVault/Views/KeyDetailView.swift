import SwiftUI

struct KeyDetailView: View {
    @Bindable var viewModel: KeyVaultViewModel
    let key: EncryptionKey
    @State private var showDeleteConfirm = false
    @State private var showEditNote = false
    @State private var deleteError: String?
    @State private var copied = false

    /// Held only while revealed, and dropped the moment the pane changes key,
    /// so at most one secret is in memory at a time rather than every one you
    /// browsed past staying there for the life of the window.
    @State private var revealedSecret: String?
    @State private var secretError: String?
    @State private var copiedSecret = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                Divider()
                metadata
                if SecretStore.ownedTypes.contains(key.type) {
                    Divider()
                    secretSection
                }
                if let pubKey = key.publicKey, !pubKey.isEmpty {
                    Divider()
                    publicKeySection(pubKey)
                }
                Spacer()
                deleteSection
            }
            .padding(20)
        }
        .navigationTitle(key.name)
        .onAppear { revealIfUnlocked() }
        // Selecting a different item must not leave the previous secret on
        // screen, or in memory. Cleared here rather than in a .task keyed on
        // the id, which would let the old value render once in the new item's
        // pane before it was replaced.
        .onChange(of: key.id) {
            forgetSecret()
            revealIfUnlocked()
        }
        .sheet(isPresented: $showEditNote) {
            // A saved edit replaces the stored secret, so anything revealed
            // before it is now stale. Re-read rather than leave the old value
            // sitting on screen looking current.
            forgetSecret()
            revealIfUnlocked()
        } content: {
            AddNoteView(viewModel: viewModel, editing: key)
        }
        .alert("Delete Key?", isPresented: $showDeleteConfirm) {
            Button("Delete", role: .destructive) {
                Task {
                    do {
                        try await viewModel.deleteKey(key)
                    } catch {
                        deleteError = error.localizedDescription
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(deleteMessage)
        }
        .alert("Delete Failed", isPresented: .init(
            get: { deleteError != nil },
            set: { if !$0 { deleteError = nil } }
        )) {
            Button("OK") { deleteError = nil }
        } message: {
            Text(deleteError ?? "")
        }
    }

    private var screen: PhosphorStyle { viewModel.settings.screenStyle }

    // MARK: - Secret

    /// Shown once the vault is open, and hidden whenever it is not.
    ///
    /// It used to take a click per item, on the reasoning that a vault which
    /// shows its contents to anyone who clicks a row is a vault in name only.
    /// But the passphrase already is that click: past the door, asking again
    /// per note was friction with nothing behind it. Hide is still there for
    /// the moment someone is standing behind you.
    @ViewBuilder private var secretSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Secret")
                    .font(.headline)
                Spacer()
                if revealedSecret == nil {
                    Button("Reveal") { loadSecret() }
                } else {
                    Button("Hide") { revealedSecret = nil }
                    Button(copiedSecret ? "Copied" : "Copy") { copySecret() }
                        .disabled(copiedSecret)
                }
            }

            // One screen in every state, so revealing or hiding does not make
            // the pane jump — and so there is something to look at either way.
            PhosphorScreen(style: screen) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 3) {
                        if let secret = revealedSecret {
                            Text(secret)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                        } else if let secretError {
                            Text(secretError)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(screen == .plain ? Color.red : screen.tint)
                        } else {
                            Text("— hidden —")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(screen == .plain ? Color.secondary : screen.tint)
                                .opacity(0.65)
                        }
                        PhosphorCursor(style: screen)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                }
                .frame(maxHeight: 220)
            }
        }
    }

    /// Read the secret for the item now on screen, if there is one to read.
    /// Nothing is revealed while the vault is locked — the detail pane is not
    /// reachable in that state, and the value could not be decrypted anyway.
    private func revealIfUnlocked() {
        guard SecretStore.ownedTypes.contains(key.type), !viewModel.vaultIsLocked else { return }
        loadSecret()
    }

    private func forgetSecret() {
        revealedSecret = nil
        secretError = nil
        copiedSecret = false
    }

    private func loadSecret() {
        secretError = nil
        do {
            revealedSecret = try SecretStore.loadSecret(for: key.id)
        } catch {
            secretError = "Could not read this secret from the Keychain: \(error.localizedDescription)"
        }
    }

    private func copySecret() {
        guard let secret = revealedSecret else { return }
        let pb = NSPasteboard.general
        // .currentHostOnly keeps this off Universal Clipboard. A plain
        // clearContents() leaves the secret eligible for Handoff, which would
        // put it on every other Mac, iPhone and iPad signed into the account —
        // rather more copies than "copy" implies.
        pb.prepareForNewContents(with: .currentHostOnly)
        // Tells clipboard managers not to archive this. Not enforceable — a
        // manager can ignore it — but the ones worth using honour it, and
        // silently seeding a searchable history with vault contents is worse
        // than not offering copy at all.
        pb.setString("", forType: .init("org.nspasteboard.ConcealedType"))
        pb.setString(secret, forType: .string)

        copiedSecret = true
        Task {
            // The label reverts on a human timescale. Tying it to the clipboard
            // clear below meant "Copied" stuck for 45 seconds, and since the
            // button is disabled while it shows, so did the button.
            try? await Task.sleep(for: .seconds(2))
            copiedSecret = false

            // Then clear the clipboard, but only if it still holds this secret
            // — stomping on whatever the user copied since would be its own
            // small betrayal.
            try? await Task.sleep(for: .seconds(43))
            if NSPasteboard.general.string(forType: .string) == secret {
                NSPasteboard.general.clearContents()
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: key.type.systemImage)
                .font(.system(size: 32))
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name)
                    .font(.title2)
                    .fontWeight(.semibold)
                Text(key.type.rawValue)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            // Notes are the only type KeyVault stores outright, so they are
            // the only one it can rewrite. SSH and GPG entries are a view onto
            // files and a keyring that their own tools own; Age is dormant.
            if key.type == .note {
                Button {
                    showEditNote = true
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help("Edit this note")
            }
        }
    }

    private var metadata: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let algorithm = key.algorithm {
                DetailRow(label: "Algorithm", value: algorithm)
            }
            if let fingerprint = key.fingerprint {
                HStack {
                    DetailRow(label: "Fingerprint", value: fingerprint)
                    Button {
                        viewModel.copyFingerprint(key)
                        flashCopied()
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.plain)
                    .help("Copy Fingerprint")
                }
            }
            if let keyID = key.keyID {
                DetailRow(label: "Key ID", value: keyID)
            }
            if let path = key.path {
                DetailRow(label: "Path", value: path)
            }
            if let service = key.service {
                DetailRow(label: "Service", value: service)
            }
            if let created = key.createdDate {
                DetailRow(label: "Created", value: created.formatted(date: .abbreviated, time: .omitted))
            }
            if let expiry = key.expiryDate {
                DetailRow(label: "Expires", value: expiry.formatted(date: .abbreviated, time: .omitted))
                    .foregroundStyle(expiry < Date() ? .red : .primary)
            }
            if key.hasPrivateKey {
                DetailRow(label: "Private Key", value: "Present")
            }
            if let notes = key.notes, !notes.isEmpty {
                DetailRow(label: "Notes", value: notes)
            }
        }
    }

    private func publicKeySection(_ pubKey: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Public Key")
                    .font(.headline)
                Spacer()
                Button {
                    viewModel.copyPublicKey(key)
                    flashCopied()
                } label: {
                    Label(copied ? "Copied!" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .animation(.easeInOut(duration: 0.2), value: copied)
            }
            PhosphorScreen(style: screen) {
                ScrollView(.horizontal, showsIndicators: false) {
                    Text(pubKey)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(10)
                }
            }
        }
    }

    private var deleteSection: some View {
        HStack {
            Spacer()
            Button(role: .destructive) {
                showDeleteConfirm = true
            } label: {
                Label("Delete Key", systemImage: "trash")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .tint(.red)
        }
    }

    private var deleteMessage: String {
        switch key.type {
        case .ssh:
            return "This will permanently delete the key file(s) from ~/.ssh/. This cannot be undone."
        case .gpg:
            return "This will remove the key from your GPG keyring. This cannot be undone."
        case .age:
            return "Age key deletion is not supported. Please edit the key file manually."
        case .api:
            return "This will delete the API key from the Keychain. This cannot be undone."
        case .note:
            // Stated plainly because notes are the one type with no copy
            // anywhere else: SSH/GPG/Age index files that still exist on disk,
            // and an API key can usually be re-issued. This is the real thing.
            return """
                This will permanently delete this note from the Keychain. \
                Nothing else holds a copy of it, and it cannot be undone.

                If you have not exported an encrypted backup, cancel and do \
                that first.
                """
        }
    }

    private func flashCopied() {
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            copied = false
        }
    }
}

private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Text(label + ":")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(.subheadline)
                .textSelection(.enabled)
        }
    }
}
