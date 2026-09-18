import SwiftUI

struct KeyListView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @State private var isDropTargeted = false
    /// The note whose New Category… was chosen, while the name is typed.
    @State private var filingNote: EncryptionKey?
    @State private var newCategoryName = ""

    var body: some View {
        Group {
            if viewModel.isLoading {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if viewModel.filteredKeys.isEmpty {
                EmptyStateView(type: viewModel.selectedType)
            } else {
                List(selection: $viewModel.selectedKeyID) {
                    // Notes group under their category; everything else stays a
                    // flat list, because only notes have one. A vault with no
                    // categories set yet renders as a single unlabelled group,
                    // which is exactly the old appearance.
                    if viewModel.selectedType == .note && viewModel.hasAnyCategory {
                        ForEach(viewModel.groupedNotes, id: \.name) { group in
                            Section {
                                if viewModel.isCategoryExpanded(group.name) {
                                    ForEach(group.keys) { key in
                                        row(key)
                                    }
                                }
                            } header: {
                                CategoryHeader(
                                    name: group.name,
                                    count: group.keys.count,
                                    isExpanded: viewModel.isCategoryExpanded(group.name)
                                ) {
                                    viewModel.toggleCategory(group.name)
                                }
                            }
                        }
                    } else {
                        ForEach(viewModel.filteredKeys) { key in
                            row(key)
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        // Dropping a file on the Files list is the quickest way to store one:
        // it opens the Add File sheet with the file already chosen, so the
        // name, the notes and the Trash toggle are still asked about.
        .dropDestination(for: URL.self) { urls, _ in
            guard viewModel.selectedType == .file, let url = urls.first else { return false }
            viewModel.droppedFileURL = url
            viewModel.showAddFileSheet = true
            return true
        } isTargeted: { targeted in
            isDropTargeted = targeted && viewModel.selectedType == .file
        }
        .overlay {
            if isDropTargeted {
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(Color.accentColor, lineWidth: 2)
                    .padding(4)
                    .allowsHitTesting(false)
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { addBar }
        .alert("New Category", isPresented: Binding(
            get: { filingNote != nil },
            set: { if !$0 { filingNote = nil } }
        )) {
            TextField("Category", text: $newCategoryName)
            Button("File") {
                let name = newCategoryName.trimmingCharacters(in: .whitespaces)
                if let note = filingNote, !name.isEmpty {
                    Task { await viewModel.setCategory(name, for: note) }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("File “\(filingNote?.name ?? "")” under a new category.")
        }
    }

    private func row(_ key: EncryptionKey) -> some View {
        KeyRowView(key: key)
            .contextMenu {
                if key.type == .note { categoryMenu(for: key) }
            }
            .tag(key.id)
    }

    /// Control-click on a note files it — under a category already in use,
    /// under a new one, or under none — and writes it straight away. Only
    /// notes have categories. Organise Notes is still the way to file many.
    private func categoryMenu(for key: EncryptionKey) -> some View {
        let current = key.category?.trimmingCharacters(in: .whitespaces) ?? ""
        return Menu("Category") {
            // Toggles, not an inline Picker: the Picker brings separators of
            // its own, which put a line above the first category and a double
            // one above New Category….
            ForEach(viewModel.noteCategories, id: \.self) { category in
                Toggle(category, isOn: filing(key, under: category, current: current))
            }
            Toggle("None", isOn: filing(key, under: "", current: current))

            Divider()

            Button("New Category…") {
                newCategoryName = ""
                filingNote = key
            }
        }
    }

    /// Checked where the note is filed now. Choosing another files it there;
    /// choosing the checked one again does nothing, as in any radio group.
    private func filing(_ key: EncryptionKey, under category: String, current: String) -> Binding<Bool> {
        Binding(
            get: { current == category },
            set: { on in
                guard on, current != category else { return }
                Task { await viewModel.setCategory(category.isEmpty ? nil : category, for: key) }
            }
        )
    }

    /// The +/- strip under a list is the Mac idiom for "this list is something
    /// you add to" — Contacts, System Settings and Finder sidebars all use it.
    /// The toolbar buttons stay, but they are discoverable only if you go
    /// looking; this is where the eye already is when the list is empty.
    ///
    /// No minus. Deleting goes through the detail pane's confirmation, and for
    /// a Note that confirmation is the only thing between a click and something
    /// nothing else holds a copy of.
    @ViewBuilder private var addBar: some View {
        HStack(spacing: 0) {
            switch viewModel.selectedType {
            case .note:
                addButton("Add Note") { viewModel.showAddNoteSheet = true }
            case .api:
                addButton("Add API Key") { viewModel.showAddAPIKeySheet = true }
            case .file:
                addButton("Add File") { viewModel.showAddFileSheet = true }
            case .none:
                // Nothing is filtered, so the button has to ask which.
                Menu {
                    Button("New Note") { viewModel.showAddNoteSheet = true }
                    Button("New API Key") { viewModel.showAddAPIKeySheet = true }
                    Button("Add File…") { viewModel.showAddFileSheet = true }
                } label: {
                    Image(systemName: "plus")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .frame(width: 28, height: 22)
                .help("Add")
            case .ssh, .gpg, .age:
                // These are generated or imported, never typed in.
                addButton("Generate Key") { viewModel.showGenerateSheet = true }
            }
            Spacer()
        }
        .padding(.horizontal, 4)
        .frame(height: 26)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    private func addButton(_ help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: "plus")
                .frame(width: 28, height: 22)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(help)
    }

}

/// A section header that folds its category away, the way the sidebar's own
/// sections do.
///
/// Drawn rather than delegated to `Section(isExpanded:)` so that it behaves
/// the same in this list's `.inset` style as it would in a sidebar, and so the
/// header can carry the count — which is the thing you want to see once a
/// category is closed.
private struct CategoryHeader: View {
    let name: String
    let count: Int
    let isExpanded: Bool
    let toggle: () -> Void

    var body: some View {
        Button {
            withAnimation(.snappy(duration: 0.18)) { toggle() }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "chevron.right")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(isExpanded ? 90 : 0))
                    .frame(width: 10)
                Text(name)
                Spacer()
                Text("\(count)")
                    .foregroundStyle(.tertiary)
                    .monospacedDigit()
            }
            // The whole width is the hit target, not just the words: a header
            // you have to aim at is a header you stop using.
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(isExpanded ? "Hide \(name)" : "Show \(name)")
    }
}

private struct KeyRowView: View {
    let key: EncryptionKey

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: key.type.systemImage)
                .foregroundStyle(.secondary)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(key.name)
                    .font(.body)
                    .lineLimit(1)

                if let sub = subtitle {
                    Text(sub)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        // A file's line ends in its size, which is the part a
                        // narrow column would otherwise cut off first.
                        .truncationMode(key.type == .file ? .middle : .tail)
                }
            }

            Spacer()

            if key.hasPrivateKey {
                Image(systemName: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 2)
    }

    private var subtitle: String? {
        // The size, and the name the file had when it differs from the one
        // it is listed under.
        if let size = key.fileSize {
            let bytes = size.formatted(.byteCount(style: .file))
            guard let fileName = key.fileName, fileName != key.name else { return bytes }
            return "\(fileName) · \(bytes)"
        }
        if let algo = key.algorithm { return algo }
        if let fp = key.fingerprint { return String(fp.prefix(30)) }
        if let service = key.service { return service }
        return nil
    }
}
