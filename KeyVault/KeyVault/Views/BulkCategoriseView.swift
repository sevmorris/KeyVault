import SwiftUI

/// Files every note in one pass.
///
/// Exists because the alternative is opening, editing and saving 24 notes
/// individually to set one field each. Categorising is a job you do once, when
/// you decide on a scheme, and then rarely — which is exactly the shape that
/// deserves its own screen rather than being buried in the per-note editor.
///
/// Nothing is written until Save. Edits accumulate in `assignments`, so
/// abandoning the sheet changes nothing, and only the notes whose category
/// actually differs are written back.
struct BulkCategoriseView: View {
    @Bindable var viewModel: KeyVaultViewModel
    @Environment(\.dismiss) private var dismiss

    /// id -> category. Seeded from what is already stored.
    @State private var assignments: [UUID: String] = [:]
    @State private var newCategory = ""
    /// Names invented in this sitting. Held apart from `assignments` so adding
    /// one makes it pickable without filing anything under it.
    @State private var customCategories: [String] = []
    @State private var saving = false

    private var notes: [EncryptionKey] {
        // Split rather than chained: as one expression the sort closure pushed
        // the type checker past its budget and the file stopped compiling.
        let onlyNotes: [EncryptionKey] = viewModel.allKeys.filter { $0.type == .note }
        return onlyNotes.sorted { (a: EncryptionKey, b: EncryptionKey) -> Bool in
            a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }

    /// Categories already stored, plus any typed during this sitting, so a name
    /// invented for the first note is immediately pickable for the rest.
    private var availableCategories: [String] {
        let typed = assignments.values.map { $0.trimmingCharacters(in: .whitespaces) }
        let all = Set(SecretStore.knownCategories() + typed + customCategories)
            .filter { !$0.isEmpty }
        return all.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    private var changedCount: Int {
        notes.reduce(into: 0) { count, note in
            let now = (assignments[note.id] ?? "").trimmingCharacters(in: .whitespaces)
            let before = (note.category ?? "").trimmingCharacters(in: .whitespaces)
            if now != before { count += 1 }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header

            List {
                ForEach(notes) { note in
                    HStack {
                        Text(note.name)
                            .lineLimit(1)
                        Spacer(minLength: 12)
                        Picker("", selection: binding(for: note)) {
                            Text("—").tag("")
                            ForEach(availableCategories, id: \.self) { category in
                                Text(category).tag(category)
                            }
                        }
                        .labelsHidden()
                        .frame(width: 200)
                    }
                }
            }
            .listStyle(.inset)

            Divider()
            footer
        }
        .frame(width: 620, height: 560)
        .onAppear {
            for note in notes {
                assignments[note.id] = note.category ?? ""
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Organise Notes").font(.headline)
            Text("Set a category for each note. Add one below, then pick it for as many notes as you like. Nothing is saved until you press Save.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
    }

    private var footer: some View {
        HStack {
            TextField("New category…", text: $newCategory)
                .textFieldStyle(.roundedBorder)
                .frame(width: 200)
                .onSubmit(addCategory)
            Button("Add", action: addCategory)
                .disabled(newCategory.trimmingCharacters(in: .whitespaces).isEmpty)

            Spacer()

            Text(changedCount == 0 ? "No changes" : "\(changedCount) to update")
                .font(.callout)
                .foregroundStyle(.secondary)
            Button("Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button("Save") { save() }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || changedCount == 0)
        }
        .padding()
    }

    private func binding(for note: EncryptionKey) -> Binding<String> {
        Binding(
            get: { assignments[note.id] ?? "" },
            set: { assignments[note.id] = $0 }
        )
    }

    /// Adding a category only makes it selectable. It is not attached to
    /// anything until you pick it, so a typo costs a re-type and nothing else.
    private func addCategory() {
        let trimmed = newCategory.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              !customCategories.contains(trimmed) else { newCategory = ""; return }
        customCategories.append(trimmed)
        newCategory = ""
    }

    private func save() {
        saving = true
        Task {
            await viewModel.applyCategories(assignments)
            saving = false
            dismiss()
        }
    }
}
