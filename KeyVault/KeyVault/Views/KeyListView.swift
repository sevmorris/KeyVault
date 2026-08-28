import SwiftUI

struct KeyListView: View {
    @Bindable var viewModel: KeyVaultViewModel

    var body: some View {
        Group {
            if viewModel.isLoading {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if viewModel.filteredKeys.isEmpty {
                EmptyStateView(type: viewModel.selectedType)
            } else {
                List(viewModel.filteredKeys, selection: $viewModel.selectedKeyID) { key in
                    KeyRowView(key: key)
                        .tag(key.id)
                }
                .listStyle(.inset)
            }
        }
        .toolbar {
            ToolbarItemGroup {
                if viewModel.selectedType == .api || viewModel.selectedType == nil {
                    Button {
                        viewModel.showAddAPIKeySheet = true
                    } label: {
                        Label("Add API Key", systemImage: "plus")
                    }
                    .help("Add API Key")
                }

                Button {
                    viewModel.showImportSheet = true
                } label: {
                    Image(systemName: "square.and.arrow.down")
                }
                .help("Import Key")

                Button {
                    viewModel.showGenerateSheet = true
                } label: {
                    Image(systemName: "wand.and.stars")
                }
                .help("Generate Key")

                Button {
                    Task { await viewModel.reload() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh")
            }
        }
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
        if let algo = key.algorithm { return algo }
        if let fp = key.fingerprint { return String(fp.prefix(30)) }
        if let service = key.service { return service }
        return nil
    }
}
