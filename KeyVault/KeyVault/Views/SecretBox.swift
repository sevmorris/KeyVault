import SwiftUI

/// The box a revealed secret, a stored file's contents or a public key is
/// shown in: ordinary text on the text background, inside a rounded border.
///
/// It fills whatever it is given, so a caller decides the size — the secret
/// pane gives it everything left over, and a public key gets a strip. That is
/// the part of the old phosphor screen worth keeping; the tube itself, with
/// its glow, scanlines and cursor, is gone.
struct SecretBox<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(10)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.secondary.opacity(0.3))
            )
    }
}
