import SwiftUI

/// The colour of the tube.
enum PhosphorStyle: String, CaseIterable, Identifiable {
    case green
    case amber
    case plain

    var id: String { rawValue }

    var label: String {
        switch self {
        case .green: return "Phosphor Green"
        case .amber: return "Phosphor Amber"
        case .plain: return "Plain"
        }
    }

    /// P1 green and P3 amber, near enough. Bright, and brighter than a text
    /// colour has any business being, because a phosphor dot emits light
    /// rather than reflecting it.
    var tint: Color {
        switch self {
        case .green: return Color(red: 0.44, green: 1.00, blue: 0.56)
        case .amber: return Color(red: 1.00, green: 0.72, blue: 0.24)
        case .plain: return .primary
        }
    }

    /// Not black. An unlit tube still has a colour, and a pure black ground
    /// makes the glow look pasted on rather than emitted.
    var ground: Color {
        switch self {
        case .green: return Color(red: 0.02, green: 0.055, blue: 0.03)
        case .amber: return Color(red: 0.055, green: 0.032, blue: 0.012)
        case .plain: return Color(nsColor: .textBackgroundColor)
        }
    }
}

/// Dresses a block of monospaced output as a phosphor screen: glowing text on
/// a dark tube, scanlines, a slow refresh sweep, and a bezel.
///
/// Everything here is decoration over unmodified content — the text inside is
/// the exact string it always was, still selectable and still copyable. A
/// secret you cannot proof-read is worse than a boring one, so nothing
/// transforms, truncates or restyles the characters themselves.
struct PhosphorScreen<Content: View>: View {
    let style: PhosphorStyle
    @ViewBuilder var content: Content

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var sweepDown = false

    private let corner: CGFloat = 8

    var body: some View {
        if style == .plain {
            content
                .background(style.ground)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.3))
                )
        } else {
            content
                .foregroundStyle(style.tint)
                // Two shadows rather than one: a tight halo for the bloom
                // around each stroke, and a wide dim one for the light the
                // tube throws onto its own glass.
                .shadow(color: style.tint.opacity(0.55), radius: 3)
                .shadow(color: style.tint.opacity(0.22), radius: 10)
                .background { tube }
                .overlay { scanlines }
                .overlay { if !reduceMotion { sweep } }
                .clipShape(RoundedRectangle(cornerRadius: corner))
                .overlay { bezel }
        }
    }

    private var tube: some View {
        style.ground.overlay {
            // Brightest in the middle, falling away at the corners, the way a
            // deflection tube does.
            RadialGradient(
                colors: [style.tint.opacity(0.07), .clear, .black.opacity(0.45)],
                center: .center,
                startRadius: 8,
                endRadius: 320
            )
        }
    }

    /// Drawn rather than tiled: a Canvas costs one pass and needs no image
    /// asset, and the spacing stays honest at any size.
    private var scanlines: some View {
        Canvas { context, size in
            for y in stride(from: 0, to: size.height, by: 3) {
                context.fill(
                    Path(CGRect(x: 0, y: y, width: size.width, height: 1)),
                    with: .color(.black.opacity(0.32))
                )
            }
        }
        .allowsHitTesting(false)
    }

    /// The slow bright band of a tube refreshing. Driven by a repeating
    /// SwiftUI animation, not a TimelineView, so Core Animation runs it off
    /// the main thread instead of redrawing this view sixty times a second.
    private var sweep: some View {
        GeometryReader { geo in
            LinearGradient(
                colors: [.clear, style.tint.opacity(0.06), .clear],
                startPoint: .top,
                endPoint: .bottom
            )
            .frame(height: 90)
            .offset(y: sweepDown ? geo.size.height : -90)
            .onAppear {
                withAnimation(.linear(duration: 6.5).repeatForever(autoreverses: false)) {
                    sweepDown = true
                }
            }
        }
        .allowsHitTesting(false)
    }

    private var bezel: some View {
        RoundedRectangle(cornerRadius: corner)
            .strokeBorder(style.tint.opacity(0.22), lineWidth: 1)
            .shadow(color: .black.opacity(0.6), radius: 6)
            .allowsHitTesting(false)
    }
}

/// The block cursor sitting under the output, blinking at roughly the rate a
/// terminal did.
struct PhosphorCursor: View {
    let style: PhosphorStyle

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private static let period: TimeInterval = 0.53

    var body: some View {
        if style == .plain {
            EmptyView()
        } else if reduceMotion {
            block.opacity(0.85)
        } else {
            TimelineView(.periodic(from: .now, by: Self.period)) { context in
                block.opacity(lit(at: context.date) ? 0.95 : 0.06)
            }
        }
    }

    private var block: some View {
        RoundedRectangle(cornerRadius: 1)
            .fill(style.tint)
            .frame(width: 9, height: 16)
            .shadow(color: style.tint.opacity(0.7), radius: 4)
    }

    private func lit(at date: Date) -> Bool {
        Int(date.timeIntervalSinceReferenceDate / Self.period) % 2 == 0
    }
}
