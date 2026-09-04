import SwiftUI

/// The colour of the tube.
///
/// A sibling of Magic Backup Machine's screen of the same name, deliberately
/// copied rather than shared: that one tints an NSTextView from AppKit and
/// insets its scroll view by hand, where this one draws ordinary SwiftUI text
/// and can glow it per glyph. The geometry is what the two have in common,
/// and it was worked out over there — see boxInset for why it is derived
/// rather than chosen.
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

/// The type the tube is set in.
///
/// A couple of points above the system sizes, and kept here rather than at the
/// call sites so the screens cannot drift apart. The glow is the reason: a
/// bloom softens the edge of every glyph, so monospaced 13 under one reads
/// smaller and fuzzier than the same face set plain. The extra points buy back
/// what the phosphor costs.
enum PhosphorType {
    static let body = Font.system(size: 15, design: .monospaced)
    static let caption = Font.system(size: 13, design: .monospaced)
}

/// The face of the tube: a rounded rectangle whose edges bow outward, the way
/// glass does over a deflection yoke.
///
/// The shape insets itself by the bow and then curves back out by the same
/// amount, so the widest point of each edge lands exactly on the rectangle it
/// was handed and the screen still fills its slot.
struct TubeFace: InsettableShape {
    /// Curvature as a fraction of the shorter side rather than a fixed number
    /// of points. A tube bows in proportion to its size: six points of bend
    /// reads as a curve on a small pane and as a straight edge on a window
    /// thirteen hundred points wide, which is exactly how this first shipped.
    /// Clamped at both ends so it stays sane either way.
    var bowFraction: CGFloat = 0.022
    var cornerFraction: CGFloat = 0.055
    var insetAmount: CGFloat = 0

    func bow(for size: CGSize) -> CGFloat {
        let minSide = min(size.width, size.height)
        let base = min(max(minSide * bowFraction, 5), 24)
        // Relax the curve as the shape gets extreme. A tube eleven times wider
        // than it is tall never existed, and bowing one reads as a lozenge
        // rather than glass — which is exactly what a one-line public key
        // looked like. Full bow up to 2:1, none past 4:1.
        let ratio = max(size.width, size.height) / max(minSide, 1)
        let slack = max(0, min(1, (4 - ratio) / 2))
        return base * slack
    }

    func corner(for size: CGSize) -> CGFloat {
        let minSide = min(size.width, size.height)
        let wanted = min(max(minSide * cornerFraction, 10), 70)
        // Never more than a sixth of the short side. The floor exists so a
        // small screen still reads as rounded, but on a wide, shallow strip —
        // a one-line public key, say — a 16-point radius at each corner of a
        // 96-point height turns the whole thing into a capsule.
        return min(wanted, minSide * 0.16)
    }

    /// How far a rectangular box has to sit from the edge to look like it
    /// belongs on the glass.
    ///
    /// Derived from the same bow and corner the path uses rather than picked
    /// by eye, because both scale with the pane: a fixed inset that looked
    /// generous on a small screen let the corner arc bite the first character
    /// on a large one. The log's scroll view is inset by this, so the text box
    /// lives inside the bezel rather than running under it.
    ///
    /// The same on every side. An earlier version solved the corner only for
    /// the first line of text, which left the vertical inset a third smaller
    /// than the horizontal — measured at 29 points against 52 — and margins
    /// that uneven read as a mistake rather than a bezel.
    func boxInset(for size: CGSize) -> CGFloat {
        // 0.29 ≈ 1 − 1/√2: how far a corner of that radius cuts into the
        // rectangle it is rounding, measured along the diagonal.
        bow(for: size) + corner(for: size) * 0.29 + 8
    }

    func path(in rect: CGRect) -> Path {
        let bow = bow(for: rect.size)
        let r = rect.insetBy(dx: bow + insetAmount, dy: bow + insetAmount)
        guard r.width > 0, r.height > 0 else { return Path() }
        let c = min(corner(for: rect.size), min(r.width, r.height) / 2)
        // A quadratic's midpoint sits half way to its control point, so the
        // control goes twice the bow out to deviate by exactly the bow.
        let reach = bow * 2

        var p = Path()
        p.move(to: CGPoint(x: r.minX + c, y: r.minY))
        p.addQuadCurve(to: CGPoint(x: r.maxX - c, y: r.minY),
                       control: CGPoint(x: r.midX, y: r.minY - reach))
        p.addQuadCurve(to: CGPoint(x: r.maxX, y: r.minY + c),
                       control: CGPoint(x: r.maxX, y: r.minY))
        p.addQuadCurve(to: CGPoint(x: r.maxX, y: r.maxY - c),
                       control: CGPoint(x: r.maxX + reach, y: r.midY))
        p.addQuadCurve(to: CGPoint(x: r.maxX - c, y: r.maxY),
                       control: CGPoint(x: r.maxX, y: r.maxY))
        p.addQuadCurve(to: CGPoint(x: r.minX + c, y: r.maxY),
                       control: CGPoint(x: r.midX, y: r.maxY + reach))
        p.addQuadCurve(to: CGPoint(x: r.minX, y: r.maxY - c),
                       control: CGPoint(x: r.minX, y: r.maxY))
        p.addQuadCurve(to: CGPoint(x: r.minX, y: r.minY + c),
                       control: CGPoint(x: r.minX - reach, y: r.midY))
        p.addQuadCurve(to: CGPoint(x: r.minX + c, y: r.minY),
                       control: CGPoint(x: r.minX, y: r.minY))
        p.closeSubpath()
        return p
    }

    func inset(by amount: CGFloat) -> some InsettableShape {
        var copy = self
        copy.insetAmount += amount
        return copy
    }
}

/// Dresses a block of monospaced output as a phosphor screen: a dark tube,
/// scanlines, a slow refresh sweep, and a bezel.
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

    private let face = TubeFace()

    var body: some View {
        if style == .plain {
            content
                .padding(12)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .background(style.ground)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.secondary.opacity(0.3))
                )
        } else {
            // A GeometryReader, so the screen fills whatever it is given and
            // insets its own content to clear the curve. Callers hand it text
            // and nothing else: they should not have to know the shape of the
            // glass to keep their words off it.
            GeometryReader { geo in
                content
                    .padding(face.boxInset(for: geo.size))
                    .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
                    .foregroundStyle(style.tint)
                    // Two shadows: a tight halo for the bloom around each
                    // stroke, and a wide dim one for the light the tube throws
                    // onto its own glass.
                    .shadow(color: style.tint.opacity(0.55), radius: 3)
                    .shadow(color: style.tint.opacity(0.22), radius: 10)
                    .background { tube }
                    .overlay { scanlines }
                    .overlay { if !reduceMotion { sweep } }
                    .overlay { glass }
                    .clipShape(face)
                    .overlay { bezel }
            }
        }
    }

    private var tube: some View {
        style.ground.overlay {
            // Brightest in the middle, falling away at the corners, the way a
            // deflection tube does.
            // Fractional radii, not absolute ones: a fixed 520-point falloff
            // put the black end of the gradient over almost the whole pane on
            // a real window, which flattened the tube to near-black and buried
            // the scanlines drawn on top of it.
            EllipticalGradient(
                colors: [style.tint.opacity(0.07), .clear, .black.opacity(0.42)],
                center: .center,
                startRadiusFraction: 0,
                endRadiusFraction: 0.78
            )
        }
    }

    /// Drawn rather than tiled: a Canvas costs one pass and needs no image
    /// asset, and the spacing stays honest at any size.
    private var scanlines: some View {
        Canvas { context, size in
            guard size.height > 0 else { return }
            for y in stride(from: 0, to: size.height, by: 3) {
                // Flat at the middle of the screen, bowing further as it
                // approaches either edge. Straight scanlines over curved glass
                // give the whole trick away.
                let fromCentre = (y / size.height) * 2 - 1
                // Tied to the face's own bow rather than computed separately,
                // so a screen whose curve has relaxed does not keep bending
                // its scanlines.
                let bow = face.bow(for: size) * 1.5
                var line = Path()
                line.move(to: CGPoint(x: 0, y: y))
                line.addQuadCurve(
                    to: CGPoint(x: size.width, y: y),
                    control: CGPoint(x: size.width / 2, y: y + fromCentre * bow)
                )
                context.stroke(line, with: .color(.black.opacity(0.30)), lineWidth: 1)
            }
        }
        .allowsHitTesting(false)
    }

    /// The slow bright band of a tube refreshing. Driven by a repeating
    /// SwiftUI animation, not a TimelineView, so Core Animation runs it off
    /// the main thread rather than redrawing this view sixty times a second —
    /// which matters more here than in a static pane, because a run is already
    /// pushing rsync output through it.
    private var sweep: some View {
        GeometryReader { geo in
            LinearGradient(
                colors: [.clear, style.tint.opacity(0.05), .clear],
                startPoint: .top,
                endPoint: .bottom
            )
            .frame(height: 120)
            .offset(y: sweepDown ? geo.size.height : -120)
            .onAppear {
                withAnimation(.linear(duration: 7.5).repeatForever(autoreverses: false)) {
                    sweepDown = true
                }
            }
        }
        .allowsHitTesting(false)
    }

    /// A soft highlight up and to the left, the way a room light sits on the
    /// curve of a real tube. Faint enough to read as a sheen rather than a
    /// smear over the output.
    private var glass: some View {
        EllipticalGradient(
            colors: [.white.opacity(0.055), .clear],
            center: UnitPoint(x: 0.3, y: 0.1),
            startRadiusFraction: 0,
            endRadiusFraction: 0.62
        )
        .allowsHitTesting(false)
    }

    private var bezel: some View {
        face
            .strokeBorder(style.tint.opacity(0.22), lineWidth: 1)
            .shadow(color: .black.opacity(0.6), radius: 6)
            .allowsHitTesting(false)
    }
}

/// The block cursor an idle terminal leaves sitting there, blinking at roughly
/// the rate one did.
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
            .frame(width: 10, height: 18)
            .shadow(color: style.tint.opacity(0.7), radius: 4)
    }

    private func lit(at date: Date) -> Bool {
        Int(date.timeIntervalSinceReferenceDate / Self.period) % 2 == 0
    }
}
