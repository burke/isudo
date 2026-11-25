// Draws the isudo app icon: the root prompt "#" inside a scanner frame.
//
//   swift tools/make-icon.swift App/Resources/Assets.xcassets/AppIcon.appiconset
//
// Writes three 1024x1024 PNGs: the standard icon, a dark variant and a
// tinted (greyscale) variant, both on a transparent ground as iOS expects.

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let size: CGFloat = 1024

enum Variant: String {
    case standard = "icon"
    case dark = "icon-dark"
    case tinted = "icon-tinted"
}

func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(
        red: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
        blue: CGFloat(hex & 0xff) / 255, alpha: alpha
    )
}

/// The four corners of a rounded square, as open strokes.
func frame(inset: CGFloat, radius: CGFloat, arm: CGFloat) -> CGPath {
    let path = CGMutablePath()
    let lo = inset, hi = size - inset
    // (corner point, direction along x, direction along y)
    for (cx, cy, dx, dy) in [(lo, lo, 1.0, 1.0), (hi, lo, -1.0, 1.0), (hi, hi, -1.0, -1.0), (lo, hi, 1.0, -1.0)] {
        path.move(to: CGPoint(x: cx, y: cy + dy * arm))
        path.addLine(to: CGPoint(x: cx, y: cy + dy * radius))
        path.addQuadCurve(to: CGPoint(x: cx + dx * radius, y: cy), control: CGPoint(x: cx, y: cy))
        path.addLine(to: CGPoint(x: cx + dx * arm, y: cy))
    }
    return path
}

/// A slightly slanted "#", the root shell prompt.
func hash(half: CGFloat, gap: CGFloat, slant: CGFloat) -> CGPath {
    let path = CGMutablePath()
    let c = size / 2
    for x in [c - gap, c + gap] {
        path.move(to: CGPoint(x: x - slant, y: c - half))
        path.addLine(to: CGPoint(x: x + slant, y: c + half))
    }
    for y in [c - gap, c + gap] {
        path.move(to: CGPoint(x: c - half, y: y))
        path.addLine(to: CGPoint(x: c + half, y: y))
    }
    return path
}

func draw(_ variant: Variant) -> CGImage {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let context = CGContext(
        data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0, space: space,
        // The standard icon fills its square and must have no alpha channel:
        // the App Store refuses an icon that has one. The other two are
        // drawn on nothing, for the system to put a background behind.
        bitmapInfo: (variant == .standard ? CGImageAlphaInfo.noneSkipLast : .premultipliedLast).rawValue
    )!

    if variant == .standard {
        let colors = [rgb(0x6e63ff), rgb(0x3a2fc4)] as CFArray
        let gradient = CGGradient(colorsSpace: space, colors: colors, locations: [0, 1])!
        context.drawLinearGradient(
            gradient, start: CGPoint(x: 0, y: size), end: CGPoint(x: size, y: 0), options: []
        )
    }

    let (frameColor, hashColor): (CGColor, CGColor) = switch variant {
    case .standard: (rgb(0xffffff, 0.55), rgb(0xffffff))
    case .dark: (rgb(0x8f88ff, 0.6), rgb(0xa9a3ff))
    case .tinted: (rgb(0xffffff, 0.55), rgb(0xffffff))
    }

    context.setLineCap(.round)
    context.setLineJoin(.round)

    context.setStrokeColor(frameColor)
    context.setLineWidth(54)
    context.addPath(frame(inset: 178, radius: 124, arm: 184))
    context.strokePath()

    context.setStrokeColor(hashColor)
    context.setLineWidth(70)
    context.addPath(hash(half: 172, gap: 78, slant: 30))
    context.strokePath()

    return context.makeImage()!
}

let directory = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? ".")
for variant in [Variant.standard, .dark, .tinted] {
    let url = directory.appendingPathComponent("\(variant.rawValue).png")
    let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, draw(variant), nil)
    guard CGImageDestinationFinalize(destination) else { fatalError("could not write \(url.path)") }
    print("wrote \(url.path)")
}
