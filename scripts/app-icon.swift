#!/usr/bin/env swift
/* Pads the logo into the macOS icon grid: the artwork occupies `span` of the tile so the Dock
   and taskbar render it at a normal size instead of full-bleed.

   Usage:  swift scripts/app-icon.swift [source] [target] [span]
   Then:   npx tauri icon assets/app-icon.png
*/

import AppKit

let args = CommandLine.arguments
let source = args.count > 1 ? args[1] : "dist/logo.png"
let target = args.count > 2 ? args[2] : "assets/app-icon.png"
let span = args.count > 3 ? (Double(args[3]) ?? 0.8) : 0.8
let size = 512

guard let image = NSImage(contentsOfFile: source) else {
    fatalError("cannot read \(source)")
}
guard let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
    samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
    bytesPerRow: 0, bitsPerPixel: 0
) else {
    fatalError("cannot create canvas")
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let side = Double(size) * span
let offset = (Double(size) - side) / 2
image.draw(in: NSRect(x: offset, y: offset, width: side, height: side))
NSGraphicsContext.restoreGraphicsState()

let data = rep.representation(using: .png, properties: [:])!
try! data.write(to: URL(fileURLWithPath: target))
let corner = rep.colorAt(x: 2, y: 2)!
print("\(target): art \(Int(side))px in a \(size)px tile (\(Int(span * 100))%), corner alpha \(corner.alphaComponent)")
