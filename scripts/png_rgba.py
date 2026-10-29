"""Rewrite an 8-bit RGB(A) PNG as an RGBA PNG, which is what tauri's icon parser insists on."""
import struct, sys, zlib


def read_png(path):
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, hdr = 8, b"", None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        kind = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            hdr = struct.unpack(">IIBBBBB", chunk)
        elif kind == b"IDAT":
            idat += chunk
        elif kind == b"IEND":
            break
        pos += 12 + length
    width, height, depth, color, compress, filt, interlace = hdr
    assert depth == 8 and interlace == 0, "need an 8-bit non-interlaced PNG"
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color]
    raw = zlib.decompress(idat)
    stride = width * channels
    out = bytearray(height * stride)
    prev = bytearray(stride)

    def paeth(a, b, c):
        p = a + b - c
        pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
        if pa <= pb and pa <= pc:
            return a
        return b if pb <= pc else c

    offset = 0
    for y in range(height):
        kind = raw[offset]
        offset += 1
        line = bytearray(raw[offset:offset + stride])
        offset += stride
        for i in range(stride):
            a = line[i - channels] if i >= channels else 0
            b = prev[i]
            c = prev[i - channels] if i >= channels else 0
            if kind == 0:
                v = line[i]
            elif kind == 1:
                v = line[i] + a
            elif kind == 2:
                v = line[i] + b
            elif kind == 3:
                v = line[i] + ((a + b) >> 1)
            elif kind == 4:
                v = line[i] + paeth(a, b, c)
            else:
                raise SystemExit("unknown filter %d" % kind)
            line[i] = v & 0xFF
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return width, height, channels, bytes(out)


def write_png(path, width, height, rgba):
    stride = width * 4
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw += rgba[y * stride:(y + 1) * stride]

    def chunk(kind, payload):
        return (struct.pack(">I", len(payload)) + kind + payload
                + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))

    body = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))
    open(path, "wb").write(body)


def main(src, dst):
    width, height, channels, pixels = read_png(src)
    if channels == 4:
        rgba = pixels
    else:
        out = bytearray(width * height * 4)
        for i in range(width * height):
            if channels == 3:
                r, g, b = pixels[i * 3:i * 3 + 3]
            else:
                r = g = b = pixels[i]
            out[i * 4:i * 4 + 4] = bytes((r, g, b, 255))
        rgba = bytes(out)
    write_png(dst, width, height, rgba)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
