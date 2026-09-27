"""Payload extraction and decoding for a single captured TCP segment.

Reads the raw bytes of one frame with TShark, then makes them legible: an ASCII
and hex rendering, an HTTP request/response parse when the bytes look like HTTP,
and detection of the common encodings a capture tends to carry (gzip, deflate,
base64, JSON, JWT). Decoding is deliberately one level deep; the goal is to show
what is there, not to unwrap an arbitrary chain.
"""
import base64
import binascii
import gzip
import json
import re
import subprocess
import zlib

from flask import abort

from .config import capture_path

MAX_PAYLOAD_BYTES = 1 << 20  # 1 MiB: enough for a body, bounded for the response


def _read_bytes(path, frame):
    """Return the tcp payload bytes for one frame, or b"" if it carries none.

    TShark prints the payload as a hex string. frame.number is used as the
    display filter so a single segment is read without decoding the whole file.
    """
    command = [
        "tshark", "-n", "-r", str(path),
        "-Y", f"frame.number=={int(frame)}",
        "-T", "fields", "-e", "tcp.payload", "-E", "occurrence=f", "-E", "quote=n",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60,
                                check=False, errors="replace")
    except subprocess.TimeoutExpired:
        abort(504, "TShark timed out reading the payload")
    except FileNotFoundError:
        abort(500, "TShark is unavailable")
    if result.returncode:
        abort(422, "TShark could not read this capture: " + result.stderr[-500:])
    text = result.stdout.strip().replace(":", "")
    if not text:
        return b""
    try:
        data = binascii.unhexlify(text)
    except (binascii.Error, ValueError):
        return b""
    return data[:MAX_PAYLOAD_BYTES]


def ascii_view(data):
    """Printable rendering: keep tabs and newlines, replace everything else."""
    return "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "." for b in data)


def hex_dump(data, width=16):
    """Classic offset / hex / ascii dump, one string per row."""
    rows = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hexed = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = ascii_view(chunk)
        rows.append(f"{offset:08x}  {hexed}  {text}")
    return rows


_PRINTABLE = re.compile(rb"^[\x09\x0a\x0d\x20-\x7e]+$")


def _looks_printable(data):
    return bool(data) and bool(_PRINTABLE.match(data))


def _try_gzip(data):
    try:
        out = gzip.decompress(data)
        return out[:MAX_PAYLOAD_BYTES]
    except Exception:
        return None


def _try_zlib(data):
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 15 + 32):
        try:
            out = zlib.decompress(data, wbits)
            return out[:MAX_PAYLOAD_BYTES]
        except Exception:
            continue
    return None


_B64 = re.compile(rb"^[A-Za-z0-9+/]+={0,2}$")


def _try_base64(data):
    """Decode a base64 blob only when the round trip proves it was base64.

    A short or text-like run can decode by accident, so the input is re-encoded
    and compared; anything that does not survive that check is left alone.
    """
    stripped = data.strip()
    if len(stripped) < 8 or len(stripped) % 4 != 0:
        return None
    if not _B64.match(stripped):
        return None
    try:
        out = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not out:
        return None
    if base64.b64encode(out).rstrip(b"=") != stripped.rstrip(b"="):
        return None
    # Short runs of [A-Za-z0-9+/] round-trip by accident but decode to binary
    # noise. A real encoded payload decodes to something a reader can use, so
    # require the result to be printable text before calling it base64.
    sample = out[:4096]
    if not sample:
        return None
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(sample) < 0.85:
        return None
    return out[:MAX_PAYLOAD_BYTES]


_JWT = re.compile(rb"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def _decode_jwt(data):
    token = data.strip()
    if not _JWT.match(token):
        return None
    parts = token.split(b".")
    if len(parts) != 3:
        return None
    out = {}
    for name, part in (("header", parts[0]), ("payload", parts[1])):
        padded = part + b"=" * (-len(part) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            out[name] = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return None
    return out


def _pretty_json(data):
    try:
        parsed = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    return json.dumps(parsed, indent=2)


def _split_headers(text):
    """Split an HTTP head from its body, tolerating CRLF or bare LF."""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in text:
            head, body = text.split(sep, 1)
            return head, body
    return text, ""


_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$")
_REQUEST = re.compile(r"^([A-Z]{3,7})\s+(\S+)\s+HTTP/\d(?:\.\d)?$")


def parse_http(data):
    """Parse an HTTP message. Returns a dict, or None if this is not HTTP.

    Only the head is required to match; the body is kept as text so a
    Content-Encoding can be applied afterwards.
    """
    text = data.decode("latin-1")
    head, body = _split_headers(text)
    lines = head.splitlines()
    if not lines:
        return None
    first = lines[0].strip()
    request = _REQUEST.match(first)
    status = _STATUS.match(first)
    if not request and not status:
        return None
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append([name.strip(), value.strip()])
    message = {"kind": "request" if request else "response", "start_line": first, "headers": headers}
    if request:
        message["method"], message["target"] = request.group(1), request.group(2)
    else:
        message["status"] = int(status.group(1))
        message["reason"] = (status.group(2) or "").strip()
    message["body_text"] = body
    return message


_ENCODING_ORDER = ("gzip", "deflate", "br", "x-gzip")


def _content_encoding(headers):
    for name, value in headers:
        if name.lower() == "content-encoding":
            for token in value.split(","):
                token = token.strip().lower()
                if token:
                    return token
    return None


def _decode_body(headers, body_text):
    """Apply Content-Encoding to an HTTP body and report what was done."""
    token = _content_encoding(headers)
    if not token:
        return None
    raw = body_text.encode("latin-1")
    if token in ("gzip", "x-gzip"):
        out = _try_gzip(raw)
    elif token == "deflate":
        out = _try_zlib(raw)
    elif token == "br":
        out = None  # brotli is not in the standard library
    else:
        out = None
    if out is None:
        return {"encoding": token, "ok": False,
                "note": f"Content-Encoding: {token} could not be decoded here"}
    return {"encoding": token, "ok": True, "bytes": len(out),
            "text": out.decode("utf-8", "replace")}


def detect_formats(data):
    """Report recognised encodings without decoding them, for highlighting."""
    found = []
    if data[:2] == b"\x1f\x8b":
        found.append({"kind": "gzip", "reason": "gzip magic 1f 8b"})
    if _looks_printable(data):
        if _JWT.match(data.strip()):
            found.append({"kind": "jwt", "reason": "three base64url fields"})
        elif _try_base64(data):
            found.append({"kind": "base64", "reason": "decodes cleanly and round-trips"})
        if data.lstrip()[:1] in (b"{", b"["):
            found.append({"kind": "json", "reason": "starts with a JSON container"})
    return found


def decode_segment(path, frame):
    """Everything the payload panel needs for one frame."""
    data = _read_bytes(path, frame)
    http = parse_http(data) if data else None
    decoded = []
    if http:
        applied = _decode_body(http["headers"], http.get("body_text", ""))
        if applied:
            decoded.append(applied)
        body = http.get("body_text", "").strip()
        if body:
            pretty = _pretty_json(body.encode("latin-1", "replace"))
            if pretty:
                decoded.append({"encoding": "json", "ok": True, "text": pretty})
    elif data:
        gz = _try_gzip(data)
        if gz is not None:
            decoded.append({"encoding": "gzip", "ok": True, "bytes": len(gz),
                            "text": gz.decode("utf-8", "replace")})
        else:
            b64 = _try_base64(data)
            if b64 is not None:
                decoded.append({"encoding": "base64", "ok": True, "bytes": len(b64),
                                "text": b64.decode("utf-8", "replace")})
            jwt = _decode_jwt(data)
            if jwt is not None:
                decoded.append({"encoding": "jwt", "ok": True,
                                "text": json.dumps(jwt, indent=2)})
    return {
        "frame": int(frame),
        "length": len(data),
        "ascii": ascii_view(data),
        "hex": hex_dump(data),
        "hex_raw": data.hex(),
        "http": http,
        "decoded": decoded,
        "detected": detect_formats(data),
    }
