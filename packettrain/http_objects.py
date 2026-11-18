"""Conservative, binary-safe HTTP/1.x object recovery from captured TCP streams.

Reassemble actual captured bytes, never invent bytes for sequence gaps. Only
export fully framed successful GET response bodies; no network requests.
"""
import gzip
import hashlib
import io
import mimetypes
import os
import re
import subprocess
import tempfile
import zlib
from email.message import Message
from urllib.parse import unquote, urlsplit

from flask import abort

from .config import MAX_PACKETS

MAX_HTTP_EXPORT_BYTES = int(os.environ.get("MAX_HTTP_EXPORT_BYTES", str(64 * 1024**2)))
MAX_HEADER = 64 * 1024
MAX_OBJECTS = 256

_REQ = re.compile(rb"([A-Z]+) (\S+) HTTP/1\.[01]")
_RES = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?:[ \t].*)?")
_FIELDS = ("ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst",
           "tcp.dstport", "tcp.seq_raw", "tcp.len", "tcp.flags.syn",
           "tcp.flags.fin", "tcp.flags.reset", "tcp.payload")


class Incomplete(ValueError):
    """Cannot prove a complete, correctly framed object."""


def _delta(seq, base):
    return ((seq - base + 2**31) % 2**32) - 2**31


def reassemble(records, limit=MAX_HTTP_EXPORT_BYTES):
    """Return contiguous captured prefix, clean FIN at its end, and warning.

    records: (raw sequence, advertised payload length, SYN, FIN, RST, bytes).
    The input may be out of order, overlap, or contain retransmissions.
    """
    data = bytearray()
    if not records:
        return b"", False, None
    syns = [(seq + 1) % 2**32 for seq, _, syn, _, _, _ in records if syn]
    payloads = [((seq + int(syn)) % 2**32, length, raw)
                for seq, length, syn, _, _, raw in records if length]
    if not payloads:
        return b"", False, None
    base = syns[0] if syns else payloads[0][0]
    if syns and any(s != base for s in syns):
        raise Incomplete("Conflicting SYN sequence numbers")
    parts = [(_delta(seq, base), length, raw) for seq, length, raw in payloads]
    if not syns:
        start = min(offset for offset, _, _ in parts)
        base = (base + start) % 2**32
        parts = [(offset - start, length, raw) for offset, length, raw in parts]
    declared_end = max(offset + length for offset, length, _ in parts)
    if declared_end > limit:
        raise Incomplete("TCP direction exceeds configured HTTP export byte limit")
    warning = None
    for offset, length, raw in sorted(parts, key=lambda p: p[0]):
        if offset < 0 or len(raw) > length:
            raise Incomplete("Invalid TCP sequence or captured payload length")
        if not raw:
            continue
        if offset > len(data):
            warning = "Missing TCP bytes; only the contiguous prefix is usable"
            break
        overlap = min(len(raw), len(data) - offset)
        if overlap and data[offset:offset + overlap] != raw[:overlap]:
            # A previous object might overlap this ambiguous range; fail closed.
            raise Incomplete("Conflicting TCP retransmission bytes")
        data.extend(raw[overlap:])
    if len(data) != declared_end:
        warning = "Missing or sliced TCP payload; only the contiguous prefix is usable"
    fins = [_delta((seq + int(syn) + length) % 2**32, base)
            for seq, length, syn, fin, _, _ in records if fin]
    clean_fin = (warning is None and len(data) in fins
                 and not any(rst for _, _, _, _, rst, _ in records))
    return bytes(data), clean_fin, warning


def read_directions(path, stream):
    command = ["tshark", "-n", "-r", str(path), "-Y", f"tcp.stream == {int(stream)}",
               "-T", "fields", "-E", "occurrence=f", "-E", "quote=n"]
    for field in _FIELDS:
        command.extend(("-e", field))
    records = {}
    raw_total = count = 0
    # Avoid storing the hex-rendered entire capture in RAM.
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(command, stdout=output, stderr=subprocess.PIPE,
                                    timeout=180, check=False)
        except subprocess.TimeoutExpired:
            abort(504, "TShark timed out extracting HTTP objects")
        except FileNotFoundError:
            abort(500, "TShark is unavailable")
        if result.returncode:
            abort(422, "TShark could not extract TCP data: " +
                  result.stderr[-500:].decode("utf-8", "replace"))
        output.seek(0)
        for line in output:
            count += 1
            if count > MAX_PACKETS:
                abort(413, "Selected flow exceeds MAX_PACKETS")
            cols = line.rstrip(b"\r\n").split(b"\t")
            cols += [b""] * (len(_FIELDS) - len(cols))
            try:
                src = (cols[0] or cols[1], int(cols[2]))
                dst = (cols[3] or cols[4], int(cols[5]))
                seq, length = int(cols[6]), int(cols[7])
                syn, fin, rst = (v in (b"1", b"True", b"true") for v in cols[8:11])
                raw = bytes.fromhex(cols[11].replace(b":", b"").decode("ascii"))
            except (ValueError, UnicodeError, IndexError):
                raise Incomplete("TShark returned an unreadable TCP record")
            raw_total += len(raw)
            if raw_total > MAX_HTTP_EXPORT_BYTES * 2:
                abort(413, "Captured payload including retransmissions exceeds HTTP export limit")
            records.setdefault((src, dst), []).append((seq, length, syn, fin, rst, raw))
    if not records:
        abort(404, "TCP stream not found")
    if len(records) != 2:
        raise Incomplete("Both TCP directions are required for HTTP request/response recovery")
    directions, warnings = [], []
    total = 0
    for packets in records.values():
        data, fin, warning = reassemble(packets)
        total += len(data)
        if total > MAX_HTTP_EXPORT_BYTES:
            abort(413, "Reassembled stream exceeds HTTP export byte limit")
        directions.append((data, fin))
        if warning and warning not in warnings:
            warnings.append(warning)
    return directions, warnings


def _head(data, pos, pattern):
    end = data.find(b"\r\n\r\n", pos, pos + MAX_HEADER + 4)
    if end < 0:
        raise Incomplete("Incomplete or oversized HTTP header")
    lines = data[pos:end].split(b"\r\n")
    match = pattern.fullmatch(lines[0])
    if not match:
        raise Incomplete("Not an aligned HTTP/1.x message")
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep or not re.fullmatch(rb"[!#$%&'*+\-.^_\x60|~0-9A-Za-z]+", name):
            raise Incomplete("Unsupported or malformed HTTP header")
        headers.setdefault(name.decode("ascii").lower(), []).append(value.strip().decode("latin-1"))
    return match, headers, end + 4


def _tokens(headers, name):
    return [v.strip().lower() for field in headers.get(name, []) for v in field.split(",")]


def _chunked(data, pos, limit):
    out = bytearray()
    while True:
        end = data.find(b"\r\n", pos, pos + 8192)
        if end < 0:
            raise Incomplete("Incomplete HTTP chunk size")
        size = data[pos:end].split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9a-fA-F]{1,16}", size):
            raise Incomplete("Invalid HTTP chunk size")
        length = int(size, 16)
        pos = end + 2
        if length == 0:
            if data[pos:pos + 2] == b"\r\n":
                return bytes(out), pos + 2
            end = data.find(b"\r\n\r\n", pos, pos + MAX_HEADER + 4)
            if end < 0:
                raise Incomplete("Incomplete HTTP chunk trailers")
            return bytes(out), end + 4
        if length > limit - len(out):
            raise Incomplete("HTTP object exceeds export size limit")
        if pos + length + 2 > len(data) or data[pos + length:pos + length + 2] != b"\r\n":
            raise Incomplete("Incomplete or malformed HTTP chunk body")
        out.extend(data[pos:pos + length])
        pos += length + 2


def _body(data, pos, headers, *, request=False, no_body=False, fin=False, limit=MAX_HTTP_EXPORT_BYTES):
    if no_body:
        return b"", pos
    transfer = _tokens(headers, "transfer-encoding")
    lengths = _tokens(headers, "content-length")
    if transfer:
        if transfer != ["chunked"] or lengths:
            raise Incomplete("Unsupported or ambiguous HTTP transfer framing")
        return _chunked(data, pos, limit)
    if lengths:
        if any(not re.fullmatch(r"[0-9]{1,16}", v) for v in lengths) or len(set(lengths)) != 1:
            raise Incomplete("Invalid or conflicting HTTP Content-Length")
        length = int(lengths[0])
        if length > limit:
            raise Incomplete("HTTP object exceeds export size limit")
        if pos + length > len(data):
            raise Incomplete("Content-Length exceeds captured TCP bytes")
        return data[pos:pos + length], pos + length
    if request:
        return b"", pos
    if not fin:
        raise Incomplete("Close-delimited HTTP response has no captured clean TCP FIN")
    if len(data) - pos > limit:
        raise Incomplete("HTTP object exceeds export size limit")
    return data[pos:], len(data)


def _decode_content(body, encodings, limit):
    """Decode content codings in reverse order; enforce decompressed size."""
    out = body
    for encoding in reversed(encodings):
        if encoding == "identity":
            continue
        if encoding in ("gzip", "x-gzip"):
            with gzip.GzipFile(fileobj=io.BytesIO(out)) as reader:
                out = reader.read(limit + 1)
        elif encoding == "deflate":
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    decoder = zlib.decompressobj(wbits)
                    decoded = decoder.decompress(out, limit + 1)
                    if len(decoded) > limit:
                        raise Incomplete("Decompressed object exceeds export size limit")
                    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                        raise zlib.error("Incomplete or trailing deflate data")
                    out = decoded
                    break
                except zlib.error:
                    continue
            else:
                raise Incomplete("Invalid deflate encoding")
        else:
            raise Incomplete("Unsupported Content-Encoding: " + encoding)
        if len(out) > limit:
            raise Incomplete("Decompressed object exceeds export size limit")
    return out


def _filename(headers, target, index, encoded):
    message = Message()
    if headers.get("content-disposition"):
        message["Content-Disposition"] = headers["content-disposition"][0]
    filename = message.get_filename()
    if not filename:
        try:
            filename = unquote(urlsplit(target).path.rstrip("/").rsplit("/", 1)[-1])
        except ValueError:
            filename = ""
    filename = re.split(r"[/\\]", str(filename or ""))[-1]
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._-")[:160]
    media = headers.get("content-type", ["application/octet-stream"])[0].split(";")[0].strip().lower()
    extension = mimetypes.guess_extension(media) or ".bin"
    if not filename:
        filename = "http-object-" + str(index) + extension
    elif "." not in filename:
        filename += extension
    if encoded:
        filename += ".encoded"
    return filename, media


def recover_http_objects(directions, limit=MAX_HTTP_EXPORT_BYTES):
    """Pair HTTP/1.x requests and final responses; keep complete GET objects."""
    if len(directions) != 2:
        return [], ["Both TCP directions are needed"]
    client, server = directions
    if client[0].startswith(b"HTTP/1.") and not server[0].startswith(b"HTTP/1."):
        client, server = server, client
    req, _ = client
    res, fin = server
    if not _REQ.fullmatch(req.split(b"\r\n", 1)[0]) or not res.startswith(b"HTTP/1."):
        return [], ["No aligned plaintext HTTP/1.x request/response at start of captured data"]
    objects, warnings = [], []
    rp = sp = total = 0
    while rp < len(req) and sp < len(res):
        try:
            match, headers, rp = _head(req, rp, _REQ)
            method, target = (v.decode("latin-1") for v in match.groups())
            _, rp = _body(req, rp, headers, request=True, limit=limit)
            while True:
                match, headers, sp = _head(res, sp, _RES)
                status = int(match.group(1))
                if 100 <= status < 200 and status != 101:
                    continue
                break
            if status == 101 or (method == "CONNECT" and 200 <= status < 300):
                warnings.append("HTTP upgrade or tunnel: subsequent bytes not interpreted")
                break
            body, sp = _body(res, sp, headers, no_body=method == "HEAD" or status in (204, 304),
                             fin=fin, limit=limit)
            if method != "GET" or not 200 <= status < 300 or not body:
                continue
            if status == 206 or "content-range" in headers:
                warnings.append("Partial HTTP range response skipped; not a complete original file")
                continue
            encodings = _tokens(headers, "content-encoding")
            encoded = False
            note = None
            try:
                decoded = _decode_content(body, encodings, limit - total)
            except (Incomplete, OSError, EOFError, zlib.error) as exc:
                decoded = body
                encoded = True
                note = "Captured encoded body only: " + str(exc)
            if len(decoded) > limit - total:
                warnings.append("Total recovered object size exceeds export limit")
                break
            index = len(objects)
            filename, media = _filename(headers, target, index + 1, encoded)
            objects.append({"id": index, "filename": filename, "target": target,
                            "status": status, "content_type": media,
                            "content_encoding": ", ".join(encodings) or "identity",
                            "size": len(decoded), "sha256": hashlib.sha256(decoded).hexdigest(),
                            "encoded": encoded, "note": note, "data": decoded})
            total += len(decoded)
            if len(objects) >= MAX_OBJECTS:
                warnings.append("HTTP object count limit reached")
                break
        except Incomplete as exc:
            warnings.append(str(exc))
            break
    if rp < len(req) and sp >= len(res):
        warnings.append("Additional requests have no complete captured response")
    return objects, list(dict.fromkeys(warnings))


def extract_http_objects(path, stream):
    try:
        directions, warnings = read_directions(path, stream)
        objects, notes = recover_http_objects(directions)
        return objects, list(dict.fromkeys(warnings + notes))
    except Incomplete as exc:
        return [], [str(exc)]
