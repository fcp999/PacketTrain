import gzip

import pytest

from packettrain.http_objects import Incomplete, reassemble, recover_http_objects


def req(path="/file.bin", method="GET"):
    return f"{method} {path} HTTP/1.1\r\nHost: lab\r\n\r\n".encode()


def response(body, extra=b"", status=b"200 OK"):
    return (b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\n" + extra + b"\r\n" + body)


def recover(requests, responses, fin=False):
    return recover_http_objects([(requests, False), (responses, fin)])


def test_binary_content_and_filename():
    body = bytes(range(256)) * 32
    files, notes = recover(req(), response(body, b'Content-Disposition: attachment; filename="../../file.bin"\r\n'))
    assert not notes
    assert files[0]["filename"] == "file.bin"
    assert files[0]["data"] == body
    assert files[0]["size"] == len(body)
    assert len(files[0]["sha256"]) == 64


def test_reassembly_out_of_order_retransmit_wrap_and_fin():
    packets = [(0xfffffff9, 0, True, False, False, b""),
               (0, 3, False, False, False, b"ghi"),
               (0xfffffffa, 6, False, False, False, b"abcdef"),
               (0xfffffffd, 3, False, False, False, b"def"),
               (3, 0, False, True, False, b"")]
    assert reassemble(packets) == (b"abcdefghi", True, None)


def test_gap_does_not_invent_bytes():
    data, fin, warning = reassemble([(100, 4, False, False, False, b"abcd"),
                                    (106, 4, False, False, False, b"ghij")])
    assert data == b"abcd" and not fin and warning


def test_conflicting_retransmit_fails_closed():
    with pytest.raises(Incomplete):
        reassemble([(100, 4, False, False, False, b"abcd"),
                    (102, 2, False, False, False, b"XX")])


def test_chunked_gzip_with_trailers():
    body = b"\x00\x01hello" * 200
    compressed = gzip.compress(body)
    chunks = [compressed[:10], compressed[10:]]
    wire = b"".join(f"{len(c):x};x=y\r\n".encode() + c + b"\r\n" for c in chunks)
    wire += b"0\r\nX-Done: yes\r\n\r\n"
    files, notes = recover(req(), b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" + wire)
    assert not notes
    assert files[0]["data"] == body and not files[0]["encoded"]


def test_multiple_gets_head_and_interim_response():
    requests = req("/a", "HEAD") + req("/b.bin") + req("/c.bin")
    replies = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    replies += b"HTTP/1.1 100 Continue\r\n\r\n" + response(b"abc") + response(b"xyz")
    files, notes = recover(requests, replies)
    assert not notes
    assert [(f["filename"], f["data"]) for f in files] == [("b.bin", b"abc"), ("c.bin", b"xyz")]


def test_last_truncated_keeps_earlier_complete():
    files, notes = recover(req("/a.bin") + req("/b.bin"), response(b"abc") + response(b"xyz")[:-1])
    assert len(files) == 1 and files[0]["data"] == b"abc"
    assert any("Content-Length" in n for n in notes)


def test_close_delimited_requires_fin():
    reply = b"HTTP/1.0 200 OK\r\n\r\nabcd"
    assert recover(req(), reply)[0] == []
    assert recover(req(), reply, True)[0][0]["data"] == b"abcd"


def test_partial_range_and_unsupported_encoding():
    files, notes = recover(req(), response(b"abc", status=b"206 Partial Content"))
    assert not files and any("range" in n for n in notes)
    files, notes = recover(req(), response(b"abc", b"Content-Encoding: br\r\n"))
    assert files[0]["encoded"] and files[0]["filename"].endswith(".encoded")


def test_invalid_chunk_and_conflicting_lengths_refused():
    for reply in (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc",
                  b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 3\r\n\r\nabcd"):
        files, notes = recover(req(), reply)
        assert not files and notes


def test_download_endpoint_returns_binary_attachment(monkeypatch, tmp_path):
    import importlib
    from packettrain import config

    webapp = importlib.import_module("app")
    (tmp_path / "sample.pcap").write_bytes(b"pcap")
    monkeypatch.setattr(config, "PCAP_DIR", tmp_path)
    monkeypatch.setattr(webapp.indexing, "supported", lambda path: False)
    objects, warnings = recover(req(), response(b"\x00\xff"))
    monkeypatch.setattr(webapp, "extract_http_objects", lambda path, stream: (objects, warnings))
    client = webapp.app.test_client()
    url = "/api/http-objects?file=sample.pcap&stream=0"
    listing = client.get(url)
    assert listing.status_code == 200
    assert "data" not in listing.json["objects"][0]
    attachment = client.get(url + "&object=0&sha256=" + objects[0]["sha256"])
    assert attachment.status_code == 200 and attachment.data == b"\x00\xff"
    assert "attachment" in attachment.headers["Content-Disposition"]
    assert attachment.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get(url + "&object=0&sha256=wrong").status_code == 422
