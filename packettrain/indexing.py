"""Background PCAP indexing and indexed flow extraction."""
import contextlib
import hashlib
import json
import mmap
import os
import re
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

INDEX_DIR = Path(os.environ.get("PACKETTRAIN_INDEX_DIR", "/cache")).resolve()
INDEX_BINARY = Path(os.environ.get("PACKETTRAIN_INDEX_BINARY", "/usr/local/bin/packettrain-index"))
INDEX_TIMEOUT = int(os.environ.get("PACKETTRAIN_INDEX_TIMEOUT", "900"))
INDEX_SCHEMA_VERSION = "2"
REF_SIZE = 32
NO_REF = (1 << 64) - 1
_PROGRESS = re.compile(r"indexed frame=(\d+) flows=(\d+) elapsed=([0-9.]+)s")
_threads = set()
_threads_lock = threading.Lock()


def supported(path):
    return path.suffix.lower() == ".pcap" and INDEX_BINARY.is_file()


def _identity(path):
    stat = path.stat()
    raw = f"{INDEX_SCHEMA_VERSION}\0{path.name}\0{stat.st_size}\0{stat.st_mtime_ns}".encode()
    return hashlib.sha256(raw).hexdigest()[:24]


def paths(path):
    key = _identity(path)
    return {
        "key": key,
        "dir": INDEX_DIR / key,
        "lock": INDEX_DIR / f"{key}.lock",
        "status": INDEX_DIR / f"{key}.status.json",
    }


def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def is_ready(path):
    item = paths(path)["dir"]
    return (item / "READY").is_file() and (item / "capture.sqlite").is_file() \
        and (item / "refs.bin").is_file()


def _run_index(path, item):
    status = item["status"]
    started = time.time()
    _atomic_json(status, {"state": "indexing", "started": started, "frame": 0, "flows": 0})
    command = [str(INDEX_BINARY), "scan", str(path), "--output", str(item["dir"])]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, errors="replace")
        stderr_tail = []
        deadline = time.monotonic() + INDEX_TIMEOUT
        while True:
            line = process.stderr.readline()
            if line:
                stderr_tail.append(line)
                stderr_tail = stderr_tail[-20:]
                match = _PROGRESS.search(line)
                if match:
                    _atomic_json(status, {"state": "indexing", "started": started,
                                 "frame": int(match.group(1)), "flows": int(match.group(2)),
                                 "elapsed": float(match.group(3))})
            if process.poll() is not None:
                break
            if time.monotonic() > deadline:
                process.kill()
                process.wait()
                raise TimeoutError(f"indexing exceeded {INDEX_TIMEOUT} seconds")
        stdout = process.stdout.read()[-1000:]
        remaining = process.stderr.read()
        if remaining:
            stderr_tail.extend(remaining.splitlines(keepends=True))
        if process.returncode:
            raise RuntimeError("".join(stderr_tail)[-2000:] or stdout or
                               f"indexer exited {process.returncode}")
        _atomic_json(status, {"state": "ready", "started": started,
                             "elapsed": round(time.time() - started, 3), "output": stdout.strip()})
    except Exception as exc:  # background failures are returned through status API
        _atomic_json(status, {"state": "error", "started": started,
                             "elapsed": round(time.time() - started, 3), "error": str(exc)})
    finally:
        with contextlib.suppress(OSError):
            item["lock"].unlink()
        with _threads_lock:
            _threads.discard(threading.current_thread())


def request_index(path):
    """Return index state, starting one background build when necessary."""
    if not supported(path):
        return {"supported": False, "state": "unsupported"}
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    item = paths(path)
    if is_ready(path):
        return {"supported": True, "state": "ready", "key": item["key"]}
    current = _read_json(item["status"])
    if item["lock"].exists():
        try:
            if time.time() - item["lock"].stat().st_mtime < INDEX_TIMEOUT:
                return {"supported": True, "key": item["key"],
                        **(current or {"state": "indexing"})}
            item["lock"].unlink()
        except OSError:
            pass
    try:
        descriptor = os.open(item["lock"], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError:
        return {"supported": True, "key": item["key"],
                **(_read_json(item["status"]) or {"state": "indexing"})}
    thread = threading.Thread(target=_run_index, args=(path, item),
                              name=f"pcap-index-{item['key']}", daemon=True)
    with _threads_lock:
        _threads.add(thread)
    thread.start()
    return {"supported": True, "state": "indexing", "key": item["key"],
            "started": time.time(), "frame": 0, "flows": 0}


def _connect(path):
    database = paths(path)["dir"] / "capture.sqlite"
    return sqlite3.connect(f"file:{database}?mode=ro", uri=True)


def stream_summaries(path, flow_id=None):
    """Return lightweight UI summaries from the completed flow manifest."""
    query = ("SELECT id,left_addr,left_port,right_addr,right_port,first_ts_ns,last_ts_ns,"
             "packets,payload_bytes,left_payload_bytes,right_payload_bytes,client_is_left "
             "FROM flows")
    parameters = ()
    if flow_id is not None:
        query += " WHERE id=?"
        parameters = (flow_id,)
    query += " ORDER BY id"
    with _connect(path) as connection:
        rows = connection.execute(query, parameters).fetchall()
    results = []
    for (flow_id, left_addr, left_port, right_addr, right_port, first_ns, last_ns,
         packets, total, left_bytes, right_bytes, client_left) in rows:
        client = left_addr if client_left else right_addr
        client_port = left_port if client_left else right_port
        server = right_addr if client_left else left_addr
        server_port = right_port if client_left else left_port
        client_bytes = left_bytes if client_left else right_bytes
        server_bytes = right_bytes if client_left else left_bytes
        dominant = max(client_bytes, server_bytes)
        share = dominant / total if total else 0
        duration = max(0, last_ns - first_ns) / 1_000_000
        if not total:
            pattern = "Control-only / idle"
        elif total >= 256_000 and share >= .85:
            pattern = "Bulk upload pattern" if client_bytes > server_bytes else "Bulk download pattern"
        elif client_bytes and server_bytes:
            pattern = "Request/response pattern"
        elif duration >= 10_000 and total >= 128_000:
            pattern = "Sustained one-way transfer"
        else:
            pattern = "Insufficient pattern"
        results.append({"id": flow_id, "client": client, "server": server,
                        "client_port": client_port, "server_port": server_port,
                        "packets": packets, "bytes": total,
                        "duration_ms": round(duration, 2), "pattern": pattern})
    return results


def flow_packet_count(path, flow_id):
    with _connect(path) as connection:
        row = connection.execute("SELECT packets FROM flows WHERE id=?", (flow_id,)).fetchone()
    if row is None:
        raise KeyError(flow_id)
    return int(row[0])


def original_frames(path, flow_id):
    """Walk one reference chain and return original frame numbers in source order."""
    with _connect(path) as connection:
        row = connection.execute("SELECT last_ref,packets FROM flows WHERE id=?", (flow_id,)).fetchone()
    if row is None:
        raise KeyError(flow_id)
    current, expected = row
    refs_path = paths(path)["dir"] / "refs.bin"
    frames = []
    with refs_path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as refs:
        while current != NO_REF:
            offset = current * REF_SIZE
            if offset + REF_SIZE > len(refs):
                raise ValueError("flow reference lies outside refs.bin")
            _, _, frame, previous, owner = struct.unpack_from("<QIIQI", refs, offset)
            if owner != flow_id:
                raise ValueError("flow reference chain crossed owners")
            frames.append(frame)
            if len(frames) > expected:
                raise ValueError("flow reference chain contains a cycle")
            current = previous
    frames.reverse()
    if len(frames) != expected:
        raise ValueError(f"flow expected {expected} references, found {len(frames)}")
    return frames


@contextlib.contextmanager
def extracted_flow(path, flow_id):
    """Materialize one indexed flow into a bounded-lifetime classic PCAP."""
    if not is_ready(path):
        raise FileNotFoundError("flow index is not ready")
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix=f"flow-{flow_id}-", suffix=".pcap",
                                         dir=INDEX_DIR, delete=False)
    output = Path(handle.name)
    handle.close()
    try:
        result = subprocess.run([str(INDEX_BINARY), "extract", "--index", str(paths(path)["dir"]),
                                 "--flow", str(flow_id), "--output", str(output)],
                                capture_output=True, text=True, timeout=120,
                                check=False, errors="replace")
        if result.returncode:
            raise RuntimeError(result.stderr[-1000:] or result.stdout[-1000:])
        yield output
    finally:
        with contextlib.suppress(OSError):
            output.unlink()
        with contextlib.suppress(OSError):
            output.with_suffix(".part").unlink()
