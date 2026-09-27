use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use rusqlite::{params, Connection};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Instant, UNIX_EPOCH};

const REF_SIZE: usize = 32;
const NO_REF: u64 = u64::MAX;

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn u32_at(data: &[u8], off: usize, e: Endian) -> Result<u32> {
    let b: [u8; 4] = data
        .get(off..off + 4)
        .context("truncated u32")?
        .try_into()?;
    Ok(match e {
        Endian::Little => u32::from_le_bytes(b),
        Endian::Big => u32::from_be_bytes(b),
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    addr: [u8; 16],
    port: u16,
}
impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr).then(self.port.cmp(&other.port))
    }
}
impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    family: u8,
    left: Endpoint,
    right: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FragmentKey {
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
    ident: u32,
}

struct ParsedPacket {
    key: Option<FlowKey>,
    fragment: Option<FragmentKey>,
    non_initial_fragment: bool,
    src_is_left: bool,
    flags: u8,
    payload: u32,
}

#[derive(Debug)]
struct Flow {
    id: u32,
    generation: u32,
    key: FlowKey,
    first_frame: u32,
    last_frame: u32,
    first_ts_ns: i64,
    last_ts_ns: i64,
    packets: u64,
    captured_bytes: u64,
    payload_bytes: u64,
    left_payload_bytes: u64,
    right_payload_bytes: u64,
    client_is_left: bool,
    syn_seen: bool,
    fin_mask: u8,
    rst_seen: bool,
    closed: bool,
    first_ref: u64,
    last_ref: u64,
}

fn addr4(v: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(v);
    a
}
fn canonical(family: u8, src: [u8; 16], sport: u16, dst: [u8; 16], dport: u16) -> (FlowKey, bool) {
    let a = Endpoint {
        addr: src,
        port: sport,
    };
    let b = Endpoint {
        addr: dst,
        port: dport,
    };
    if a <= b {
        (
            FlowKey {
                family,
                left: a,
                right: b,
            },
            true,
        )
    } else {
        (
            FlowKey {
                family,
                left: b,
                right: a,
            },
            false,
        )
    }
}

fn parse_tcp(packet: &[u8], linktype: u32) -> Option<ParsedPacket> {
    if linktype != 1 || packet.len() < 14 {
        return None;
    }
    let mut off = 14usize;
    let mut eth = u16::from_be_bytes(packet[12..14].try_into().ok()?);
    while matches!(eth, 0x8100 | 0x88a8 | 0x9100) {
        if packet.len() < off + 4 {
            return None;
        }
        eth = u16::from_be_bytes(packet[off + 2..off + 4].try_into().ok()?);
        off += 4;
    }
    let (family, src, dst, tcp_off, declared_end, fragment, non_initial) = if eth == 0x0800 {
        if packet.len() < off + 20 {
            return None;
        }
        let ihl = ((packet[off] & 0x0f) as usize) * 4;
        if ihl < 20 || packet.len() < off + ihl || packet[off + 9] != 6 {
            return None;
        }
        let frag = u16::from_be_bytes(packet[off + 6..off + 8].try_into().ok()?);
        let ident = u16::from_be_bytes(packet[off + 4..off + 6].try_into().ok()?) as u32;
        let src = addr4(&packet[off + 12..off + 16]);
        let dst = addr4(&packet[off + 16..off + 20]);
        let fk = if frag & 0x3fff != 0 {
            Some(FragmentKey {
                family: 4,
                src,
                dst,
                ident,
            })
        } else {
            None
        };
        let total = u16::from_be_bytes(packet[off + 2..off + 4].try_into().ok()?) as usize;
        (
            4,
            src,
            dst,
            off + ihl,
            off.saturating_add(total),
            fk,
            frag & 0x1fff != 0,
        )
    } else if eth == 0x86dd {
        if packet.len() < off + 40 || packet[off] >> 4 != 6 {
            return None;
        }
        let mut src = [0u8; 16];
        src.copy_from_slice(&packet[off + 8..off + 24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&packet[off + 24..off + 40]);
        let declared_end =
            off + 40 + u16::from_be_bytes(packet[off + 4..off + 6].try_into().ok()?) as usize;
        let mut next = packet[off + 6];
        let mut cur = off + 40;
        let mut fk = None;
        let mut non_initial = false;
        while matches!(next, 0 | 43 | 44 | 51 | 60) {
            if packet.len() < cur + 2 {
                return None;
            }
            let old = next;
            next = packet[cur];
            if old == 44 {
                if packet.len() < cur + 8 {
                    return None;
                }
                let frag = u16::from_be_bytes(packet[cur + 2..cur + 4].try_into().ok()?);
                let ident = u32::from_be_bytes(packet[cur + 4..cur + 8].try_into().ok()?);
                non_initial = frag & 0xfff8 != 0;
                fk = Some(FragmentKey {
                    family: 6,
                    src,
                    dst,
                    ident,
                });
                cur += 8;
            } else if old == 51 {
                cur += ((packet[cur + 1] as usize) + 2) * 4;
            } else {
                cur += ((packet[cur + 1] as usize) + 1) * 8;
            }
        }
        if next != 6 {
            return None;
        }
        (6, src, dst, cur, declared_end, fk, non_initial)
    } else {
        return None;
    };
    if non_initial {
        return Some(ParsedPacket {
            key: None,
            fragment,
            non_initial_fragment: true,
            src_is_left: false,
            flags: 0,
            payload: 0,
        });
    }
    if packet.len() < tcp_off + 20 {
        return None;
    }
    let sport = u16::from_be_bytes(packet[tcp_off..tcp_off + 2].try_into().ok()?);
    let dport = u16::from_be_bytes(packet[tcp_off + 2..tcp_off + 4].try_into().ok()?);
    let data_off = ((packet[tcp_off + 12] >> 4) as usize) * 4;
    if data_off < 20 {
        return None;
    }
    let (key, src_is_left) = canonical(family, src, sport, dst, dport);
    Some(ParsedPacket {
        key: Some(key),
        fragment,
        non_initial_fragment: false,
        src_is_left,
        flags: packet[tcp_off + 13],
        payload: declared_end.saturating_sub(tcp_off + data_off) as u32,
    })
}

fn endpoint_text(family: u8, ep: Endpoint) -> String {
    if family == 4 {
        Ipv4Addr::new(ep.addr[0], ep.addr[1], ep.addr[2], ep.addr[3]).to_string()
    } else {
        Ipv6Addr::from(ep.addr).to_string()
    }
}

fn write_ref(
    w: &mut BufWriter<File>,
    source_offset: u64,
    source_len: u32,
    frame: u32,
    previous: u64,
    flow_id: u32,
) -> Result<()> {
    let mut b = [0u8; REF_SIZE];
    b[0..8].copy_from_slice(&source_offset.to_le_bytes());
    b[8..12].copy_from_slice(&source_len.to_le_bytes());
    b[12..16].copy_from_slice(&frame.to_le_bytes());
    b[16..24].copy_from_slice(&previous.to_le_bytes());
    b[24..28].copy_from_slice(&flow_id.to_le_bytes());
    w.write_all(&b)?;
    Ok(())
}

fn scan(source: &Path, out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let ready = out.join("READY");
    if ready.exists() {
        fs::remove_file(&ready)?;
    }
    let started = Instant::now();
    let file = File::open(source)?;
    let map = unsafe { Mmap::map(&file)? };
    if map.len() < 24 {
        bail!("capture is shorter than a PCAP header");
    }
    let (endian, nanos) = match &map[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => bail!("only classic PCAP is supported in this stage"),
    };
    let linktype = u32_at(&map, 20, endian)?;
    if linktype != 1 {
        bail!("stage A supports Ethernet PCAP only (linktype {linktype})");
    }
    let refs_tmp = out.join("refs.bin.tmp");
    let mut refs = BufWriter::with_capacity(4 << 20, File::create(&refs_tmp)?);
    let mut flows: Vec<Flow> = Vec::new();
    let mut active: HashMap<FlowKey, usize> = HashMap::new();
    let mut generations: HashMap<FlowKey, u32> = HashMap::new();
    let mut fragments: HashMap<FragmentKey, usize> = HashMap::new();
    let mut pos = 24usize;
    let mut frame = 0u32;
    let mut ref_count = 0u64;
    let mut tcp_packets = 0u64;
    while pos + 16 <= map.len() {
        let rec = pos;
        let sec = u32_at(&map, pos, endian)?;
        let frac = u32_at(&map, pos + 4, endian)?;
        let incl = u32_at(&map, pos + 8, endian)? as usize;
        pos += 16;
        if incl > map.len() - pos {
            bail!("truncated packet record at frame {}", frame + 1);
        }
        frame = frame
            .checked_add(1)
            .context("capture exceeds u32 frame numbers")?;
        let packet = &map[pos..pos + incl];
        pos += incl;
        let Some(parsed) = parse_tcp(packet, linktype) else {
            continue;
        };
        tcp_packets += 1;
        let flow_index = if parsed.non_initial_fragment {
            let Some(fk) = parsed.fragment else {
                continue;
            };
            let Some(i) = fragments.get(&fk).copied() else {
                continue;
            };
            i
        } else {
            let key = parsed.key.unwrap();
            let syn = parsed.flags & 0x02 != 0;
            let ack = parsed.flags & 0x10 != 0;
            let make_new = match active.get(&key) {
                None => true,
                Some(i) => syn && !ack && flows[*i].closed,
            };
            if make_new {
                let generation = *generations.entry(key).and_modify(|g| *g += 1).or_insert(0);
                let i = flows.len();
                flows.push(Flow {
                    id: i as u32,
                    generation,
                    key,
                    first_frame: frame,
                    last_frame: frame,
                    first_ts_ns: 0,
                    last_ts_ns: 0,
                    packets: 0,
                    captured_bytes: 0,
                    payload_bytes: 0,
                    left_payload_bytes: 0,
                    right_payload_bytes: 0,
                    client_is_left: parsed.src_is_left,
                    syn_seen: false,
                    fin_mask: 0,
                    rst_seen: false,
                    closed: false,
                    first_ref: NO_REF,
                    last_ref: NO_REF,
                });
                active.insert(key, i);
                i
            } else {
                *active.get(&key).unwrap()
            }
        };
        if let Some(fk) = parsed.fragment {
            fragments.insert(fk, flow_index);
        }
        let ts_ns = (sec as i64) * 1_000_000_000 + (frac as i64) * if nanos { 1 } else { 1000 };
        let flow = &mut flows[flow_index];
        if flow.packets == 0 {
            flow.first_ts_ns = ts_ns;
        }
        flow.last_ts_ns = ts_ns;
        flow.last_frame = frame;
        flow.packets += 1;
        flow.captured_bytes += incl as u64;
        if !parsed.non_initial_fragment {
            flow.payload_bytes += parsed.payload as u64;
            if parsed.src_is_left {
                flow.left_payload_bytes += parsed.payload as u64;
            } else {
                flow.right_payload_bytes += parsed.payload as u64;
            }
            let syn = parsed.flags & 2 != 0;
            let fin = parsed.flags & 1 != 0;
            let rst = parsed.flags & 4 != 0;
            flow.syn_seen |= syn;
            if fin {
                flow.fin_mask |= if parsed.src_is_left { 1 } else { 2 };
            }
            flow.rst_seen |= rst;
            flow.closed |= rst || flow.fin_mask == 3;
        }
        let idx = ref_count;
        write_ref(
            &mut refs,
            rec as u64,
            (16 + incl) as u32,
            frame,
            flow.last_ref,
            flow.id,
        )?;
        if flow.first_ref == NO_REF {
            flow.first_ref = idx;
        }
        flow.last_ref = idx;
        ref_count += 1;
        if frame % 1_000_000 == 0 {
            eprintln!(
                "indexed frame={frame} flows={} elapsed={:.2}s",
                flows.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
    refs.flush()?;
    refs.get_ref().sync_all()?;
    let db_tmp = out.join("capture.sqlite.tmp");
    if db_tmp.exists() {
        fs::remove_file(&db_tmp)?;
    }
    let mut db = Connection::open(&db_tmp)?;
    db.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
      CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE flows(id INTEGER PRIMARY KEY,generation INTEGER NOT NULL,family INTEGER NOT NULL,
       left_addr TEXT NOT NULL,left_port INTEGER NOT NULL,right_addr TEXT NOT NULL,right_port INTEGER NOT NULL,
       first_frame INTEGER NOT NULL,last_frame INTEGER NOT NULL,first_ts_ns INTEGER NOT NULL,last_ts_ns INTEGER NOT NULL,
       packets INTEGER NOT NULL,captured_bytes INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,
       left_payload_bytes INTEGER NOT NULL,right_payload_bytes INTEGER NOT NULL,client_is_left INTEGER NOT NULL,
       syn_seen INTEGER NOT NULL,fin_mask INTEGER NOT NULL,rst_seen INTEGER NOT NULL,closed INTEGER NOT NULL,first_ref INTEGER NOT NULL,last_ref INTEGER NOT NULL,
       analysis_state TEXT NOT NULL DEFAULT 'pending');")?;
    let meta = fs::metadata(source)?;
    let mtime = meta.modified()?.duration_since(UNIX_EPOCH)?.as_nanos();
    let entries = [
        ("format", "pcap".to_string()),
        (
            "source_path",
            fs::canonicalize(source)?.display().to_string(),
        ),
        ("source_size", meta.len().to_string()),
        ("source_mtime_ns", mtime.to_string()),
        ("linktype", linktype.to_string()),
        (
            "timestamp_precision",
            if nanos {
                "nanosecond".into()
            } else {
                "microsecond".into()
            },
        ),
        ("frames", frame.to_string()),
        ("tcp_packets", tcp_packets.to_string()),
        ("flows", flows.len().to_string()),
        ("refs", ref_count.to_string()),
        ("index_seconds", started.elapsed().as_secs_f64().to_string()),
        ("index_version", env!("CARGO_PKG_VERSION").into()),
    ];
    {
        let tx = db.transaction()?;
        for (k, v) in entries {
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                params![k, v],
            )?;
        }
        {
            let mut st=tx.prepare("INSERT INTO flows(id,generation,family,left_addr,left_port,right_addr,right_port,first_frame,last_frame,first_ts_ns,last_ts_ns,packets,captured_bytes,payload_bytes,left_payload_bytes,right_payload_bytes,client_is_left,syn_seen,fin_mask,rst_seen,closed,first_ref,last_ref) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)")?;
            for f in &flows {
                st.execute(params![
                    f.id,
                    f.generation,
                    f.key.family,
                    endpoint_text(f.key.family, f.key.left),
                    f.key.left.port,
                    endpoint_text(f.key.family, f.key.right),
                    f.key.right.port,
                    f.first_frame,
                    f.last_frame,
                    f.first_ts_ns,
                    f.last_ts_ns,
                    f.packets,
                    f.captured_bytes,
                    f.payload_bytes,
                    f.left_payload_bytes,
                    f.right_payload_bytes,
                    f.client_is_left as u8,
                    f.syn_seen as u8,
                    f.fin_mask,
                    f.rst_seen as u8,
                    f.closed as u8,
                    f.first_ref,
                    f.last_ref
                ])?;
            }
        }
        tx.commit()?;
    }
    db.close().map_err(|(_, e)| e)?;
    let refs_final = out.join("refs.bin");
    let db_final = out.join("capture.sqlite");
    if refs_final.exists() {
        fs::remove_file(&refs_final)?;
    }
    if db_final.exists() {
        fs::remove_file(&db_final)?;
    }
    fs::rename(refs_tmp, refs_final)?;
    fs::rename(db_tmp, db_final)?;
    fs::write(
        &ready,
        format!("packettrain-index {}\n", env!("CARGO_PKG_VERSION")),
    )?;
    println!(
        "indexed frames={frame} tcp_packets={tcp_packets} flows={} refs={ref_count} seconds={:.3}",
        flows.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn metadata_value(db: &Connection, key: &str) -> Result<String> {
    Ok(
        db.query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })?,
    )
}
fn extract(index: &Path, flow_id: u32, out: &Path) -> Result<()> {
    let started = Instant::now();
    if !index.join("READY").is_file() {
        bail!("index is incomplete; rebuild it");
    }
    let db = Connection::open(index.join("capture.sqlite"))?;
    let source = PathBuf::from(metadata_value(&db, "source_path")?);
    let expected_size: u64 = metadata_value(&db, "source_size")?.parse()?;
    let expected_mtime: u128 = metadata_value(&db, "source_mtime_ns")?.parse()?;
    let source_meta = fs::metadata(&source)?;
    let actual_mtime = source_meta
        .modified()?
        .duration_since(UNIX_EPOCH)?
        .as_nanos();
    if source_meta.len() != expected_size || actual_mtime != expected_mtime {
        bail!("source capture changed; rebuild the index");
    }
    let (last_ref, packets): (u64, u64) = db.query_row(
        "SELECT last_ref,packets FROM flows WHERE id=?1",
        [flow_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let refs_file = File::open(index.join("refs.bin"))?;
    let refs = unsafe { Mmap::map(&refs_file)? };
    let mut chain = Vec::with_capacity(packets as usize);
    let mut current = last_ref;
    while current != NO_REF {
        let off = (current as usize)
            .checked_mul(REF_SIZE)
            .context("reference offset overflow")?;
        let row = refs
            .get(off..off + REF_SIZE)
            .context("reference outside refs.bin")?;
        let source_offset = u64::from_le_bytes(row[0..8].try_into()?);
        let source_len = u32::from_le_bytes(row[8..12].try_into()?);
        let frame = u32::from_le_bytes(row[12..16].try_into()?);
        let previous = u64::from_le_bytes(row[16..24].try_into()?);
        let owner = u32::from_le_bytes(row[24..28].try_into()?);
        if owner != flow_id {
            bail!("reference chain crossed into flow {owner}");
        }
        chain.push((frame, source_offset, source_len));
        current = previous;
        if chain.len() > packets as usize {
            bail!("reference chain cycle detected");
        }
    }
    chain.reverse();
    if chain.len() != packets as usize {
        bail!("flow expected {packets} references, found {}", chain.len());
    }
    let source_file = File::open(&source)?;
    let capture = unsafe { Mmap::map(&source_file)? };
    let temp = out.with_extension("part");
    let mut writer = BufWriter::with_capacity(
        1 << 20,
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)?,
    );
    writer.write_all(&capture[0..24])?;
    for (_, off, len) in &chain {
        let a = *off as usize;
        let b = a + *len as usize;
        writer.write_all(capture.get(a..b).context("source record outside capture")?)?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    fs::rename(&temp, out)?;
    println!(
        "extracted flow={flow_id} packets={} bytes={} seconds={:.4}",
        chain.len(),
        fs::metadata(out)?.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; 14 + total];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = 14;
        p[ip] = 0x45;
        p[ip + 2..ip + 4].copy_from_slice(&(total as u16).to_be_bytes());
        p[ip + 8] = 64;
        p[ip + 9] = 6;
        p[ip + 12..ip + 16].copy_from_slice(&src);
        p[ip + 16..ip + 20].copy_from_slice(&dst);
        let t = ip + 20;
        p[t..t + 2].copy_from_slice(&sport.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&dport.to_be_bytes());
        p[t + 12] = 0x50;
        p[t + 13] = flags;
        p[t + 20..].copy_from_slice(payload);
        p
    }
    fn write_fixture(path: &Path) -> Result<()> {
        let mut f = File::create(path)?;
        let mut h = [0u8; 24];
        h[0..4].copy_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        h[4..6].copy_from_slice(&2u16.to_le_bytes());
        h[6..8].copy_from_slice(&4u16.to_le_bytes());
        h[16..20].copy_from_slice(&65535u32.to_le_bytes());
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        f.write_all(&h)?;
        let a = [192, 0, 2, 1];
        let b = [198, 51, 100, 2];
        let c = [203, 0, 113, 3];
        let packets = vec![
            tcp_packet(a, b, 50000, 80, 0x02, &[]),
            tcp_packet(b, a, 80, 50000, 0x12, &[]),
            tcp_packet(a, b, 50000, 80, 0x04, &[]),
            tcp_packet(a, b, 50000, 80, 0x02, &[]),
            tcp_packet(b, a, 80, 50000, 0x04, &[]),
            tcp_packet(c, b, 40000, 443, 0x18, b"hello"),
        ];
        for (i, p) in packets.iter().enumerate() {
            f.write_all(&(i as u32 + 1).to_le_bytes())?;
            f.write_all(&0u32.to_le_bytes())?;
            f.write_all(&(p.len() as u32).to_le_bytes())?;
            f.write_all(&(p.len() as u32).to_le_bytes())?;
            f.write_all(p)?;
        }
        Ok(())
    }
    fn packet_count(path: &Path) -> Result<u32> {
        let d = fs::read(path)?;
        let mut p = 24;
        let mut n = 0;
        while p + 16 <= d.len() {
            let l = u32::from_le_bytes(d[p + 8..p + 12].try_into()?) as usize;
            p += 16 + l;
            n += 1;
        }
        Ok(n)
    }
    #[test]
    fn indexes_tuple_reuse_and_extracts_exact_membership() -> Result<()> {
        let root = env::temp_dir().join(format!(
            "packettrain-index-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&root)?;
        let source = root.join("fixture.pcap");
        let index = root.join("fixture.ptindex");
        write_fixture(&source)?;
        scan(&source, &index)?;
        let db = Connection::open(index.join("capture.sqlite"))?;
        let rows: i64 = db.query_row("SELECT count(*) FROM flows", [], |r| r.get(0))?;
        assert_eq!(rows, 3);
        let values: Vec<(i64, i64)> = db
            .prepare("SELECT generation,packets FROM flows ORDER BY id")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        assert_eq!(values, vec![(0, 3), (1, 2), (0, 1)]);
        drop(db);
        let out = root.join("flow0.pcap");
        extract(&index, 0, &out)?;
        assert_eq!(packet_count(&out)?, 3);
        assert_eq!(
            fs::metadata(index.join("refs.bin"))?.len(),
            6 * REF_SIZE as u64
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}

fn usage() -> ! {
    eprintln!("usage:\n  packettrain-index scan <capture.pcap> --output <index-dir>\n  packettrain-index extract --index <index-dir> --flow <id> --output <flow.pcap>");
    std::process::exit(2)
}
fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage()
    }
    match args[1].as_str() {
        "scan" => {
            if args.len() < 3 {
                usage()
            }
            scan(
                Path::new(&args[2]),
                Path::new(&option(&args, "--output").unwrap_or_else(|| usage())),
            )
        }
        "extract" => {
            let idx = option(&args, "--index").unwrap_or_else(|| usage());
            let flow: u32 = option(&args, "--flow").unwrap_or_else(|| usage()).parse()?;
            let out = option(&args, "--output").unwrap_or_else(|| usage());
            extract(Path::new(&idx), flow, Path::new(&out))
        }
        _ => usage(),
    }
}
