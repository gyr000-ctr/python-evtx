import os
import sys
import subprocess

import pytest

import Evtx.Evtx as evtx
import Evtx.Recovery as recovery


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def normal_records(buf):
    fh = evtx.FileHeader(buf, 0x0)
    return [record for chunk in fh.chunks() for record in chunk.records()]


def test_recovery_matches_normal_parse_on_healthy_file(system):
    """
    recovery mode on a healthy file must produce exactly the same
    events, in the same order, as the normal parser.
    """
    report = recovery.RecoveryReport()
    recovered = list(recovery.recover_records(system, report))
    expected = normal_records(system)

    assert [r.record_num() for r in recovered] == [r.record_num() for r in expected]
    assert all(c.status == recovery.ChunkStatus.COMPLETE for c in report.chunks)
    assert report.total_truncated_records == 0
    for got, want in zip(recovered, expected):
        assert got.xml() == want.xml()


def test_recovery_report_offsets_and_chunk_numbers(system):
    report = recovery.RecoveryReport()
    list(recovery.recover_records(system, report))

    for i, chunk in enumerate(report.chunks):
        assert chunk.index == i
        assert chunk.offset == 0x1000 + i * 0x10000
    rendered = report.render()
    assert "0x00001000" in rendered
    assert "0x00011000" in rendered
    assert "summary:" in rendered


def test_recovery_truncated_final_chunk(data_path):
    """
    a file cut off mid-chunk (power loss) must yield every complete
    event before the cut, count the truncated tail, and not raise.
    """
    healthy = read_file(os.path.join(data_path, "system.evtx"))
    # cut inside the data region of chunk 2
    cut = 0x1000 + 2 * 0x10000 + 0x4000
    truncated = healthy[:cut]

    report = recovery.RecoveryReport()
    records = list(recovery.recover_records(truncated, report))

    assert report.chunks[-1].status == recovery.ChunkStatus.TRUNCATED
    assert report.chunks[-1].index == 2
    assert report.chunks[-1].offset == 0x1000 + 2 * 0x10000
    assert report.total_truncated_records >= 1

    healthy_report = recovery.RecoveryReport()
    healthy_records = list(recovery.recover_records(healthy, healthy_report))
    got_nums = [r.record_num() for r in records]
    # recovered events are a strict prefix of the healthy parse
    assert got_nums == [r.record_num() for r in healthy_records][: len(got_nums)]
    assert 0 < len(got_nums) < len(healthy_records)


def test_recovery_truncated_mid_record(data_path):
    """
    a file cut in the middle of a record must recover all records up to
    the cut and count exactly one truncated event in the final chunk.
    """
    healthy = read_file(os.path.join(data_path, "system.evtx"))
    # find the offset of the third record in chunk 0 of the healthy file
    fh = evtx.FileHeader(healthy, 0x0)
    chunk0 = fh.first_chunk()
    records = list(chunk0.records())
    victim = records[3]
    cut = victim._offset + victim.length() // 2
    truncated = healthy[:cut]

    report = recovery.RecoveryReport()
    recovered = list(recovery.recover_records(truncated, report))

    assert [r.record_num() for r in recovered] == [r.record_num() for r in records[:3]]
    assert report.chunks[0].status == recovery.ChunkStatus.TRUNCATED
    assert report.chunks[0].records_truncated == 1


def test_recovery_skips_chunk_with_bad_magic(data_path):
    """
    a chunk with a destroyed signature is reported invalid and skipped;
    chunks after it are still recovered.
    """
    healthy = read_file(os.path.join(data_path, "system.evtx"))
    corrupted = bytearray(healthy)
    chunk1_offset = 0x1000 + 0x10000
    corrupted[chunk1_offset : chunk1_offset + 8] = b"\x00" * 8

    report = recovery.RecoveryReport()
    records = list(recovery.recover_records(bytes(corrupted), report))

    invalid = report.by_status(recovery.ChunkStatus.INVALID)
    assert len(invalid) == 1
    assert invalid[0].index == 1
    assert invalid[0].offset == chunk1_offset
    # chunks after the gap are still parsed
    assert any(c.index == 2 and c.status == recovery.ChunkStatus.COMPLETE for c in report.chunks)

    healthy_report = recovery.RecoveryReport()
    healthy_records = list(recovery.recover_records(healthy, healthy_report))
    lost = healthy_report.chunks[1].records_recovered
    assert len(records) == len(healthy_records) - lost


def test_recovery_checksum_failed_chunk(data_path):
    """
    a chunk whose data was corrupted reports checksum-failed; its
    records are still walked and parsing continues afterwards.
    """
    healthy = read_file(os.path.join(data_path, "system.evtx"))
    corrupted = bytearray(healthy)
    # flip a byte inside chunk 1's data region
    corrupted[0x1000 + 0x10000 + 0x1000] ^= 0xFF

    report = recovery.RecoveryReport()
    records = list(recovery.recover_records(bytes(corrupted), report))

    failed = report.by_status(recovery.ChunkStatus.CHECKSUM_FAILED)
    assert len(failed) == 1
    assert failed[0].index == 1
    assert failed[0].data_checksum_ok is False
    assert failed[0].header_checksum_ok is True

    healthy_report = recovery.RecoveryReport()
    healthy_records = list(recovery.recover_records(healthy, healthy_report))
    # the corruption is inside one record's BinXML payload; the record
    # envelopes are intact, so no events are lost
    assert len(records) == len(healthy_records)


def test_recovery_dirty_file_header(data_path):
    """
    a dirty file header (log not cleanly closed) does not block recovery.
    """
    healthy = read_file(os.path.join(data_path, "system.evtx"))
    corrupted = bytearray(healthy)
    # set the dirty flag (file header flags field at 0x78)
    corrupted[0x78] |= 0x1

    report = recovery.RecoveryReport()
    records = list(recovery.recover_records(bytes(corrupted), report))

    assert report.file_header_ok is True
    assert report.is_dirty is True
    healthy_report = recovery.RecoveryReport()
    healthy_records = list(recovery.recover_records(healthy, healthy_report))
    assert len(records) == len(healthy_records)


def test_evtx_dump_recover_cli(data_path, tmp_path):
    """
    the --recover switch streams XML to stdout and the recovery report
    (with offsets and chunk numbers) to stderr, exiting cleanly.
    """
    healthy = read_file(os.path.join(data_path, "system.evtx"))
    damaged = bytearray(healthy[: 0x1000 + 2 * 0x10000 + 0x4000])
    damaged[0x1000 + 0x10000 : 0x1000 + 0x10000 + 8] = b"\x00" * 8
    damaged_path = str(tmp_path / "damaged.evtx")
    with open(damaged_path, "wb") as f:
        f.write(damaged)

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, os.path.join(repo_root, "evtx_scripts", "evtx_dump.py"), "--recover", damaged_path],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "<Events>" in proc.stdout
    assert "</Events>" in proc.stdout
    assert "<Event" in proc.stdout
    assert "EVTX recovery report" in proc.stderr
    assert "chunk 1 @ 0x00011000: invalid" in proc.stderr
    assert "chunk 2 @ 0x00021000: truncated" in proc.stderr
