#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
"""Recovery-oriented parsing for corrupt or truncated EVTX files.

This module tolerates the damage typically found in images captured from
systems that lost power mid-write: dirty file headers, chunks with failed
checksums, and a final chunk truncated on disk.

Design notes:

  - The input buffer is only ever memory-mapped or bytes-like; it is
    indexed lazily, so memory use stays bounded regardless of file size.
  - Records are produced as a generator, in chunk order, so callers can
    stream output without buffering all events in memory.
  - Nothing here raises on corrupt input. Damage is reported per chunk
    (with file offsets and chunk numbers) via a RecoveryReport.
"""
from __future__ import absolute_import

import struct
import logging
from dataclasses import dataclass, field

from .Evtx import Record, FileHeader, ChunkHeader
from .BinaryParser import ParseException

logger = logging.getLogger(__name__)

FILE_HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000
CHUNK_DATA_START = 0x200
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = 0x2A2A
# smallest plausible record: 0x18 byte header + size2 dword
RECORD_MIN_SIZE = 0x1C


class ChunkStatus(object):
    COMPLETE = "complete"
    TRUNCATED = "truncated"
    CHECKSUM_FAILED = "checksum-failed"
    INVALID = "invalid"


@dataclass
class ChunkReport:
    """The recovery outcome for a single chunk (or missing chunk slot)."""

    index: int  # chunk number; -1 if the chunk was found at an unaligned offset
    offset: int  # absolute file offset of the chunk header
    status: str
    records_recovered: int = 0
    records_truncated: int = 0  # events cut off mid-record within this chunk
    header_checksum_ok: bool = None
    data_checksum_ok: bool = None
    note: str = ""

    def render(self):
        line = "chunk {index} @ 0x{offset:08x}: {status}".format(
            index=self.index if self.index >= 0 else "?",
            offset=self.offset,
            status=self.status,
        )
        details = []
        if self.records_recovered or self.records_truncated:
            details.append(
                "records={}, truncated_events={}".format(self.records_recovered, self.records_truncated)
            )
        if self.header_checksum_ok is not None:
            details.append("header_crc={}".format("ok" if self.header_checksum_ok else "FAIL"))
        if self.data_checksum_ok is not None:
            details.append("data_crc={}".format("ok" if self.data_checksum_ok else "FAIL"))
        if self.note:
            details.append(self.note)
        if details:
            line += " (" + ", ".join(details) + ")"
        return line


@dataclass
class RecoveryReport:
    """Summary of a recovery pass over one EVTX file."""

    file_header_ok: bool = False
    is_dirty: bool = False
    is_full: bool = False
    declared_chunk_count: int = 0
    chunks: list = field(default_factory=list)
    render_errors: int = 0  # records recovered but failing to render as XML

    def add_chunk(self, chunk_report):
        self.chunks.append(chunk_report)
        return chunk_report

    def by_status(self, status):
        return [c for c in self.chunks if c.status == status]

    @property
    def total_records(self):
        return sum(c.records_recovered for c in self.chunks)

    @property
    def total_truncated_records(self):
        return sum(c.records_truncated for c in self.chunks)

    def render(self):
        lines = ["EVTX recovery report"]
        header_bits = []
        header_bits.append("ok" if self.file_header_ok else "INVALID")
        if self.is_dirty:
            header_bits.append("dirty")
        if self.is_full:
            header_bits.append("full")
        lines.append("file header: {} (declared chunks: {})".format(", ".join(header_bits), self.declared_chunk_count))
        for chunk in self.chunks:
            lines.append(chunk.render())
        lines.append(
            "summary: chunks={} complete={} truncated={} checksum_failed={} invalid={} "
            "records_recovered={} truncated_events={} render_errors={}".format(
                len(self.chunks),
                len(self.by_status(ChunkStatus.COMPLETE)),
                len(self.by_status(ChunkStatus.TRUNCATED)),
                len(self.by_status(ChunkStatus.CHECKSUM_FAILED)),
                len(self.by_status(ChunkStatus.INVALID)),
                self.total_records,
                self.total_truncated_records,
                self.render_errors,
            )
        )
        return "\n".join(lines)


def _chunk_index(offset):
    """Return the chunk number for a file offset, or -1 if not chunk-aligned."""
    if offset < FILE_HEADER_SIZE or (offset - FILE_HEADER_SIZE) % CHUNK_SIZE != 0:
        return -1
    return (offset - FILE_HEADER_SIZE) // CHUNK_SIZE


def _looks_like_chunk_header(buf, offset):
    """
    Heuristic check that the bytes at `offset` plausibly start a chunk,
    used to reject false positives when scanning for the chunk signature
    (the magic bytes can appear inside event data).
    """
    if offset + CHUNK_DATA_START > len(buf):
        return False
    try:
        (header_size,) = struct.unpack_from("<I", buf, offset + 0x28)
        (next_record_offset,) = struct.unpack_from("<I", buf, offset + 0x30)
    except struct.error:
        return False
    return header_size == 0x80 and CHUNK_DATA_START <= next_record_offset <= CHUNK_SIZE


def find_chunk_offsets(buf):
    """
    Scan the buffer for chunk signatures, in file order.

    @rtype generator of int
    @return A generator of absolute file offsets at which plausible
      chunk headers were found.
    """
    pos = FILE_HEADER_SIZE
    while True:
        try:
            ofs = buf.find(CHUNK_MAGIC, pos)
        except ValueError:
            return
        if ofs == -1:
            return
        if _looks_like_chunk_header(buf, ofs):
            yield ofs
        pos = ofs + 1


def _safe_checksum(fn):
    try:
        return fn()
    except (ParseException, struct.error, IndexError, ValueError):
        return None


def _iter_chunk_records(buf, chunk, chunk_report):
    """
    Walk the records of one chunk with strict bounds checking.

    Yields each complete Record up to the first damaged or truncated
    record, then stops; the damaged tail is counted on `chunk_report`
    rather than raised. A record is complete only if its magic, size,
    and trailing size2 all validate and it lies fully within the chunk
    data actually present in the buffer.
    """
    chunk_offset = chunk._offset
    # data the chunk claims to have, clamped to sane bounds
    try:
        next_record_offset = chunk.next_record_offset()
    except (ParseException, struct.error):
        next_record_offset = CHUNK_SIZE
    if not CHUNK_DATA_START <= next_record_offset <= CHUNK_SIZE:
        next_record_offset = CHUNK_SIZE

    # data actually present in the buffer (handles a truncated final chunk)
    available_end = min(chunk_offset + CHUNK_SIZE, len(buf))
    end = min(chunk_offset + next_record_offset, available_end)

    record_offset = chunk_offset + CHUNK_DATA_START
    while record_offset + 8 <= end:
        magic, size = struct.unpack_from("<II", buf, record_offset)
        if magic != RECORD_MAGIC or size < RECORD_MIN_SIZE or record_offset + size > end:
            chunk_report.records_truncated += 1
            return
        (size2,) = struct.unpack_from("<I", buf, record_offset + size - 4)
        if size2 != size:
            chunk_report.records_truncated += 1
            return
        record = Record(buf, record_offset, chunk)
        chunk_report.records_recovered += 1
        yield record
        record_offset += size
    if record_offset < end:
        # leftover bytes that cannot hold another record header
        chunk_report.records_truncated += 1


def recover_records(buf, report=None):
    """
    Recover records from a possibly corrupt EVTX file, in chunk order.

    Damaged chunks are skipped (or cut at their last complete event) and
    described in the report; parsing always continues with the next chunk.

    @type buf: a bytes-like or mmap object containing the EVTX file
    @type report: RecoveryReport or None
    @rtype generator of Evtx.Evtx.Record
    @return A generator of recovered Records. The given report (or a new
      one, accessible via `recover_records` callers holding it) is filled
      in as the generator is consumed.
    """
    if report is None:
        report = RecoveryReport()

    try:
        file_header = FileHeader(buf, 0x0)
        report.file_header_ok = file_header.check_magic()
        report.is_dirty = file_header.is_dirty()
        report.is_full = file_header.is_full()
        report.declared_chunk_count = file_header.chunk_count()
    except (ParseException, struct.error, IndexError, ValueError) as e:
        logger.warning("file header unreadable, scanning for chunks anyway: %s", e)
        report.file_header_ok = False

    expected_offset = FILE_HEADER_SIZE
    for chunk_offset in find_chunk_offsets(buf):
        index = _chunk_index(chunk_offset)
        # report aligned chunk slots that were skipped (no valid signature)
        if index > 0:
            missing = (chunk_offset - expected_offset) // CHUNK_SIZE
            for i in range(missing):
                missing_offset = expected_offset + i * CHUNK_SIZE
                report.add_chunk(
                    ChunkReport(
                        index=_chunk_index(missing_offset),
                        offset=missing_offset,
                        status=ChunkStatus.INVALID,
                        note="no valid chunk signature found",
                    )
                )
        if index >= 0:
            expected_offset = chunk_offset + CHUNK_SIZE

        chunk_report = report.add_chunk(ChunkReport(index=index, offset=chunk_offset, status=ChunkStatus.COMPLETE))
        try:
            chunk = ChunkHeader(buf, chunk_offset)
        except (ParseException, struct.error, IndexError, ValueError) as e:
            chunk_report.status = ChunkStatus.INVALID
            chunk_report.note = "chunk header unreadable: {}".format(e)
            continue

        calc_header = _safe_checksum(chunk.calculate_header_checksum)
        calc_data = _safe_checksum(chunk.calculate_data_checksum)
        try:
            chunk_report.header_checksum_ok = calc_header is not None and calc_header == chunk.header_checksum()
            chunk_report.data_checksum_ok = calc_data is not None and calc_data == chunk.data_checksum()
        except (ParseException, struct.error):
            chunk_report.status = ChunkStatus.INVALID
            chunk_report.note = "chunk header fields unreadable"
            continue

        for record in _iter_chunk_records(buf, chunk, chunk_report):
            yield record

        if chunk_report.records_truncated:
            chunk_report.status = ChunkStatus.TRUNCATED
        elif not (chunk_report.header_checksum_ok and chunk_report.data_checksum_ok):
            chunk_report.status = ChunkStatus.CHECKSUM_FAILED
