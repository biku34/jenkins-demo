"""
Disk Entropy Analyzer
======================
Tkinter forensic analysis tool for raw disk images (.dd/.img) and EnCase E01.

Modules:
  DiskReader         – raw .dd/.img/.bin/.raw/.iso streaming
  E01Reader          – pure-Python EWF/E01 multi-segment reader (no libewf)
  EntropyCalculator  – Shannon entropy + byte-frequency per block
  ChiSquareTest      – goodness-of-fit vs uniform distribution → p-value
  CompressionTest    – zlib compression ratio to detect truly random/encrypted data
  SlidingWindowAnalyzer – overlapping sub-windows for fine-grained detection
  ThresholdDetector  – flag blocks above configurable entropy threshold
  RegionAggregator   – merge consecutive flagged blocks into regions, filter noise

Usage:
    python disk_entropy_analyzer.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import math
import os
import csv
import json
import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional, Iterator, Tuple, Dict


# ═════════════════════════════════════════════════════════════════════════════
# E01 / EWF Reader  (pure Python, no libewf dependency)
# ═════════════════════════════════════════════════════════════════════════════

EWF_SIGNATURE     = b"EVF\x09\x0d\x0a\xff\x00"
SECTION_HDR_SIZE  = 76
CHUNK_COMP_FLAG   = 0x80000000
CHUNK_OFFSET_MASK = 0x7FFFFFFF


class EWFSegment:
    def __init__(self, path: str):
        self.path = path
        self.fh   = open(path, "rb")
        self._validate()
        self.sections: List[dict] = []
        self._parse_sections()

    def _validate(self):
        sig = self.fh.read(8)
        if sig != EWF_SIGNATURE:
            raise ValueError(f"Not a valid EWF/E01 file: {self.path}")
        self.fh.read(5)

    def _parse_sections(self):
        self.fh.seek(13)
        visited = set()
        while True:
            pos = self.fh.tell()
            if pos in visited:
                break
            visited.add(pos)
            raw = self.fh.read(SECTION_HDR_SIZE)
            if len(raw) < SECTION_HDR_SIZE:
                break
            t     = raw[0:16].rstrip(b"\x00").decode("ascii", errors="replace").lower()
            next_ = struct.unpack_from("<Q", raw, 16)[0]
            size  = struct.unpack_from("<Q", raw, 24)[0]
            self.sections.append({
                "type_str":    t,
                "next_offset": next_,
                "size":        size,
                "data_offset": pos + SECTION_HDR_SIZE,
            })
            if t in ("done", "next"):
                break
            if next_ == 0 or next_ == pos:
                break
            self.fh.seek(next_)

    def get_section(self, name: str) -> Optional[dict]:
        for s in self.sections:
            if s["type_str"] == name:
                return s
        return None

    def read_section_data(self, sec: dict) -> bytes:
        n = sec["size"] - SECTION_HDR_SIZE
        if n <= 0:
            return b""
        self.fh.seek(sec["data_offset"])
        return self.fh.read(n)

    def close(self):
        self.fh.close()


class EWFVolume:
    def __init__(self, data: bytes):
        self.sectors_per_chunk = 64
        self.bytes_per_sector  = 512
        self.chunk_count       = 0
        self.sector_count      = 0
        if len(data) >= 25:
            try:
                (_, _, self.chunk_count, self.sectors_per_chunk,
                 self.bytes_per_sector, self.sector_count
                 ) = struct.unpack_from("<B3sIIIQ", data, 0)
            except struct.error:
                pass

    @property
    def chunk_size(self) -> int:
        return self.sectors_per_chunk * self.bytes_per_sector

    @property
    def total_bytes(self) -> int:
        return self.sector_count * self.bytes_per_sector


class EWFChunkTable:
    def __init__(self, data: bytes):
        self.entries: List[Tuple[int, bool]] = []
        if len(data) < 20:
            return
        num_entries = struct.unpack_from("<I", data, 0)[0]
        base_offset = struct.unpack_from("<Q", data, 8)[0]
        entry_start = 16
        for i in range(num_entries):
            pos = entry_start + i * 4
            if pos + 4 > len(data):
                break
            val        = struct.unpack_from("<I", data, pos)[0]
            compressed = bool(val & CHUNK_COMP_FLAG)
            rel_offset = val & CHUNK_OFFSET_MASK
            self.entries.append((base_offset + rel_offset, compressed))


class E01Reader:
    def __init__(self, e01_path: str, block_size: int = 512):
        self.block_size     = block_size
        self._segments:     List[EWFSegment]    = []
        self._chunk_tables: List[EWFChunkTable] = []
        self._chunk_segs:   List[int]           = []
        self._chunk_size    = 32768
        self._total_bytes   = 0
        self._load_segments(e01_path)
        self._parse_volume()
        self._parse_tables()

    def _load_segments(self, first: str):
        paths = [first] + self._next_paths(first)
        for p in paths:
            if os.path.isfile(p):
                self._segments.append(EWFSegment(p))
            else:
                break

    @staticmethod
    def _next_paths(first: str) -> List[str]:
        base = first[:-3]
        out  = [f"{base}E{i:02d}" for i in range(2, 100)]
        for c1 in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            for c2 in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                out.append(f"{base}E{c1}{c2}")
        return out

    def _parse_volume(self):
        for seg in self._segments:
            vsec = seg.get_section("volume") or seg.get_section("disk")
            if vsec:
                vol = EWFVolume(seg.read_section_data(vsec))
                if vol.chunk_size > 0:
                    self._chunk_size = vol.chunk_size
                self._total_bytes = vol.total_bytes
                return
        for seg in self._segments:
            for s in seg.sections:
                if s["type_str"] in ("sectors", "data"):
                    self._total_bytes += max(0, s["size"] - SECTION_HDR_SIZE)

    def _parse_tables(self):
        for idx, seg in enumerate(self._segments):
            for s in seg.sections:
                if s["type_str"] == "table":
                    ct = EWFChunkTable(seg.read_section_data(s))
                    if ct.entries:
                        self._chunk_tables.append(ct)
                        self._chunk_segs.append(idx)

    @property
    def total_blocks(self) -> int:
        return math.ceil(self._total_bytes / self.block_size) if self.block_size else 0

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def stream_blocks(self) -> Iterator[Tuple[int, bytes]]:
        if self._chunk_tables:
            yield from self._stream_via_tables()
        else:
            yield from self._stream_fallback()

    def _stream_via_tables(self) -> Iterator[Tuple[int, bytes]]:
        buffer = b""
        block_index = 0
        bs = self.block_size
        all_entries: List[Tuple[int, bool, int]] = []
        for ct, si in zip(self._chunk_tables, self._chunk_segs):
            for off, comp in ct.entries:
                all_entries.append((off, comp, si))
        for ei, (file_off, compressed, si) in enumerate(all_entries):
            seg = self._segments[si]
            if ei + 1 < len(all_entries) and all_entries[ei + 1][2] == si:
                read_size = all_entries[ei + 1][0] - file_off
            else:
                read_size = self._chunk_size + 256
            seg.fh.seek(file_off)
            raw = seg.fh.read(max(0, read_size))
            if compressed:
                try:
                    chunk_data = zlib.decompress(raw)
                except zlib.error:
                    try:
                        chunk_data = zlib.decompress(raw, -15)
                    except zlib.error:
                        chunk_data = raw
            else:
                chunk_data = raw[:self._chunk_size]
            buffer += chunk_data
            while len(buffer) >= bs:
                yield block_index, buffer[:bs]
                buffer = buffer[bs:]
                block_index += 1
        if buffer:
            yield block_index, buffer

    def _stream_fallback(self) -> Iterator[Tuple[int, bytes]]:
        block_index = 0
        buffer = b""
        bs = self.block_size
        for seg in self._segments:
            for s in seg.sections:
                if s["type_str"] not in ("sectors", "data"):
                    continue
                remaining = s["size"] - SECTION_HDR_SIZE
                if remaining <= 0:
                    continue
                seg.fh.seek(s["data_offset"])
                while remaining > 0:
                    chunk = seg.fh.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    buffer += chunk
                    while len(buffer) >= bs:
                        yield block_index, buffer[:bs]
                        buffer = buffer[bs:]
                        block_index += 1
        if buffer:
            yield block_index, buffer

    def get_metadata(self) -> dict:
        meta = {
            "segments":    len(self._segments),
            "chunk_size":  self._chunk_size,
            "total_bytes": self._total_bytes,
        }
        for seg in self._segments:
            for ht in ("header2", "header"):
                hsec = seg.get_section(ht)
                if not hsec:
                    continue
                raw = seg.read_section_data(hsec)
                try:
                    text = zlib.decompress(raw).decode("utf-16-le", errors="replace")
                except Exception:
                    try:
                        text = raw.decode("ascii", errors="replace")
                    except Exception:
                        text = ""
                if text:
                    meta["header_text"] = text[:500]
                    break
            break
        return meta

    def close(self):
        for seg in self._segments:
            seg.close()


# ═════════════════════════════════════════════════════════════════════════════
# Raw Disk Reader
# ═════════════════════════════════════════════════════════════════════════════

class RawDiskReader:
    def __init__(self, path: str, block_size: int = 512):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Not found: {path}")
        self.path         = path
        self.block_size   = block_size
        self.total_bytes  = os.path.getsize(path)
        self.total_blocks = math.ceil(self.total_bytes / block_size) if block_size else 0

    def stream_blocks(self) -> Iterator[Tuple[int, bytes]]:
        with open(self.path, "rb") as fh:
            idx = 0
            while True:
                chunk = fh.read(self.block_size)
                if not chunk:
                    break
                yield idx, chunk
                idx += 1

    def get_metadata(self) -> dict:
        return {"file_size": self.total_bytes, "block_size": self.block_size}

    def close(self):
        pass


def open_image(path: str, block_size: int):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".e01", ".ex01", ".lx01"):
        return E01Reader(path, block_size)
    if ext in (".dd", ".img", ".raw", ".bin", ".iso"):
        return RawDiskReader(path, block_size)
    raise ValueError(
        f"Unsupported format '{ext}'.\n"
        "Supported: .E01, .Ex01, .Lx01, .dd, .img, .raw, .bin, .iso"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Entropy Calculation
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class BlockResult:
    block_index:      int
    offset:           int
    size:             int
    entropy:          float
    suspicious:       bool  = False
    # Chi-square test
    chi_square:       float = 0.0
    chi_p_value:      float = 1.0    # 1.0 = perfectly uniform
    chi_flag:         bool  = False  # True = statistically non-uniform at alpha
    # Compression test
    comp_ratio:       float = 1.0    # compressed_size / original_size; <1 = compressible
    comp_flag:        bool  = False  # True = incompressible (likely encrypted)
    # Sliding window peak
    sw_peak_entropy:  float = 0.0    # highest entropy found in any sub-window
    sw_peak_offset:   int   = 0      # relative byte offset of that sub-window
    # Combined verdict
    verdict:          str   = "—"    # "Encrypted", "Compressed", "Normal", "Structured"
    byte_freq:        dict  = field(default_factory=dict)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n    = len(data)
    freq = Counter(data)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 6)


def byte_frequency(data: bytes) -> dict:
    freq = Counter(data)
    return {b: freq.get(b, 0) for b in range(256)}


class EntropyCalculator:
    def __init__(self, store_byte_freq: bool = False):
        self.store_byte_freq = store_byte_freq
        self.results: List[BlockResult] = []

    def reset(self):
        self.results.clear()

    def process_block(self, block_index: int, data: bytes, block_size: int) -> BlockResult:
        result = BlockResult(
            block_index=block_index,
            offset=block_index * block_size,
            size=len(data),
            entropy=shannon_entropy(data),
            byte_freq=byte_frequency(data) if self.store_byte_freq else {},
        )
        self.results.append(result)
        return result

    def summary(self) -> dict:
        if not self.results:
            return {}
        ents = [r.entropy for r in self.results]
        susp = sum(1 for r in self.results if r.suspicious)
        enc  = sum(1 for r in self.results if r.verdict == "Encrypted")
        return {
            "total_blocks":      len(self.results),
            "suspicious_blocks": susp,
            "encrypted_blocks":  enc,
            "min_entropy":       round(min(ents), 6),
            "max_entropy":       round(max(ents), 6),
            "avg_entropy":       round(sum(ents) / len(ents), 6),
        }


# ═════════════════════════════════════════════════════════════════════════════
# Chi-Square Randomness Test
# ═════════════════════════════════════════════════════════════════════════════

class ChiSquareTest:
    """
    Tests whether the byte distribution of a block is consistent with a
    uniform distribution over all 256 byte values.

    Method:
      χ² = Σ (observed - expected)² / expected
      where expected = n / 256 for each byte value.

    The p-value is approximated using the regularized incomplete gamma
    function (stdlib only — no scipy needed).

    Interpretation:
      p < alpha  → distribution is NOT uniform → structured data (not random)
      p ≥ alpha  → distribution is uniform → consistent with random/encrypted

    A HIGH chi-square + HIGH entropy together strongly indicates encrypted data.
    A HIGH chi-square + LOW entropy indicates structured/patterned data.
    A LOW chi-square + HIGH entropy is the classic false-positive scenario
    (e.g. already-compressed data that still looks high-entropy) that this
    test helps catch by confirming uniformity.
    """

    # Critical χ² values for df=255 at common alpha levels (right-tail):
    # alpha=0.05 → 293.25, alpha=0.01 → 310.46, alpha=0.001 → 332.60
    # We store these as references but use the full p-value for flexibility.
    CHI2_CRIT_05  = 293.25
    CHI2_CRIT_01  = 310.46
    CHI2_CRIT_001 = 332.60

    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha   # significance level

    def test(self, data: bytes) -> Tuple[float, float, bool]:
        """
        Returns (chi_square, p_value, is_uniform).
        is_uniform=True  → fail to reject H₀ (looks random/uniform).
        is_uniform=False → reject H₀ (byte distribution is non-uniform).
        """
        n = len(data)
        if n < 256:
            return 0.0, 1.0, True   # too small to test

        freq     = Counter(data)
        expected = n / 256.0
        chi2     = sum(
            (freq.get(b, 0) - expected) ** 2 / expected
            for b in range(256)
        )
        p_value   = self._chi2_sf(chi2, df=255)
        is_uniform = p_value >= self.alpha
        return round(chi2, 4), round(p_value, 6), is_uniform

    # ── Pure-Python chi-squared survival function (P(X > x) for df=k) ───────
    # Uses the regularized upper incomplete gamma: Q(k/2, x/2)
    # Approximated via continued fraction (Lentz method) which converges
    # well for large x (typical for encrypted blocks).

    @staticmethod
    def _chi2_sf(x: float, df: int) -> float:
        """Survival function P(χ²_df > x). Returns value in [0, 1]."""
        if x <= 0:
            return 1.0
        a = df / 2.0
        z = x / 2.0
        return ChiSquareTest._gammaincc(a, z)

    @staticmethod
    def _gammaincc(a: float, x: float) -> float:
        """
        Regularized upper incomplete gamma Q(a, x) = 1 - P(a, x).
        Uses series expansion for x < a+1, continued fraction otherwise.
        Accurate to ~6 decimal places for typical forensic use.
        """
        if x < 0:
            return 1.0
        if x == 0:
            return 1.0
        try:
            log_gamma_a = ChiSquareTest._loggamma(a)
        except Exception:
            return 0.5

        if x < a + 1.0:
            # Series expansion for lower incomplete gamma → subtract from 1
            p = ChiSquareTest._gammaincl_series(a, x, log_gamma_a)
            return max(0.0, min(1.0, 1.0 - p))
        else:
            # Continued fraction for upper incomplete gamma
            cf = ChiSquareTest._gammaincl_cf(a, x, log_gamma_a)
            return max(0.0, min(1.0, cf))

    @staticmethod
    def _gammaincl_series(a: float, x: float, log_gamma_a: float) -> float:
        """Lower regularized incomplete gamma via series."""
        if x <= 0:
            return 0.0
        ap  = a
        s   = 1.0 / a
        delta = s
        for _ in range(300):
            ap += 1.0
            delta *= x / ap
            s += delta
            if abs(delta) < abs(s) * 1e-10:
                break
        return s * math.exp(-x + a * math.log(x) - log_gamma_a)

    @staticmethod
    def _gammaincl_cf(a: float, x: float, log_gamma_a: float) -> float:
        """Upper regularized incomplete gamma via Lentz continued fraction."""
        FPMIN = 1e-300
        b = x + 1.0 - a
        c = 1.0 / FPMIN
        d = 1.0 / b if b != 0 else 1.0 / FPMIN
        h = d
        for i in range(1, 301):
            an = -i * (i - a)
            b += 2.0
            d = an * d + b
            if abs(d) < FPMIN:
                d = FPMIN
            c = b + an / c
            if abs(c) < FPMIN:
                c = FPMIN
            d = 1.0 / d
            delta = d * c
            h *= delta
            if abs(delta - 1.0) < 1e-10:
                break
        return math.exp(-x + a * math.log(x) - log_gamma_a) * h

    @staticmethod
    def _loggamma(z: float) -> float:
        """Stirling-series log-gamma, accurate to ~12 significant figures."""
        c = [76.18009172947146, -86.50532032941677, 24.01409824083091,
             -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5]
        y = x = z
        tmp = x + 5.5
        tmp -= (x + 0.5) * math.log(tmp)
        ser = 1.000000000190015
        for ci in c:
            y += 1
            ser += ci / y
        return -tmp + math.log(2.5066282746310005 * ser / x)


# ═════════════════════════════════════════════════════════════════════════════
# Compression Test
# ═════════════════════════════════════════════════════════════════════════════

class CompressionTest:
    """
    Attempts to compress the block using zlib and measures the ratio:
        ratio = compressed_size / original_size

    Interpretation guide:
      ratio < 0.95  → data IS compressible → NOT encrypted (structured/plain)
      ratio ≥ 0.95  → data is NOT compressible → likely encrypted or already compressed
      ratio > 1.00  → data expanded (zlib overhead on truly random data)

    The threshold is configurable. The default 0.95 gives ~5% headroom for
    near-random data that still compresses very slightly.

    Note: Compressed file formats (ZIP, JPEG, MP4…) also produce high ratios.
    Use in combination with entropy and chi-square for accurate verdicts.
    """

    def __init__(self, threshold: float = 0.95, level: int = 6):
        self.threshold = threshold   # ratio above which block is flagged
        self.level     = level       # zlib compression level (1-9, 6=default)

    def test(self, data: bytes) -> Tuple[float, bool]:
        """
        Returns (ratio, is_incompressible).
        ratio            = compressed / original length
        is_incompressible= True if ratio >= threshold
        """
        n = len(data)
        if n == 0:
            return 1.0, False
        try:
            compressed = zlib.compress(data, self.level)
            ratio = len(compressed) / n
        except Exception:
            ratio = 1.0
        return round(ratio, 4), ratio >= self.threshold

    def batch_test(self, data: bytes, window_size: int = 0) -> float:
        """
        If window_size > 0, splits data into windows and returns the
        maximum compression ratio found (worst-case / most random sub-block).
        Otherwise tests the whole block.
        """
        if window_size <= 0 or window_size >= len(data):
            ratio, _ = self.test(data)
            return ratio
        ratios = []
        for i in range(0, len(data) - window_size + 1, window_size):
            r, _ = self.test(data[i:i + window_size])
            ratios.append(r)
        return max(ratios) if ratios else 1.0


# ═════════════════════════════════════════════════════════════════════════════
# Sliding Window Analyzer
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class WindowResult:
    window_index:  int
    block_index:   int           # parent block
    rel_offset:    int           # offset within block (bytes)
    abs_offset:    int           # absolute offset in image
    size:          int
    entropy:       float
    chi_square:    float = 0.0
    chi_p_value:   float = 1.0
    comp_ratio:    float = 1.0


class SlidingWindowAnalyzer:
    """
    Splits each block into overlapping sub-windows and runs full analysis
    (entropy + chi-square + compression) on each, enabling fine-grained
    detection of partially-encrypted blocks.

    Parameters:
      window_size : sub-window size in bytes (default: block_size // 4)
      step_size   : number of bytes to advance between windows
                    step < window_size → overlapping (more detail, slower)
                    step = window_size → non-overlapping (faster)

    A block with mixed content (e.g. half plaintext + half AES ciphertext)
    will look only "medium" entropy in block mode but reveal a clear spike
    in sliding window mode.
    """

    def __init__(self,
                 window_size: int = 128,
                 step_size: int   = 64,
                 chi_alpha: float = 0.05,
                 comp_threshold: float = 0.95):
        self.window_size     = max(16, window_size)
        self.step_size       = max(1,  step_size)
        self.chi_test        = ChiSquareTest(alpha=chi_alpha)
        self.comp_test       = CompressionTest(threshold=comp_threshold)
        self.window_results: List[WindowResult] = []

    def analyze_block(self, result: BlockResult, data: bytes) -> List[WindowResult]:
        """
        Runs sliding window analysis on `data` (the raw block bytes).
        Stores and returns WindowResult list for this block.
        Updates result.sw_peak_entropy and result.sw_peak_offset.
        """
        wins: List[WindowResult] = []
        n    = len(data)
        widx = 0
        peak_entropy = 0.0
        peak_offset  = 0

        for start in range(0, n - self.window_size + 1, self.step_size):
            win = data[start:start + self.window_size]
            ent = shannon_entropy(win)
            chi2, pval, _ = self.chi_test.test(win)
            ratio, _      = self.comp_test.test(win)

            wr = WindowResult(
                window_index = widx,
                block_index  = result.block_index,
                rel_offset   = start,
                abs_offset   = result.offset + start,
                size         = len(win),
                entropy      = ent,
                chi_square   = chi2,
                chi_p_value  = pval,
                comp_ratio   = ratio,
            )
            wins.append(wr)

            if ent > peak_entropy:
                peak_entropy = ent
                peak_offset  = start
            widx += 1

        result.sw_peak_entropy = round(peak_entropy, 6)
        result.sw_peak_offset  = peak_offset
        self.window_results.extend(wins)
        return wins

    def reset(self):
        self.window_results.clear()

    def windows_for_block(self, block_index: int) -> List[WindowResult]:
        return [w for w in self.window_results if w.block_index == block_index]


# ═════════════════════════════════════════════════════════════════════════════
# Verdict Engine — combines all three tests into a single label
# ═════════════════════════════════════════════════════════════════════════════

def compute_verdict(result: BlockResult, entropy_threshold: float = 7.0) -> str:
    """
    Combines Shannon entropy, chi-square test, and compression test to
    produce a human-readable verdict that minimises false positives.

    Decision matrix:
      High entropy + non-compressible + uniform distribution → "Encrypted"
      High entropy + compressible                           → "Compressed"
      High entropy + non-uniform distribution               → "High Entropy"
      Low entropy  + non-uniform                            → "Structured"
      Low entropy  + uniform                                → "Normal"
    """
    high_entropy   = result.entropy >= entropy_threshold
    incompressible = result.comp_flag      # ratio >= threshold
    uniform        = not result.chi_flag   # chi-square says uniform

    if high_entropy and incompressible and uniform:
        return "Encrypted"
    if high_entropy and incompressible and not uniform:
        # Looks random in entropy but chi says non-uniform → could be custom cipher
        return "Encrypted?"
    if high_entropy and not incompressible:
        return "Compressed"
    if not high_entropy and not uniform:
        return "Structured"
    return "Normal"


# ═════════════════════════════════════════════════════════════════════════════
# Threshold Detection
# ═════════════════════════════════════════════════════════════════════════════

class ThresholdDetector:
    def __init__(self, threshold: float = 7.0):
        self.threshold = threshold
        self.flagged:  List[BlockResult] = []

    def flag_block(self, result: BlockResult) -> bool:
        if result.entropy > self.threshold:
            result.suspicious = True
            self.flagged.append(result)
        else:
            result.suspicious = False
        return result.suspicious

    def apply(self, results: List[BlockResult]):
        self.flagged.clear()
        for r in results:
            self.flag_block(r)

    def summary(self) -> dict:
        return {
            "threshold":      self.threshold,
            "flagged_blocks": len(self.flagged),
        }


# ═════════════════════════════════════════════════════════════════════════════
# Region Aggregation
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class EntropyRegion:
    region_id:    int
    start_block:  int
    end_block:    int
    start_offset: int
    end_offset:   int
    total_bytes:  int
    block_count:  int
    avg_entropy:  float
    max_entropy:  float
    verdict:      str  = "—"
    is_noise:     bool = False

    @property
    def size_label(self) -> str:
        n = self.total_bytes
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"

    @property
    def offset_range(self) -> str:
        return f"0x{self.start_offset:08X} – 0x{self.end_offset:08X}"


class RegionAggregator:
    def __init__(self, min_region_bytes: int = 4096):
        self.min_region_bytes = min_region_bytes
        self.regions: List[EntropyRegion] = []

    def build(self, results: List[BlockResult]) -> List[EntropyRegion]:
        self.regions.clear()
        if not results:
            return []
        region_id = 0
        in_region = False
        buf: List[BlockResult] = []

        def flush():
            nonlocal region_id
            if not buf:
                return
            total = sum(b.size for b in buf)
            entrs = [b.entropy for b in buf]
            # Dominant verdict in region
            vdict = Counter(b.verdict for b in buf if b.verdict != "Normal")
            dom_verdict = vdict.most_common(1)[0][0] if vdict else "Normal"
            region = EntropyRegion(
                region_id    = region_id,
                start_block  = buf[0].block_index,
                end_block    = buf[-1].block_index,
                start_offset = buf[0].offset,
                end_offset   = buf[-1].offset,
                total_bytes  = total,
                block_count  = len(buf),
                avg_entropy  = round(sum(entrs) / len(entrs), 6),
                max_entropy  = round(max(entrs), 6),
                verdict      = dom_verdict,
                is_noise     = total < self.min_region_bytes,
            )
            self.regions.append(region)
            region_id += 1
            buf.clear()

        for r in results:
            if r.suspicious:
                buf.append(r)
                in_region = True
            else:
                if in_region:
                    flush()
                    in_region = False
        if in_region:
            flush()
        return [r for r in self.regions if not r.is_noise]

    @property
    def significant_regions(self) -> List[EntropyRegion]:
        return [r for r in self.regions if not r.is_noise]

    @property
    def noise_regions(self) -> List[EntropyRegion]:
        return [r for r in self.regions if r.is_noise]

    def summary(self) -> dict:
        sig = self.significant_regions
        return {
            "total_regions":        len(self.regions),
            "significant_regions":  len(sig),
            "noise_regions":        len(self.noise_regions),
            "min_region_bytes":     self.min_region_bytes,
            "largest_region_bytes": max((r.total_bytes for r in sig), default=0),
        }


# ═════════════════════════════════════════════════════════════════════════════
# Risk Scorer
# ═════════════════════════════════════════════════════════════════════════════

def compute_risk_score(region: EntropyRegion,
                       blocks: List[BlockResult]) -> float:
    """
    Compute a 0–100 risk score for a suspicious region.

    Scoring components (weighted sum):
      ① Avg entropy proximity to 8.0        (0–35 pts)
      ② Fraction of blocks with Encrypted verdict (0–25 pts)
      ③ Average compression ratio           (0–20 pts)  — higher = riskier
      ④ Chi-square uniformity fraction      (0–10 pts)  — more uniform = riskier
      ⑤ SW peak entropy delta               (0–10 pts)  — peaks above block avg

    Returns a float in [0.0, 100.0].
    """
    region_blocks = [b for b in blocks
                     if region.start_block <= b.block_index <= region.end_block]
    if not region_blocks:
        return 0.0

    n = len(region_blocks)

    # ① Entropy score: how close average entropy is to maximum (8.0)
    ent_score = min(35.0, (region.avg_entropy / 8.0) * 35.0)

    # ② Encrypted verdict fraction
    enc_frac  = sum(1 for b in region_blocks
                    if "Encrypted" in b.verdict) / n
    enc_score = enc_frac * 25.0

    # ③ Average compression ratio (0→0 pts, 1→20 pts)
    avg_ratio = sum(b.comp_ratio for b in region_blocks) / n
    comp_score = min(20.0, avg_ratio * 20.0)

    # ④ Chi-square uniformity: fraction of uniform (p ≥ α) blocks
    #    More uniform blocks → more random → higher risk
    uniform_frac = sum(1 for b in region_blocks if not b.chi_flag) / n
    chi_score = uniform_frac * 10.0

    # ⑤ Sliding window peak bonus: if peaks significantly exceed block entropy
    sw_deltas = [max(0.0, b.sw_peak_entropy - b.entropy) for b in region_blocks]
    avg_delta = sum(sw_deltas) / n
    sw_score  = min(10.0, (avg_delta / 1.0) * 10.0)

    total = ent_score + enc_score + comp_score + chi_score + sw_score
    return round(min(100.0, total), 1)


def risk_label(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "MINIMAL"


def risk_color(score: float) -> str:
    if score >= 80: return "#ff5555"
    if score >= 60: return "#ff79c6"
    if score >= 40: return "#ffb86c"
    if score >= 20: return "#f1fa8c"
    return "#50fa7b"


# ═════════════════════════════════════════════════════════════════════════════
# GUI
# ═════════════════════════════════════════════════════════════════════════════

DARK_BG    = "#0d1117"
PANEL_BG   = "#161b22"
ACCENT     = "#58a6ff"
ACCENT2    = "#f78166"
TEXT       = "#e6edf3"
MUTED      = "#8b949e"
SUCCESS    = "#3fb950"
WARNING    = "#d29922"
BORDER     = "#30363d"
E01_CLR    = "#bc8cff"
SUSP_CLR   = "#ff6e6e"
REGION_CLR = "#ffa657"
ENC_CLR    = "#ff79c6"    # encrypted verdict
COMP_CLR   = "#8be9fd"    # compressed verdict
CHI_CLR    = "#ffb86c"    # chi-square highlight
SW_CLR     = "#50fa7b"    # sliding window peak
RISK_CRIT  = "#ff5555"    # critical risk
RISK_HIGH  = "#ff79c6"    # high risk
RISK_MED   = "#ffb86c"    # medium risk
RISK_LOW   = "#f1fa8c"    # low risk
AXIS_CLR   = "#444c56"    # chart axis / grid lines


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Disk Entropy Analyzer")
        self.geometry("1400x960")
        self.configure(bg=DARK_BG)
        self.resizable(True, True)

        # Core modules
        self._calculator   = EntropyCalculator()
        self._chi_test     = ChiSquareTest()
        self._comp_test    = CompressionTest()
        self._sw_analyzer  = SlidingWindowAnalyzer()
        self._detector     = ThresholdDetector()
        self._aggregator   = RegionAggregator()
        self._stop_flag    = threading.Event()
        self._risk_scores: Dict[int, float] = {}   # region_id → score

        # StringVars / DoubleVars
        self._file_path    = tk.StringVar(value="No file selected")
        self._file_type    = tk.StringVar(value="")
        self._block_size   = tk.IntVar(value=512)
        self._store_freq   = tk.BooleanVar(value=False)
        self._status       = tk.StringVar(value="Ready")
        self._progress     = tk.DoubleVar(value=0.0)
        self._meta_var     = tk.StringVar(value="")
        self._threshold    = tk.DoubleVar(value=7.0)
        self._min_region_kb= tk.DoubleVar(value=4.0)
        self._show_susp    = tk.BooleanVar(value=True)
        self._show_regions = tk.BooleanVar(value=True)
        # New test toggles
        self._use_chi      = tk.BooleanVar(value=True)
        self._use_comp     = tk.BooleanVar(value=True)
        self._use_sw       = tk.BooleanVar(value=True)
        self._chi_alpha    = tk.DoubleVar(value=0.05)
        self._comp_thresh  = tk.DoubleVar(value=0.95)
        self._sw_window    = tk.IntVar(value=128)
        self._sw_step      = tk.IntVar(value=64)
        # Internal state
        self._raw_blocks: Dict[int, bytes] = {}   # block_index → raw bytes cache for SW

        self._build_ui()
        self._style_widgets()

        self._threshold.trace_add("write", self._on_threshold_change)
        self._min_region_kb.trace_add("write", self._on_threshold_change)

    # ─────────────────────────────────────────────────────────────────────────
    # UI Build
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        hdr = tk.Frame(self, bg=PANEL_BG, pady=7)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="⬡  DISK ENTROPY ANALYZER",
                 font=("Courier New", 14, "bold"), bg=PANEL_BG, fg=ACCENT).pack(side=tk.LEFT, padx=16)
        tk.Label(hdr, text="Shannon · χ² · Compression · Sliding Window · Heatmap · Histogram · Risk Report  |  Raw / E01",
                 font=("Courier New", 8), bg=PANEL_BG, fg=MUTED).pack(side=tk.LEFT, padx=4)

        main = tk.Frame(self, bg=DARK_BG)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        main.columnconfigure(0, weight=3)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(1, weight=2)
        main.rowconfigure(2, weight=1)

        self._build_controls(main)
        self._build_block_table(main)
        self._build_viz_panel(main)
        self._build_region_table(main)
        self._build_statusbar()

    # ── Controls ─────────────────────────────────────────────────────────────

    def _build_controls(self, p):
        ctrl = tk.LabelFrame(p, text=" Configuration ", bg=PANEL_BG, fg=ACCENT,
                             font=("Courier New", 10, "bold"), bd=1, relief=tk.FLAT)
        ctrl.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))

        # ── File row
        fr = tk.Frame(ctrl, bg=PANEL_BG)
        fr.pack(fill=tk.X, padx=10, pady=4)
        tk.Label(fr, text="Image File:", bg=PANEL_BG, fg=TEXT,
                 font=("Courier New", 9, "bold"), width=14, anchor="w").pack(side=tk.LEFT)
        tk.Label(fr, textvariable=self._file_path, bg=PANEL_BG, fg=ACCENT2,
                 font=("Courier New", 9), anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._type_badge = tk.Label(fr, textvariable=self._file_type, bg=PANEL_BG,
                                     fg=E01_CLR, font=("Courier New", 9, "bold"))
        self._type_badge.pack(side=tk.LEFT, padx=6)
        tk.Button(fr, text="Browse…", command=self._browse_file,
                  bg=ACCENT, fg=DARK_BG, font=("Courier New", 9, "bold"),
                  relief=tk.FLAT, padx=10, cursor="hand2").pack(side=tk.RIGHT, padx=4)

        # ── Meta row
        mr = tk.Frame(ctrl, bg=PANEL_BG)
        mr.pack(fill=tk.X, padx=10, pady=(0, 2))
        tk.Label(mr, text="Image Info:", bg=PANEL_BG, fg=TEXT,
                 font=("Courier New", 9, "bold"), width=14, anchor="w").pack(side=tk.LEFT)
        tk.Label(mr, textvariable=self._meta_var, bg=PANEL_BG, fg=E01_CLR,
                 font=("Courier New", 8)).pack(side=tk.LEFT)

        # ── Two-column param area
        prow = tk.Frame(ctrl, bg=PANEL_BG)
        prow.pack(fill=tk.X, padx=10, pady=2)
        left  = tk.Frame(prow, bg=PANEL_BG)
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        right = tk.Frame(prow, bg=PANEL_BG)
        right.pack(side=tk.RIGHT, padx=(16, 0))

        # Block size (left)
        br = tk.Frame(left, bg=PANEL_BG)
        br.pack(fill=tk.X, pady=1)
        tk.Label(br, text="Block Size:", bg=PANEL_BG, fg=TEXT,
                 font=("Courier New", 9, "bold"), width=14, anchor="w").pack(side=tk.LEFT)
        for lbl, val in [("512B",512),("1KB",1024),("4KB",4096),
                          ("16KB",16384),("64KB",65536),("1MB",1048576)]:
            tk.Button(br, text=lbl, command=lambda v=val: self._block_size.set(v),
                      bg=BORDER, fg=TEXT, font=("Courier New", 8),
                      relief=tk.FLAT, padx=4, cursor="hand2").pack(side=tk.LEFT, padx=1)
        tk.Entry(br, textvariable=self._block_size, width=7,
                 bg="#21262d", fg=TEXT, insertbackground=TEXT,
                 font=("Courier New", 8), relief=tk.FLAT).pack(side=tk.LEFT, padx=(6, 2))
        tk.Label(br, text="B", bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 8)).pack(side=tk.LEFT)

        # Threshold (right)
        def _slider_row(parent, label, color, var, from_, to_, res, unit, width=130):
            row = tk.Frame(parent, bg=PANEL_BG)
            row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=label, bg=PANEL_BG, fg=color,
                     font=("Courier New", 8, "bold"), width=20, anchor="w").pack(side=tk.LEFT)
            sl = tk.Scale(row, variable=var, from_=from_, to=to_, resolution=res,
                          orient=tk.HORIZONTAL, length=width,
                          bg=PANEL_BG, fg=color, troughcolor=BORDER,
                          highlightthickness=0, showvalue=False, cursor="hand2",
                          command=lambda _: lbl_val.config(text=f"{var.get():.2f}{unit}"))
            sl.pack(side=tk.LEFT)
            lbl_val = tk.Label(row, text=f"{var.get():.2f}{unit}", bg=PANEL_BG, fg=color,
                               font=("Courier New", 8, "bold"), width=7)
            lbl_val.pack(side=tk.LEFT, padx=2)
            return sl

        _slider_row(right, "⚠ Ent. Threshold:", SUSP_CLR,   self._threshold,     0.0, 8.0,  0.05, "")
        _slider_row(right, "⬡ Min Region:",     REGION_CLR, self._min_region_kb, 0.5, 512., 0.5,  " KB")

        # ── Tests panel (three columns)
        tests = tk.LabelFrame(ctrl, text=" Analysis Tests ", bg=PANEL_BG, fg=ACCENT,
                               font=("Courier New", 8, "bold"), bd=1, relief=tk.FLAT)
        tests.pack(fill=tk.X, padx=10, pady=4)

        def _test_col(parent, title, color):
            f = tk.Frame(parent, bg=PANEL_BG)
            f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=4)
            tk.Label(f, text=title, bg=PANEL_BG, fg=color,
                     font=("Courier New", 9, "bold")).pack(anchor="w")
            return f

        # Chi-square column
        chi_col = _test_col(tests, "χ² Randomness Test", CHI_CLR)
        cr = tk.Frame(chi_col, bg=PANEL_BG); cr.pack(fill=tk.X, pady=1)
        tk.Checkbutton(cr, text="Enable", variable=self._use_chi,
                       bg=PANEL_BG, fg=CHI_CLR, selectcolor=PANEL_BG,
                       activebackground=PANEL_BG,
                       font=("Courier New", 8)).pack(side=tk.LEFT)
        tk.Label(cr, text="α:", bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 8)).pack(side=tk.LEFT, padx=(8, 2))
        tk.Entry(cr, textvariable=self._chi_alpha, width=5,
                 bg="#21262d", fg=CHI_CLR, insertbackground=TEXT,
                 font=("Courier New", 8), relief=tk.FLAT).pack(side=tk.LEFT)
        tk.Label(chi_col,
                 text="Tests if byte distribution\nis uniform (random-like).\nHigh χ² + low p → structured.",
                 bg=PANEL_BG, fg=MUTED, font=("Courier New", 7),
                 justify=tk.LEFT).pack(anchor="w")

        # Compression column
        cmp_col = _test_col(tests, "Compression Ratio Test", COMP_CLR)
        cpr = tk.Frame(cmp_col, bg=PANEL_BG); cpr.pack(fill=tk.X, pady=1)
        tk.Checkbutton(cpr, text="Enable", variable=self._use_comp,
                       bg=PANEL_BG, fg=COMP_CLR, selectcolor=PANEL_BG,
                       activebackground=PANEL_BG,
                       font=("Courier New", 8)).pack(side=tk.LEFT)
        tk.Label(cpr, text="Thresh:", bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 8)).pack(side=tk.LEFT, padx=(6, 2))
        tk.Entry(cpr, textvariable=self._comp_thresh, width=5,
                 bg="#21262d", fg=COMP_CLR, insertbackground=TEXT,
                 font=("Courier New", 8), relief=tk.FLAT).pack(side=tk.LEFT)
        tk.Label(cmp_col,
                 text="ratio = compressed/original.\nratio ≥ thresh → incompressible\n→ likely encrypted.",
                 bg=PANEL_BG, fg=MUTED, font=("Courier New", 7),
                 justify=tk.LEFT).pack(anchor="w")

        # Sliding window column
        sw_col = _test_col(tests, "Sliding Window Mode", SW_CLR)
        swr = tk.Frame(sw_col, bg=PANEL_BG); swr.pack(fill=tk.X, pady=1)
        tk.Checkbutton(swr, text="Enable", variable=self._use_sw,
                       bg=PANEL_BG, fg=SW_CLR, selectcolor=PANEL_BG,
                       activebackground=PANEL_BG,
                       font=("Courier New", 8)).pack(side=tk.LEFT)
        tk.Label(swr, text="Win:", bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 8)).pack(side=tk.LEFT, padx=(6, 2))
        tk.Entry(swr, textvariable=self._sw_window, width=5,
                 bg="#21262d", fg=SW_CLR, insertbackground=TEXT,
                 font=("Courier New", 8), relief=tk.FLAT).pack(side=tk.LEFT)
        tk.Label(swr, text="Step:", bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 8)).pack(side=tk.LEFT, padx=(4, 2))
        tk.Entry(swr, textvariable=self._sw_step, width=5,
                 bg="#21262d", fg=SW_CLR, insertbackground=TEXT,
                 font=("Courier New", 8), relief=tk.FLAT).pack(side=tk.LEFT)
        tk.Label(sw_col,
                 text="Overlapping sub-windows for\nfine-grained detection of\nmixed-content blocks.",
                 bg=PANEL_BG, fg=MUTED, font=("Courier New", 7),
                 justify=tk.LEFT).pack(anchor="w")

        # ── Visibility + misc checkboxes
        vrow = tk.Frame(ctrl, bg=PANEL_BG)
        vrow.pack(fill=tk.X, padx=10, pady=(0, 2))
        for text, var in [("Highlight suspicious", self._show_susp),
                           ("Region overlays", self._show_regions),
                           ("Store byte freq", self._store_freq)]:
            tk.Checkbutton(vrow, text=text, variable=var,
                           command=self._redraw,
                           bg=PANEL_BG, fg=MUTED, selectcolor=PANEL_BG,
                           activebackground=PANEL_BG,
                           font=("Courier New", 8)).pack(side=tk.LEFT, padx=6)

        # ── Action buttons
        ab = tk.Frame(ctrl, bg=PANEL_BG)
        ab.pack(fill=tk.X, padx=10, pady=4)
        self._btn_analyze = tk.Button(ab, text="▶  Analyze", command=self._start,
                                      bg=SUCCESS, fg=DARK_BG,
                                      font=("Courier New", 10, "bold"),
                                      relief=tk.FLAT, padx=14, cursor="hand2")
        self._btn_analyze.pack(side=tk.LEFT, padx=(0, 6))
        self._btn_stop = tk.Button(ab, text="■  Stop", command=self._stop,
                                   bg=ACCENT2, fg=DARK_BG,
                                   font=("Courier New", 10, "bold"),
                                   relief=tk.FLAT, padx=14, cursor="hand2",
                                   state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=(0, 6))
        for lbl, cmd in [("Blocks CSV", self._export_csv),
                          ("Regions CSV", self._export_regions_csv),
                          ("Windows CSV", self._export_windows_csv),
                          ("JSON", self._export_json)]:
            tk.Button(ab, text=lbl, command=cmd, bg=BORDER, fg=TEXT,
                      font=("Courier New", 8), relief=tk.FLAT,
                      padx=7, cursor="hand2").pack(side=tk.LEFT, padx=(0, 3))

        self._pbar = ttk.Progressbar(ctrl, variable=self._progress,
                                     maximum=100, mode="determinate")
        self._pbar.pack(fill=tk.X, padx=10, pady=(2, 5))

    # ── Block Results Table ───────────────────────────────────────────────────

    def _build_block_table(self, p):
        frame = tk.LabelFrame(p, text=" Block Results ", bg=PANEL_BG, fg=ACCENT,
                              font=("Courier New", 10, "bold"), bd=1, relief=tk.FLAT)
        frame.grid(row=1, column=0, sticky="nsew", padx=(0, 6))

        cols = ("block","offset","entropy","chi2","pval","ratio","sw_peak","verdict","flag")
        self._block_tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        hdrs = {
            "block":   "Block #",
            "offset":  "Offset",
            "entropy": "Entropy",
            "chi2":    "χ²",
            "pval":    "p-value",
            "ratio":   "Comp Ratio",
            "sw_peak": "SW Peak",
            "verdict": "Verdict",
            "flag":    "⚠",
        }
        wids = {
            "block":60,"offset":105,"entropy":85,"chi2":80,"pval":75,
            "ratio":80,"sw_peak":75,"verdict":105,"flag":40
        }
        for c in cols:
            self._block_tree.heading(c, text=hdrs[c])
            self._block_tree.column(c, width=wids[c], anchor="center")

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._block_tree.yview)
        self._block_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._block_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Detail panel below table for sliding window view
        detail = tk.Frame(frame, bg=PANEL_BG)
        detail.pack(fill=tk.X, padx=4, pady=(0, 4))
        self._block_summary = tk.StringVar(value="—")
        tk.Label(detail, textvariable=self._block_summary, bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 7), anchor="w").pack(fill=tk.X)

        # Bind selection → show SW detail in status
        self._block_tree.bind("<<TreeviewSelect>>", self._on_block_select)

    # ── Visualization Panel (tabbed: Heatmap | Histogram | Report) ───────────

    def _build_viz_panel(self, p):
        outer = tk.LabelFrame(p, text=" Visualization ", bg=PANEL_BG, fg=ACCENT,
                              font=("Courier New", 10, "bold"), bd=1, relief=tk.FLAT)
        outer.grid(row=1, column=1, rowspan=2, sticky="nsew")

        # Tab bar (manual, no ttk.Notebook — gives us full colour control)
        tab_bar = tk.Frame(outer, bg=PANEL_BG)
        tab_bar.pack(fill=tk.X, padx=4, pady=(4, 0))

        self._viz_frames: Dict[str, tk.Frame] = {}
        self._viz_tab_btns: Dict[str, tk.Button] = {}
        self._active_tab = tk.StringVar(value="heatmap")

        for key, label in [("heatmap", "⬡ Heatmap"), ("histogram", "▦ Histogram"), ("report", "⚑ Report")]:
            f = tk.Frame(outer, bg=DARK_BG)
            self._viz_frames[key] = f
            btn = tk.Button(tab_bar, text=label,
                            command=lambda k=key: self._switch_viz_tab(k),
                            bg=BORDER, fg=MUTED,
                            font=("Courier New", 8, "bold"),
                            relief=tk.FLAT, padx=10, pady=3, cursor="hand2")
            btn.pack(side=tk.LEFT, padx=(0, 2))
            self._viz_tab_btns[key] = btn

        # ── HEATMAP tab ──────────────────────────────────────────────────────
        hm_frame = self._viz_frames["heatmap"]

        # Canvas for the actual heatmap
        self._heatmap_canvas = tk.Canvas(hm_frame, bg=DARK_BG, highlightthickness=0)
        self._heatmap_canvas.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._heatmap_canvas.bind("<Configure>", lambda e: self._draw_heatmap())
        self._heatmap_canvas.bind("<Motion>",    self._on_heatmap_hover)
        self._heatmap_canvas.bind("<Leave>",     lambda e: self._status.set(""))

        # Legend strip
        hm_leg = tk.Frame(hm_frame, bg=PANEL_BG)
        hm_leg.pack(fill=tk.X, padx=6, pady=(0, 3))
        for lbl, col in [("Normal", SUCCESS), ("Medium", WARNING), ("High", ACCENT),
                          ("Enc/Rand", ACCENT2), ("⚠ Susp", SUSP_CLR),
                          ("Encrypted", ENC_CLR), ("Compressed", COMP_CLR),
                          ("⬡ Region", REGION_CLR), ("SW peak", SW_CLR)]:
            tk.Label(hm_leg, text="█ "+lbl, bg=PANEL_BG, fg=col,
                     font=("Courier New", 6)).pack(side=tk.LEFT, padx=2)

        # ── HISTOGRAM tab ────────────────────────────────────────────────────
        hi_frame = self._viz_frames["histogram"]

        # Controls row
        hc_row = tk.Frame(hi_frame, bg=DARK_BG)
        hc_row.pack(fill=tk.X, padx=6, pady=3)
        tk.Label(hc_row, text="Bins:", bg=DARK_BG, fg=MUTED,
                 font=("Courier New", 8)).pack(side=tk.LEFT)
        self._hist_bins = tk.IntVar(value=32)
        tk.Scale(hc_row, variable=self._hist_bins, from_=8, to=128,
                 resolution=1, orient=tk.HORIZONTAL, length=120,
                 bg=DARK_BG, fg=ACCENT, troughcolor=BORDER,
                 highlightthickness=0, showvalue=True,
                 command=lambda _: self._draw_histogram()).pack(side=tk.LEFT, padx=4)
        self._hist_mode = tk.StringVar(value="entropy")
        for val, lbl in [("entropy","Entropy"), ("comp","Comp Ratio"), ("chi","χ² stat")]:
            tk.Radiobutton(hc_row, text=lbl, variable=self._hist_mode, value=val,
                           command=self._draw_histogram,
                           bg=DARK_BG, fg=MUTED, selectcolor=DARK_BG,
                           activebackground=DARK_BG,
                           font=("Courier New", 8)).pack(side=tk.LEFT, padx=4)

        self._histogram_canvas = tk.Canvas(hi_frame, bg=DARK_BG, highlightthickness=0)
        self._histogram_canvas.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self._histogram_canvas.bind("<Configure>", lambda e: self._draw_histogram())
        self._histogram_canvas.bind("<Motion>",    self._on_histogram_hover)
        self._histogram_canvas.bind("<Leave>",     lambda e: self._status.set(""))

        # ── REPORT tab ───────────────────────────────────────────────────────
        rp_frame = self._viz_frames["report"]

        # Toolbar
        rp_tb = tk.Frame(rp_frame, bg=DARK_BG)
        rp_tb.pack(fill=tk.X, padx=6, pady=3)
        tk.Button(rp_tb, text="⟳ Refresh", command=self._refresh_report,
                  bg=BORDER, fg=TEXT, font=("Courier New", 8),
                  relief=tk.FLAT, padx=8, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(rp_tb, text="Export Report TXT", command=self._export_report_txt,
                  bg=BORDER, fg=TEXT, font=("Courier New", 8),
                  relief=tk.FLAT, padx=8, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(rp_tb, text="Export Report JSON", command=self._export_report_json,
                  bg=BORDER, fg=TEXT, font=("Courier New", 8),
                  relief=tk.FLAT, padx=8, cursor="hand2").pack(side=tk.LEFT)

        # Scrollable text report
        rp_inner = tk.Frame(rp_frame, bg=DARK_BG)
        rp_inner.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        rp_vsb = ttk.Scrollbar(rp_inner, orient=tk.VERTICAL)
        rp_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._report_text = tk.Text(rp_inner, bg="#0a0e14", fg=TEXT,
                                     font=("Courier New", 8),
                                     relief=tk.FLAT, wrap=tk.NONE,
                                     yscrollcommand=rp_vsb.set,
                                     state=tk.DISABLED)
        rp_hsb = ttk.Scrollbar(rp_inner, orient=tk.HORIZONTAL,
                                command=self._report_text.xview)
        rp_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._report_text.configure(xscrollcommand=rp_hsb.set)
        self._report_text.pack(fill=tk.BOTH, expand=True)
        rp_vsb.config(command=self._report_text.yview)

        # Configure text tags for report colours
        for tag, fg in [
            ("heading",   ACCENT),
            ("subhead",   REGION_CLR),
            ("critical",  RISK_CRIT),
            ("high",      RISK_HIGH),
            ("medium",    RISK_MED),
            ("low",       RISK_LOW),
            ("ok",        SUCCESS),
            ("muted",     MUTED),
            ("enc",       ENC_CLR),
            ("comp",      COMP_CLR),
            ("val",       TEXT),
        ]:
            self._report_text.tag_configure(tag, foreground=fg)

        # Activate first tab
        self._switch_viz_tab("heatmap")

    def _switch_viz_tab(self, key: str):
        for k, f in self._viz_frames.items():
            f.pack_forget()
        self._viz_frames[key].pack(fill=tk.BOTH, expand=True)
        for k, btn in self._viz_tab_btns.items():
            btn.configure(bg=ACCENT if k == key else BORDER,
                          fg=DARK_BG if k == key else MUTED)
        self._active_tab.set(key)
        # Trigger redraw for the newly visible tab
        if key == "heatmap":
            self._draw_heatmap()
        elif key == "histogram":
            self._draw_histogram()
        elif key == "report":
            self._refresh_report()

    # ── Regions Table ─────────────────────────────────────────────────────────

    def _build_region_table(self, p):
        frame = tk.LabelFrame(p, text=" High-Entropy Regions ", bg=PANEL_BG, fg=REGION_CLR,
                              font=("Courier New", 10, "bold"), bd=1, relief=tk.FLAT)
        frame.grid(row=2, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))
        cols = ("rid","start_blk","end_blk","offset_range","size","blocks",
                "avg_ent","max_ent","verdict","noise")
        self._region_tree = ttk.Treeview(frame, columns=cols, show="headings",
                                          selectmode="browse", height=5)
        hdrs = {"rid":"ID","start_blk":"Start","end_blk":"End",
                "offset_range":"Offset Range","size":"Size","blocks":"Blocks",
                "avg_ent":"Avg Ent","max_ent":"Max Ent",
                "verdict":"Verdict","noise":"Noise?"}
        wids = {"rid":30,"start_blk":60,"end_blk":60,"offset_range":195,"size":75,
                "blocks":55,"avg_ent":75,"max_ent":75,"verdict":90,"noise":50}
        for c in cols:
            self._region_tree.heading(c, text=hdrs[c])
            self._region_tree.column(c, width=wids[c], anchor="center")
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._region_tree.yview)
        self._region_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._region_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._region_summary = tk.StringVar(value="—")
        tk.Label(frame, textvariable=self._region_summary, bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 7), anchor="w").pack(fill=tk.X, padx=6, pady=(0, 3))
        self._region_tree.bind("<<TreeviewSelect>>", self._on_region_select)

    def _build_statusbar(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill=tk.X)
        sb = tk.Frame(self, bg=PANEL_BG, pady=3)
        sb.pack(fill=tk.X)
        tk.Label(sb, textvariable=self._status, bg=PANEL_BG, fg=MUTED,
                 font=("Courier New", 8), anchor="w").pack(side=tk.LEFT, padx=10)

    def _style_widgets(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview", background=PANEL_BG, foreground=TEXT,
                    fieldbackground=PANEL_BG, rowheight=20,
                    font=("Courier New", 8))
        s.configure("Treeview.Heading", background=BORDER, foreground=ACCENT,
                    font=("Courier New", 8, "bold"))
        s.map("Treeview", background=[("selected", "#1f6feb")])
        s.configure("TProgressbar", troughcolor=BORDER, background=ACCENT,
                    darkcolor=ACCENT, lightcolor=ACCENT)
        for tag, col in [
            ("low", SUCCESS), ("medium", WARNING), ("high", ACCENT),
            ("encrypted_ent", ACCENT2), ("suspicious", SUSP_CLR),
            ("verdict_enc", ENC_CLR), ("verdict_comp", COMP_CLR),
            ("verdict_high", ACCENT), ("verdict_struct", WARNING),
        ]:
            self._block_tree.tag_configure(tag, foreground=col)
        self._region_tree.tag_configure("significant", foreground=REGION_CLR)
        self._region_tree.tag_configure("encrypted",   foreground=ENC_CLR)
        self._region_tree.tag_configure("noise",       foreground=MUTED)

    # ─────────────────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[
                ("All Supported", "*.E01 *.e01 *.Ex01 *.ex01 *.Lx01 *.lx01 "
                                  "*.dd *.img *.raw *.bin *.iso"),
                ("EnCase E01",    "*.E01 *.e01 *.Ex01 *.ex01 *.Lx01 *.lx01"),
                ("Raw Images",    "*.dd *.img *.raw *.bin *.iso"),
                ("All Files",     "*.*"),
            ]
        )
        if not path:
            return
        self._file_path.set(path)
        ext = os.path.splitext(path)[1].lower()
        if ext in (".e01", ".ex01", ".lx01"):
            self._file_type.set("[E01]")
            self._type_badge.configure(fg=E01_CLR)
            threading.Thread(target=self._load_e01_meta, args=(path,), daemon=True).start()
        else:
            self._file_type.set("[RAW]")
            self._type_badge.configure(fg=MUTED)
            self._meta_var.set(f"Size: {self._hsize(os.path.getsize(path))}")
        self._status.set(f"Loaded: {os.path.basename(path)}")

    def _load_e01_meta(self, path: str):
        try:
            r = E01Reader(path, 512)
            m = r.get_metadata(); r.close()
            parts = [
                f"Segments: {m.get('segments','?')}",
                f"Chunk: {self._hsize(m.get('chunk_size',0))}",
                f"Total: {self._hsize(m.get('total_bytes',0))}",
            ]
            if "header_text" in m:
                lines = [l.strip() for l in
                         m["header_text"].replace("\r","\n").split("\n") if l.strip()]
                if len(lines) > 1:
                    parts.append(f"Case: {lines[1][:40]}")
            self.after(0, self._meta_var.set, "  |  ".join(parts))
        except Exception as e:
            self.after(0, self._meta_var.set, f"Metadata error: {e}")

    def _start(self):
        path = self._file_path.get()
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid disk image file.")
            return
        try:
            bs = int(self._block_size.get())
            assert bs > 0
        except Exception:
            messagebox.showerror("Error", "Block size must be a positive integer.")
            return

        # Re-initialise all modules with current settings
        self._calculator  = EntropyCalculator(self._store_freq.get())
        self._chi_test    = ChiSquareTest(alpha=self._chi_alpha.get())
        self._comp_test   = CompressionTest(threshold=self._comp_thresh.get())
        self._sw_analyzer = SlidingWindowAnalyzer(
            window_size=self._sw_window.get(),
            step_size=self._sw_step.get(),
            chi_alpha=self._chi_alpha.get(),
            comp_threshold=self._comp_thresh.get(),
        )
        self._detector    = ThresholdDetector(self._threshold.get())
        self._aggregator  = RegionAggregator(int(self._min_region_kb.get() * 1024))
        self._raw_blocks  = {}

        for tree in (self._block_tree, self._region_tree):
            for item in tree.get_children():
                tree.delete(item)
        self._heatmap_canvas.delete("all")
        self._histogram_canvas.delete("all")
        self._risk_scores = {}
        self._progress.set(0)
        self._block_summary.set("—")
        self._region_summary.set("—")
        self._stop_flag.clear()
        self._btn_analyze.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)

        threading.Thread(target=self._run, args=(path, bs), daemon=True).start()

    def _stop(self):
        self._stop_flag.set()
        self._status.set("Stopping…")

    def _run(self, path: str, bs: int):
        use_chi  = self._use_chi.get()
        use_comp = self._use_comp.get()
        use_sw   = self._use_sw.get()
        thresh   = self._threshold.get()

        try:
            reader = open_image(path, bs)
            total  = reader.total_blocks
            self.after(0, self._status.set,
                       f"Analyzing {os.path.basename(path)} — ~{total} blocks × {bs} B")

            for bidx, data in reader.stream_blocks():
                if self._stop_flag.is_set():
                    break

                # 1. Entropy
                result = self._calculator.process_block(bidx, data, bs)

                # 2. Chi-square
                if use_chi:
                    chi2, pval, is_uniform = self._chi_test.test(data)
                    result.chi_square  = chi2
                    result.chi_p_value = pval
                    result.chi_flag    = not is_uniform  # True = non-uniform = structured

                # 3. Compression
                if use_comp:
                    ratio, incomp = self._comp_test.test(data)
                    result.comp_ratio = ratio
                    result.comp_flag  = incomp

                # 4. Sliding window (cache raw data for the detail view)
                if use_sw:
                    self._sw_analyzer.analyze_block(result, data)

                # 5. Verdict
                result.verdict = compute_verdict(result, entropy_threshold=thresh)

                # 6. Threshold flag
                self._detector.flag_block(result)

                progress = (bidx + 1) / total * 100 if total else 50
                self.after(0, self._update_block_ui, result, min(progress, 99.9))

            reader.close()
            regions = self._aggregator.build(self._calculator.results)
            self.after(0, self._finish,
                       self._calculator.summary(),
                       self._aggregator.regions)
        except Exception as exc:
            import traceback; traceback.print_exc()
            self.after(0, messagebox.showerror, "Analysis Error", str(exc))
            self.after(0, self._reset_btns)

    def _update_block_ui(self, result: BlockResult, progress: float):
        self._progress.set(progress)
        self._status.set(
            f"Block {result.block_index}  |  0x{result.offset:08X}  |  "
            f"Ent {result.entropy:.4f}  |  χ²={result.chi_square:.1f}  |  "
            f"ratio={result.comp_ratio:.3f}  |  {result.verdict}"
        )

        tag = self._verdict_tag(result)
        flag = "⚠" if result.suspicious else ""
        sw_pk = f"{result.sw_peak_entropy:.4f}" if self._use_sw.get() else "—"

        self._block_tree.insert("", tk.END, values=(
            result.block_index,
            f"0x{result.offset:08X}",
            f"{result.entropy:.5f}",
            f"{result.chi_square:.1f}" if self._use_chi.get() else "—",
            f"{result.chi_p_value:.4f}" if self._use_chi.get() else "—",
            f"{result.comp_ratio:.4f}" if self._use_comp.get() else "—",
            sw_pk,
            result.verdict,
            flag,
        ), tags=(tag,))

        ch = self._block_tree.get_children()
        if ch:
            self._block_tree.see(ch[-1])
        self._redraw()

    def _finish(self, summary: dict, all_regions: List[EntropyRegion]):
        self._progress.set(100)
        self._reset_btns()

        if summary:
            self._block_summary.set(
                f"Blocks: {summary['total_blocks']}  |  "
                f"⚠ Suspicious: {summary['suspicious_blocks']}  |  "
                f"Encrypted: {summary['encrypted_blocks']}  |  "
                f"Threshold: {self._threshold.get():.2f}  |  "
                f"Min: {summary['min_entropy']:.4f}  |  "
                f"Avg: {summary['avg_entropy']:.4f}  |  "
                f"Max: {summary['max_entropy']:.4f} bits"
            )

        for item in self._region_tree.get_children():
            self._region_tree.delete(item)
        for reg in all_regions:
            if reg.is_noise:
                tag = "noise"
            elif "Encrypted" in reg.verdict:
                tag = "encrypted"
            else:
                tag = "significant"
            self._region_tree.insert("", tk.END, values=(
                reg.region_id,
                reg.start_block,
                reg.end_block,
                reg.offset_range,
                reg.size_label,
                reg.block_count,
                f"{reg.avg_entropy:.4f}",
                f"{reg.max_entropy:.4f}",
                reg.verdict,
                "noise" if reg.is_noise else "",
            ), tags=(tag,))

        rsumm = self._aggregator.summary()
        self._region_summary.set(
            f"Regions: {rsumm['total_regions']}  |  "
            f"Significant: {rsumm['significant_regions']}  |  "
            f"Noise (filtered): {rsumm['noise_regions']}  |  "
            f"Min size: {self._min_region_kb.get():.1f} KB  |  "
            f"Largest: {self._hsize(rsumm['largest_region_bytes'])}"
        )

        enc_count = sum(1 for r in self._aggregator.significant_regions
                        if "Encrypted" in r.verdict)
        self._status.set(
            f"Done. {summary.get('total_blocks',0)} blocks  |  "
            f"⚠ {summary.get('suspicious_blocks',0)} suspicious  |  "
            f"⬡ {rsumm['significant_regions']} regions  |  "
            f"🔒 {enc_count} encrypted regions"
        )

        # Compute risk scores for all significant regions
        for reg in self._aggregator.significant_regions:
            self._risk_scores[reg.region_id] = compute_risk_score(
                reg, self._calculator.results)

        # Refresh all viz panels
        self._draw_heatmap()
        self._draw_histogram()
        self._refresh_report()

    def _reset_btns(self):
        self._btn_analyze.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)

    def _on_threshold_change(self, *_):
        res = self._calculator.results
        if not res:
            return
        try:
            thresh = self._threshold.get()
            min_kb = self._min_region_kb.get()
        except Exception:
            return

        self._detector   = ThresholdDetector(threshold=thresh)
        self._aggregator = RegionAggregator(min_region_bytes=int(min_kb * 1024))
        self._detector.apply(res)
        # Re-compute verdicts with new threshold
        for r in res:
            r.verdict = compute_verdict(r, entropy_threshold=thresh)
        self._aggregator.build(res)

        children = self._block_tree.get_children()
        for child, r in zip(children, res):
            tag  = self._verdict_tag(r)
            flag = "⚠" if r.suspicious else ""
            sw_pk = f"{r.sw_peak_entropy:.4f}" if self._use_sw.get() else "—"
            self._block_tree.item(child, values=(
                r.block_index, f"0x{r.offset:08X}",
                f"{r.entropy:.5f}",
                f"{r.chi_square:.1f}" if self._use_chi.get() else "—",
                f"{r.chi_p_value:.4f}" if self._use_chi.get() else "—",
                f"{r.comp_ratio:.4f}" if self._use_comp.get() else "—",
                sw_pk, r.verdict, flag,
            ), tags=(tag,))

        for item in self._region_tree.get_children():
            self._region_tree.delete(item)
        for reg in self._aggregator.regions:
            if reg.is_noise:
                tag = "noise"
            elif "Encrypted" in reg.verdict:
                tag = "encrypted"
            else:
                tag = "significant"
            self._region_tree.insert("", tk.END, values=(
                reg.region_id, reg.start_block, reg.end_block,
                reg.offset_range, reg.size_label, reg.block_count,
                f"{reg.avg_entropy:.4f}", f"{reg.max_entropy:.4f}",
                reg.verdict, "noise" if reg.is_noise else "",
            ), tags=(tag,))

        rsumm = self._aggregator.summary()
        self._region_summary.set(
            f"Regions: {rsumm['total_regions']}  |  "
            f"Significant: {rsumm['significant_regions']}  |  "
            f"Noise: {rsumm['noise_regions']}  |  "
            f"Min: {min_kb:.1f} KB"
        )

        # Recompute risk scores
        for reg in self._aggregator.significant_regions:
            self._risk_scores[reg.region_id] = compute_risk_score(
                reg, res)

        self._draw_heatmap()
        self._draw_histogram()
        self._refresh_report()

    def _on_block_select(self, _event):
        sel = self._block_tree.selection()
        if not sel:
            return
        vals = self._block_tree.item(sel[0], "values")
        if not vals:
            return
        try:
            bidx = int(vals[0])
        except Exception:
            return
        if not self._use_sw.get():
            return
        wins = self._sw_analyzer.windows_for_block(bidx)
        if not wins:
            return
        peak = max(wins, key=lambda w: w.entropy)
        self._status.set(
            f"Block {bidx} — SW: {len(wins)} windows  |  "
            f"Peak entropy {peak.entropy:.5f} at rel-offset +{peak.rel_offset} B  |  "
            f"Peak χ²={peak.chi_square:.1f}  |  ratio={peak.comp_ratio:.4f}"
        )

    def _on_region_select(self, _event):
        sel = self._region_tree.selection()
        if not sel:
            return
        vals = self._region_tree.item(sel[0], "values")
        if not vals:
            return
        try:
            start_blk = int(vals[1])
        except Exception:
            return
        children = self._block_tree.get_children()
        if start_blk < len(children):
            item = children[start_blk]
            self._block_tree.selection_set(item)
            self._block_tree.see(item)

    # ─────────────────────────────────────────────────────────────────────────
    # Chart
    # ─────────────────────────────────────────────────────────────────────────

    def _verdict_color(self, r: BlockResult) -> str:
        if r.suspicious and self._show_susp.get():
            if r.verdict == "Encrypted":   return ENC_CLR
            if r.verdict == "Encrypted?":  return ENC_CLR
            if r.verdict == "Compressed":  return COMP_CLR
            return SUSP_CLR
        return self._ecolor(r.entropy)

    def _ecolor(self, e: float) -> str:
        if e > 7.5: return ACCENT2
        if e > 6.0: return ACCENT
        if e > 3.0: return WARNING
        return SUCCESS

    def _verdict_tag(self, r: BlockResult) -> str:
        if r.verdict == "Encrypted" or r.verdict == "Encrypted?":
            return "verdict_enc"
        if r.verdict == "Compressed":
            return "verdict_comp"
        if r.suspicious:
            return "suspicious"
        if r.entropy > 7.5: return "encrypted_ent"
        if r.entropy > 6.0: return "high"
        if r.entropy > 3.0: return "medium"
        return "low"

    # ─────────────────────────────────────────────────────────────────────────
    # Visualization Drawing
    # ─────────────────────────────────────────────────────────────────────────

    def _redraw(self, *_):
        """Called on threshold/region changes — refreshes whichever tab is active."""
        tab = self._active_tab.get()
        if tab == "heatmap":
            self._draw_heatmap()
        elif tab == "histogram":
            self._draw_histogram()

    # ── Heatmap ───────────────────────────────────────────────────────────────

    def _draw_heatmap(self, *_):
        """
        Entropy Heatmap:
          X-axis = block index (left → right)
          Y-axis = entropy value (0 at bottom, 8.0 at top)
          Each block rendered as a vertical bar coloured by verdict/entropy.
          Threshold line, region overlays, SW peak ticks, Y-axis grid.
        """
        c   = self._heatmap_canvas
        c.delete("all")
        res = self._calculator.results
        if not res:
            c.create_text(10, 10, text="Run analysis to see heatmap.",
                          fill=MUTED, font=("Courier New", 9), anchor="nw")
            return

        W, H = c.winfo_width(), c.winfo_height()
        if W < 4 or H < 4:
            return

        MARGIN_L = 36   # room for Y-axis labels
        MARGIN_B = 18   # room for X-axis labels
        CHART_W  = W - MARGIN_L
        CHART_H  = H - MARGIN_B

        n  = len(res)
        bw = max(1.0, CHART_W / n)
        thresh = self._threshold.get()

        # Y-axis grid lines
        for yval in (0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0):
            py = MARGIN_B + CHART_H - (yval / 8.0) * CHART_H
            c.create_line(MARGIN_L, py, W, py, fill=AXIS_CLR, dash=(2, 6))
            c.create_text(MARGIN_L - 2, py, text=f"{yval:.0f}",
                          fill=MUTED, font=("Courier New", 6), anchor="e")

        # Bars
        for i, r in enumerate(res):
            x0  = MARGIN_L + i * bw
            x1  = x0 + bw
            bh  = (r.entropy / 8.0) * CHART_H
            col = self._verdict_color(r)
            c.create_rectangle(x0, MARGIN_B + CHART_H - bh, x1, MARGIN_B + CHART_H,
                               fill=col, outline="")

            # SW peak tick above the bar
            if self._use_sw.get() and r.sw_peak_entropy > r.entropy + 0.05:
                ph = (r.sw_peak_entropy / 8.0) * CHART_H
                c.create_line(x0, MARGIN_B + CHART_H - ph,
                              x1, MARGIN_B + CHART_H - ph,
                              fill=SW_CLR, width=1)

        # Threshold line
        ty = MARGIN_B + CHART_H - (thresh / 8.0) * CHART_H
        c.create_line(MARGIN_L, ty, W, ty, fill=SUSP_CLR, dash=(3, 3), width=1)
        c.create_text(W - 4, ty - 6, text=f"⚠ {thresh:.2f}",
                      fill=SUSP_CLR, font=("Courier New", 7), anchor="e")

        # Region overlays
        if self._show_regions.get():
            for reg in self._aggregator.significant_regions:
                rx0 = MARGIN_L + reg.start_block * bw
                rx1 = MARGIN_L + (reg.end_block + 1) * bw
                col = ENC_CLR if "Encrypted" in reg.verdict else REGION_CLR
                c.create_rectangle(rx0, MARGIN_B, rx1, MARGIN_B + CHART_H,
                                   outline=col, fill="", width=1, dash=(4, 2))
                if rx1 - rx0 > 16:
                    score = self._risk_scores.get(reg.region_id, 0.0)
                    label = f"R{reg.region_id}"
                    if score > 0:
                        label += f" {score:.0f}"
                    c.create_text(rx0 + 2, MARGIN_B + 4, text=label,
                                  fill=col, font=("Courier New", 6), anchor="nw")

        # X-axis labels (block indices, sparse)
        label_step = max(1, n // 10)
        for i in range(0, n, label_step):
            px = MARGIN_L + i * bw + bw / 2
            c.create_text(px, H - 2, text=str(i),
                          fill=MUTED, font=("Courier New", 6), anchor="s")

        # Y-axis top label
        c.create_text(MARGIN_L + 2, MARGIN_B, text="8.0",
                      fill=MUTED, font=("Courier New", 6), anchor="sw")
        # Axis titles
        c.create_text(MARGIN_L + CHART_W // 2, H - 1,
                      text="Block Index →", fill=MUTED,
                      font=("Courier New", 6), anchor="s")

    def _on_heatmap_hover(self, event):
        res = self._calculator.results
        if not res:
            return
        W = self._heatmap_canvas.winfo_width()
        MARGIN_L = 36
        CHART_W  = W - MARGIN_L
        n  = len(res)
        bw = max(1.0, CHART_W / n)
        idx = int((event.x - MARGIN_L) / bw)
        if 0 <= idx < n:
            r = res[idx]
            self._status.set(
                f"Block {r.block_index}  |  0x{r.offset:08X}  |  "
                f"Ent={r.entropy:.5f}  χ²={r.chi_square:.1f}  "
                f"p={r.chi_p_value:.4f}  ratio={r.comp_ratio:.4f}  "
                f"SW_peak={r.sw_peak_entropy:.5f}  [{r.verdict}]"
                f"{'  ⚠' if r.suspicious else ''}"
            )

    # ── Histogram ─────────────────────────────────────────────────────────────

    def _draw_histogram(self, *_):
        """
        Histogram of Entropy Distribution:
          X-axis = entropy value (or comp ratio / chi-square depending on mode)
          Y-axis = number of blocks in each bin
          Bars coloured by entropy level.
          Threshold line and suspicious zone overlay.
        """
        c   = self._histogram_canvas
        c.delete("all")
        res = self._calculator.results
        if not res:
            c.create_text(10, 10, text="Run analysis to see histogram.",
                          fill=MUTED, font=("Courier New", 9), anchor="nw")
            return

        W, H = c.winfo_width(), c.winfo_height()
        if W < 4 or H < 4:
            return

        mode = self._hist_mode.get()
        nbins = max(4, self._hist_bins.get())

        # Extract values by mode
        if mode == "entropy":
            values = [r.entropy for r in res]
            x_min, x_max = 0.0, 8.0
            x_label = "Entropy (bits per byte)"
            thresh_val = self._threshold.get()
            thresh_label = f"Threshold {thresh_val:.2f}"
        elif mode == "comp":
            values = [r.comp_ratio for r in res]
            x_min, x_max = 0.0, min(2.0, max(values) + 0.1) if values else 2.0
            x_label = "Compression Ratio"
            thresh_val = self._comp_test.threshold
            thresh_label = f"Incomp. {thresh_val:.2f}"
        else:  # chi
            values = [r.chi_square for r in res]
            x_min, x_max = 0.0, max(values) * 1.05 if values else 500.0
            x_label = "χ² Statistic (df=255)"
            thresh_val = ChiSquareTest.CHI2_CRIT_05
            thresh_label = "χ²_crit(0.05)"

        # Bin data
        bin_w   = (x_max - x_min) / nbins
        bins    = [0] * nbins
        for v in values:
            bi = min(nbins - 1, int((v - x_min) / bin_w))
            bins[bi] += 1

        max_count = max(bins) if bins else 1

        MARGIN_L = 42
        MARGIN_B = 28
        MARGIN_T = 12
        CHART_W  = W - MARGIN_L - 4
        CHART_H  = H - MARGIN_B - MARGIN_T

        bar_w = CHART_W / nbins

        # Y-axis grid + labels
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            py   = MARGIN_T + CHART_H - frac * CHART_H
            cnt  = int(frac * max_count)
            c.create_line(MARGIN_L, py, W - 4, py, fill=AXIS_CLR, dash=(2, 6))
            c.create_text(MARGIN_L - 2, py, text=str(cnt),
                          fill=MUTED, font=("Courier New", 6), anchor="e")

        # Bars
        for bi, count in enumerate(bins):
            if count == 0:
                continue
            bin_lo = x_min + bi * bin_w
            bin_mid = bin_lo + bin_w / 2

            # Pick bar colour by bin mid-value
            if mode == "entropy":
                col = self._ecolor(bin_mid)
                if bin_mid >= self._threshold.get():
                    col = SUSP_CLR
            elif mode == "comp":
                col = SUSP_CLR if bin_mid >= self._comp_test.threshold else SUCCESS
            else:
                col = SUSP_CLR if bin_mid >= ChiSquareTest.CHI2_CRIT_05 else SUCCESS

            bh  = (count / max_count) * CHART_H
            x0  = MARGIN_L + bi * bar_w + 1
            x1  = x0 + bar_w - 2
            y0  = MARGIN_T + CHART_H - bh
            y1  = MARGIN_T + CHART_H
            c.create_rectangle(x0, y0, x1, y1, fill=col, outline="")

            # Count label inside bar if tall enough
            if bh > 14:
                c.create_text((x0 + x1) / 2, y0 + 6, text=str(count),
                               fill=DARK_BG, font=("Courier New", 6))

        # Threshold vertical line
        tx = MARGIN_L + ((thresh_val - x_min) / (x_max - x_min)) * CHART_W
        if MARGIN_L <= tx <= W - 4:
            c.create_line(tx, MARGIN_T, tx, MARGIN_T + CHART_H,
                          fill=SUSP_CLR, dash=(3, 3), width=1)
            c.create_text(tx + 2, MARGIN_T + 4, text=thresh_label,
                          fill=SUSP_CLR, font=("Courier New", 6), anchor="nw")

        # X-axis labels
        x_label_step = max(1, nbins // 8)
        for bi in range(0, nbins, x_label_step):
            val = x_min + bi * bin_w
            px  = MARGIN_L + bi * bar_w + bar_w / 2
            c.create_text(px, MARGIN_T + CHART_H + 2, text=f"{val:.1f}",
                          fill=MUTED, font=("Courier New", 6), anchor="n")

        # Axis labels
        c.create_text(MARGIN_L + CHART_W // 2, H - 2,
                      text=x_label, fill=MUTED, font=("Courier New", 6), anchor="s")
        c.create_text(4, MARGIN_T + CHART_H // 2, text="Count",
                      fill=MUTED, font=("Courier New", 6), angle=90, anchor="center")

        # Stats summary in top-right
        mean_v = sum(values) / len(values)
        std_v  = math.sqrt(sum((v - mean_v) ** 2 for v in values) / len(values))
        summary = f"n={len(values)}  mean={mean_v:.3f}  σ={std_v:.3f}"
        c.create_text(W - 6, MARGIN_T + 2, text=summary,
                      fill=MUTED, font=("Courier New", 7), anchor="ne")

    def _on_histogram_hover(self, event):
        res = self._calculator.results
        if not res:
            return
        mode = self._hist_mode.get()
        nbins = max(4, self._hist_bins.get())
        W = self._histogram_canvas.winfo_width()
        MARGIN_L, CHART_W = 42, W - 42 - 4

        if mode == "entropy":
            x_min, x_max = 0.0, 8.0
        elif mode == "comp":
            vals = [r.comp_ratio for r in res]
            x_min, x_max = 0.0, min(2.0, max(vals) + 0.1) if vals else 2.0
        else:
            vals = [r.chi_square for r in res]
            x_min, x_max = 0.0, max(vals) * 1.05 if vals else 500.0

        bin_w = (x_max - x_min) / nbins
        bi = int((event.x - MARGIN_L) / (CHART_W / nbins))
        if 0 <= bi < nbins:
            lo = x_min + bi * bin_w
            hi = lo + bin_w
            count = sum(1 for r in res
                        if lo <= getattr(r, {"entropy":"entropy","comp":"comp_ratio","chi":"chi_square"}[mode]) < hi)
            pct = count / len(res) * 100
            self._status.set(
                f"Bin [{lo:.3f}, {hi:.3f})  |  {count} blocks  ({pct:.1f}%)"
            )

    # ── Suspicious Region Report ───────────────────────────────────────────────

    def _refresh_report(self, *_):
        """
        Build the Suspicious Region Report in the text widget.
        Each significant region gets:
          • Start / end offset (hex + decimal)
          • Size (human-readable)
          • Block count
          • Average entropy + max entropy
          • χ² uniformity fraction
          • Compression ratio average
          • SW peak entropy
          • Verdict breakdown
          • Risk Score (0–100) + label
        """
        rt = self._report_text
        rt.configure(state=tk.NORMAL)
        rt.delete("1.0", tk.END)

        res   = self._calculator.results
        regs  = self._aggregator.significant_regions
        summ  = self._calculator.summary()

        def w(text, tag=None):
            if tag:
                rt.insert(tk.END, text, tag)
            else:
                rt.insert(tk.END, text)

        # ── Header ────────────────────────────────────────────────────────────
        w("═" * 72 + "\n", "heading")
        w("  DISK ENTROPY ANALYZER — SUSPICIOUS REGION REPORT\n", "heading")
        w("═" * 72 + "\n", "heading")
        w(f"  File    : {self._file_path.get()}\n", "muted")
        w(f"  Type    : {self._file_type.get() or '—'}\n", "muted")
        import datetime
        w(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "muted")

        # ── Analysis Summary ──────────────────────────────────────────────────
        w("┌─ ANALYSIS SUMMARY " + "─" * 52 + "\n", "subhead")
        if summ:
            w(f"│  Total blocks     : {summ['total_blocks']}\n")
            w(f"│  Suspicious blocks: ")
            w(f"{summ['suspicious_blocks']}\n",
              "critical" if summ['suspicious_blocks'] > 0 else "ok")
            w(f"│  Encrypted blocks : ")
            w(f"{summ['encrypted_blocks']}\n",
              "enc" if summ['encrypted_blocks'] > 0 else "ok")
            w(f"│  Entropy range    : {summ['min_entropy']:.5f} → {summ['max_entropy']:.5f} bits\n")
            w(f"│  Average entropy  : {summ['avg_entropy']:.5f} bits\n")
        w(f"│  Threshold        : {self._threshold.get():.2f} bits\n")
        w(f"│  Min region size  : {self._min_region_kb.get():.1f} KB\n")
        w(f"│  χ² α level       : {self._chi_test.alpha}\n")
        w(f"│  Comp threshold   : {self._comp_test.threshold}\n")
        w(f"│  SW window/step   : {self._sw_analyzer.window_size}B / {self._sw_analyzer.step_size}B\n")
        w("└" + "─" * 70 + "\n\n", "subhead")

        # ── Per-region entries ────────────────────────────────────────────────
        if not regs:
            w("  No significant regions found above the current threshold.\n", "ok")
            w("  Try lowering the entropy threshold or minimum region size.\n", "muted")
        else:
            # Sort by risk score descending
            scored = []
            for reg in regs:
                score = compute_risk_score(reg, res)
                self._risk_scores[reg.region_id] = score
                scored.append((score, reg))
            scored.sort(key=lambda x: -x[0])

            w(f"  {len(scored)} suspicious region(s) found:\n\n", "subhead")

            for rank, (score, reg) in enumerate(scored, 1):
                rlabel = risk_label(score)
                rcol   = {"CRITICAL":"critical","HIGH":"high",
                          "MEDIUM":"medium","LOW":"low"}.get(rlabel, "ok")

                w(f"┌─ REGION {reg.region_id}  (Rank #{rank})  ", "subhead")
                w(f"[{rlabel}]  Score: {score:.1f}/100\n", rcol)

                # Offsets
                w(f"│  Start offset     : 0x{reg.start_offset:016X}")
                w(f"  ({reg.start_offset:,} bytes)\n")
                w(f"│  End offset       : 0x{reg.end_offset:016X}")
                w(f"  ({reg.end_offset:,} bytes)\n")
                w(f"│  Size             : {reg.size_label}")
                w(f"  ({reg.total_bytes:,} bytes, {reg.block_count} blocks)\n")
                w(f"│  Block range      : #{reg.start_block} → #{reg.end_block}\n")

                # Entropy stats
                w(f"│  Avg entropy      : {reg.avg_entropy:.6f} bits  ")
                ebar = "█" * int(reg.avg_entropy / 8.0 * 20)
                w(ebar + "\n",
                  "critical" if reg.avg_entropy >= 7.5 else
                  "high"     if reg.avg_entropy >= 6.5 else
                  "medium"   if reg.avg_entropy >= 5.0 else "ok")
                w(f"│  Max entropy      : {reg.max_entropy:.6f} bits\n")
                w(f"│  Verdict          : {reg.verdict}\n",
                  "enc"  if "Encrypted" in reg.verdict else
                  "comp" if "Compressed" in reg.verdict else "val")

                # Per-region block stats
                region_blocks = [b for b in res
                                 if reg.start_block <= b.block_index <= reg.end_block]
                if region_blocks:
                    enc_frac  = sum(1 for b in region_blocks if "Encrypted" in b.verdict) / len(region_blocks)
                    comp_frac = sum(1 for b in region_blocks if "Compressed" in b.verdict) / len(region_blocks)
                    avg_chi   = sum(b.chi_square for b in region_blocks) / len(region_blocks)
                    avg_ratio = sum(b.comp_ratio for b in region_blocks) / len(region_blocks)
                    avg_pval  = sum(b.chi_p_value for b in region_blocks) / len(region_blocks)
                    sw_peak   = max(b.sw_peak_entropy for b in region_blocks)
                    uniform_f = sum(1 for b in region_blocks if not b.chi_flag) / len(region_blocks)

                    w(f"│  Encrypted blocks : {enc_frac*100:.1f}%  |  Compressed: {comp_frac*100:.1f}%\n")
                    w(f"│  Avg χ² stat      : {avg_chi:.2f}  (uniform frac: {uniform_f*100:.1f}%,  avg p={avg_pval:.4f})\n")
                    w(f"│  Avg comp ratio   : {avg_ratio:.4f}  ({'incompressible' if avg_ratio >= self._comp_test.threshold else 'compressible'})\n",
                      "critical" if avg_ratio >= 0.99 else
                      "high"     if avg_ratio >= 0.95 else "ok")
                    w(f"│  SW peak entropy  : {sw_peak:.6f} bits\n",
                      "critical" if sw_peak >= 7.5 else
                      "high"     if sw_peak >= 6.5 else "ok")

                # Risk score breakdown
                w(f"│\n│  ── Risk Score: ")
                w(f"{score:.1f}/100  [{rlabel}]\n", rcol)
                # mini bar
                bar_len = int(score / 100 * 40)
                w(f"│  [{'█' * bar_len}{'░' * (40 - bar_len)}]\n", rcol)

                w("└" + "─" * 70 + "\n\n", "subhead")

        # ── Footer ────────────────────────────────────────────────────────────
        w("═" * 72 + "\n", "heading")
        w("  RISK SCORE LEGEND\n", "heading")
        w("  CRITICAL 80–100  |  ", "critical")
        w("HIGH 60–79  |  ", "high")
        w("MEDIUM 40–59  |  ", "medium")
        w("LOW 20–39  |  ", "low")
        w("MINIMAL 0–19\n", "ok")
        w("═" * 72 + "\n", "heading")

        rt.configure(state=tk.DISABLED)

        # Also refresh heatmap risk annotations
        if self._active_tab.get() == "heatmap":
            self._draw_heatmap()

    # ─────────────────────────────────────────────────────────────────────────
    # Export
    # ─────────────────────────────────────────────────────────────────────────

    def _export_csv(self):
        res = self._calculator.results
        if not res:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["block_index","offset_hex","offset_dec","size_bytes",
                        "entropy","chi_square","chi_p_value","comp_ratio",
                        "sw_peak_entropy","sw_peak_offset",
                        "suspicious","verdict"])
            for r in res:
                w.writerow([r.block_index, f"0x{r.offset:08X}", r.offset,
                            r.size, r.entropy,
                            r.chi_square, r.chi_p_value, r.comp_ratio,
                            r.sw_peak_entropy, r.sw_peak_offset,
                            r.suspicious, r.verdict])
        self._status.set(f"Exported blocks CSV → {path}")

    def _export_regions_csv(self):
        regs = self._aggregator.regions
        if not regs:
            messagebox.showinfo("Export", "No regions to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["region_id","start_block","end_block","start_offset",
                        "end_offset","total_bytes","block_count",
                        "avg_entropy","max_entropy","verdict","is_noise"])
            for r in regs:
                w.writerow([r.region_id, r.start_block, r.end_block,
                            r.start_offset, r.end_offset, r.total_bytes,
                            r.block_count, r.avg_entropy, r.max_entropy,
                            r.verdict, r.is_noise])
        self._status.set(f"Exported regions CSV → {path}")

    def _export_windows_csv(self):
        wins = self._sw_analyzer.window_results
        if not wins:
            messagebox.showinfo("Export",
                "No sliding window results. Enable SW mode and re-run analysis.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["window_index","block_index","rel_offset","abs_offset",
                        "size","entropy","chi_square","chi_p_value","comp_ratio"])
            for wr in wins:
                w.writerow([wr.window_index, wr.block_index, wr.rel_offset,
                            wr.abs_offset, wr.size, wr.entropy,
                            wr.chi_square, wr.chi_p_value, wr.comp_ratio])
        self._status.set(f"Exported windows CSV → {path}")

    def _export_json(self):
        res  = self._calculator.results
        regs = self._aggregator.regions
        if not res:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        data = {
            "analysis_summary":  self._calculator.summary(),
            "threshold":         self._detector.threshold,
            "chi_alpha":         self._chi_test.alpha,
            "comp_threshold":    self._comp_test.threshold,
            "sw_window_size":    self._sw_analyzer.window_size,
            "sw_step_size":      self._sw_analyzer.step_size,
            "region_summary":    self._aggregator.summary(),
            "blocks": [
                {"block_index":    r.block_index,
                 "offset":         r.offset,
                 "size":           r.size,
                 "entropy":        r.entropy,
                 "chi_square":     r.chi_square,
                 "chi_p_value":    r.chi_p_value,
                 "chi_flag":       r.chi_flag,
                 "comp_ratio":     r.comp_ratio,
                 "comp_flag":      r.comp_flag,
                 "sw_peak_entropy":r.sw_peak_entropy,
                 "sw_peak_offset": r.sw_peak_offset,
                 "suspicious":     r.suspicious,
                 "verdict":        r.verdict}
                for r in res
            ],
            "regions": [
                {"region_id":    r.region_id,
                 "start_block":  r.start_block, "end_block":  r.end_block,
                 "start_offset": r.start_offset, "end_offset": r.end_offset,
                 "total_bytes":  r.total_bytes, "block_count": r.block_count,
                 "avg_entropy":  r.avg_entropy, "max_entropy": r.max_entropy,
                 "verdict":      r.verdict, "is_noise": r.is_noise}
                for r in regs
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._status.set(f"Exported JSON → {path}")

    def _export_report_txt(self):
        """Export the text report to a .txt file."""
        content = self._report_text.get("1.0", tk.END)
        if not content.strip() or content.strip().startswith("Run analysis"):
            messagebox.showinfo("Export", "No report to export. Run analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self._status.set(f"Exported report TXT → {path}")

    def _export_report_json(self):
        """Export a machine-readable risk report as JSON."""
        regs = self._aggregator.significant_regions
        res  = self._calculator.results
        if not regs:
            messagebox.showinfo("Export", "No significant regions to report.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        import datetime
        report = {
            "generated":   datetime.datetime.now().isoformat(),
            "file":        self._file_path.get(),
            "file_type":   self._file_type.get(),
            "analysis":    self._calculator.summary(),
            "settings": {
                "threshold":      self._threshold.get(),
                "chi_alpha":      self._chi_test.alpha,
                "comp_threshold": self._comp_test.threshold,
                "sw_window":      self._sw_analyzer.window_size,
                "sw_step":        self._sw_analyzer.step_size,
                "min_region_kb":  self._min_region_kb.get(),
            },
            "regions": [],
        }
        for reg in sorted(regs, key=lambda r: -self._risk_scores.get(r.region_id, 0)):
            score = self._risk_scores.get(reg.region_id, 0.0)
            rb    = [b for b in res
                     if reg.start_block <= b.block_index <= reg.end_block]
            report["regions"].append({
                "region_id":     reg.region_id,
                "risk_score":    score,
                "risk_label":    risk_label(score),
                "start_offset":  reg.start_offset,
                "end_offset":    reg.end_offset,
                "start_offset_hex": f"0x{reg.start_offset:016X}",
                "end_offset_hex":   f"0x{reg.end_offset:016X}",
                "size_bytes":    reg.total_bytes,
                "size_human":    reg.size_label,
                "block_count":   reg.block_count,
                "avg_entropy":   reg.avg_entropy,
                "max_entropy":   reg.max_entropy,
                "verdict":       reg.verdict,
                "encrypted_pct": round(sum(1 for b in rb if "Encrypted" in b.verdict) / max(1, len(rb)) * 100, 1),
                "avg_comp_ratio":round(sum(b.comp_ratio for b in rb) / max(1, len(rb)), 4),
                "avg_chi_square":round(sum(b.chi_square for b in rb) / max(1, len(rb)), 2),
                "sw_peak_entropy":round(max((b.sw_peak_entropy for b in rb), default=0.0), 6),
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self._status.set(f"Exported report JSON → {path}")

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _hsize(n: int) -> str:
        for u in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"


if __name__ == "__main__":
    App().mainloop()