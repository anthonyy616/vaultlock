//! Content-defined chunking used for incremental vault storage.
//!
//! Uses a FastCDC-style rolling-gear boundary detector (the approach
//! popularised by J. Maccormick et al. and used by restic / FastCDC
//! implementations). All logic is safe, allocation-bounded code.
//!
//! Because chunking is deterministic, identical content produces identical
//! chunk boundaries on any machine, so unchanged chunks are reused and
//! interrupted transfers resume cleanly.

/// Minimum chunk length (bytes).
pub const MIN_CHUNK: usize = 64 * 1024;
/// Target average chunk length (bytes).
pub const AVG_CHUNK: usize = 256 * 1024;
/// Maximum chunk length (bytes). Uploads never reach beyond this buffer size.
pub const MAX_CHUNK: usize = 1024 * 1024;

/// A chunk reference: a byte range within the source content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRange {
    /// Absolute byte offset of the chunk start.
    pub offset: usize,
    /// Chunk length in bytes (between 1 and [`MAX_CHUNK`]).
    pub len: usize,
}

/// Split `data` into deterministic content-defined chunks with default bounds.
#[must_use]
pub fn chunk_ranges(data: &[u8]) -> Vec<ChunkRange> {
    chunk_ranges_with_bounds(data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK)
}

/// Split `data` using explicit bounds (used by tests and fuzz-like properties).
#[must_use]
pub fn chunk_ranges_with_bounds(data: &[u8], min: usize, avg: usize, max: usize) -> Vec<ChunkRange> {
    debug_assert!(min <= avg && avg <= max);
    let mut ranges = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        if remaining <= min {
            ranges.push(ChunkRange { offset, len: remaining });
            break;
        }
        let end = find_boundary(data, offset, min, avg, max);
        let len = end - offset;
        ranges.push(ChunkRange { offset, len });
        offset = end;
    }
    ranges
}

fn gear_table() -> &'static [u64; 256] {
    static GEAR: std::sync::OnceLock<[u64; 256]> = std::sync::OnceLock::new();
    GEAR.get_or_init(|| {
        let mut table = [0u64; 256];
        let mut state: u64 = 0x9E37_779B_97F4_A7C1; // fixed seed: cross-device determinism
        for slot in &mut table {
            // xorshift64: fixed deterministic PRNG. This is *not* security
            // material, only chunk-boundary discrimination.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *slot = state;
        }
        table
    })
}

fn find_boundary(data: &[u8], start: usize, min: usize, avg: usize, max: usize) -> usize {
    // Below avg: prefer the normal-size mask; beyond avg: accept sparser
    // boundaries up to the hard maximum (FastCDC dual-mask scheme).
    const NORMAL_MASK: u64 = 0x0000_0000_0006_CD9F; // ~2^15/weighted set bits for ~avg target
    const HARD_MASK: u64 = 0x0000_0000_0000_1FFF; // sparser: only after avg is passed

    let hard_stop = start.min(data.len()) + max.min(data.len() - start);
    let normal_stop = hard_stop.min(start + avg);

    let mut hash: u64 = 0;
    // Warm-up below the minimum size: no boundary before `min`.
    let warm_end = (start + min).min(normal_stop);
    for byte in &data[start..warm_end] {
        hash = (hash << 1).wrapping_add(gear_table()[*byte as usize]);
    }
    // Fast CDC normal mask until avg target.
    for (i, byte) in data.iter().enumerate().skip(warm_end).take(normal_stop.saturating_sub(warm_end)) {
        hash = (hash << 1).wrapping_add(gear_table()[*byte as usize]);
        if hash & NORMAL_MASK == 0 {
            return i + 1;
        }
    }
    // Sparser mask until the hard maximum.
    for (i, byte) in data.iter().enumerate().skip(normal_stop).take(hard_stop.saturating_sub(normal_stop)) {
        hash = (hash << 1).wrapping_add(gear_table()[*byte as usize]);
        if hash & HARD_MASK == 0 {
            return i + 1;
        }
    }
    hard_stop
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeat(n: u32, v: u8) -> Vec<u8> {
        vec![v; n.try_into().ok().unwrap_or(0)]
    }

    #[test]
    fn empty_input_produces_no_chunks() {
        assert!(chunk_ranges(&[]).is_empty());
    }

    #[test]
    fn small_input_is_single_chunk() {
        let data = repeat(1000, 7);
        let ranges = chunk_ranges(&data);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].len, 1000);
        assert_eq!(ranges[0].offset, 0);
    }

    #[test]
    fn boundaries_cover_exactly() {
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (((i % 251) as u16) * ((i / 97 % 2 * 7 + 1) as u16)) as u8)
            .collect();
        let ranges = chunk_ranges(&data);
        let mut offset = 0usize;
        for range in &ranges {
            assert_eq!(range.offset, offset);
            assert!(range.len >= 1);
            assert!(range.len <= MAX_CHUNK);
            offset += range.len;
        }
        assert_eq!(offset, data.len());
    }

    #[test]
    fn deterministic_across_calls() {
        let data: Vec<u8> = (0..800_000u32).map(|i| ((i * 31) ^ (i >> 5)) as u8).collect();
        let a = chunk_ranges(&data);
        let b = chunk_ranges(&data);
        assert_eq!(a, b);
    }

    #[test]
    fn repetitive_blocks_chunk_at_gear_boundaries() {
        let base: Vec<u8> = (0..500_000u32)
            .map(|i| if i % 4096 < 2048 { 0xAA } else { 0x55 })
            .collect();
        let ranges = chunk_ranges(&base);
        for range in &ranges {
            assert!(range.len >= 1 && range.len <= MAX_CHUNK);
        }
        assert_eq!(ranges.iter().map(|r| r.len).sum::<usize>(), base.len());
    }

    #[test]
    fn boundary_always_within_bounds() {
        let data: Vec<u8> = (0..2_000_000u32)
            .map(|i| ((i as u64).wrapping_mul(6_364_136_223_846_793_005) >> 33) as u8)
            .collect();
        for range in chunk_ranges(&data) {
            assert!(range.len >= 1);
            assert!(range.len <= MAX_CHUNK, "chunk exceeded max: {}", range.len);
        }
    }
}
