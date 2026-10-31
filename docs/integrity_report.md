# Log File Integrity Report

## Executive Summary
- **Source File**: `data\firex-10G.log`
- **Total File Size**: 6,543,120,032 bytes (6.09 GB)
- **File SHA-256**: `b71fc95eb5fef198912ba12a03f363c23ec6048ba699d5aad08b0d3ef3cba121`
- **Clean Text Region**: 0 .. 4,815,675,419 bytes (4.48 GB)
- **Boundary Offset**: `4,815,675,419` (0x11F09601B)
- **Corrupted / Bad Region**: 4,815,675,419 .. 6,543,120,032 bytes (1.61 GB)
- **Text Resumption**: Valid log lines **NEVER** resume after offset `4,815,675,419`.
- **Likely Cause**: **Appended high-entropy noise / raw pseudorandom binary payload** (Shannon entropy = 7.9995 bits/byte, perfectly uniform distribution, magic bytes `baf714bc6e9cecdc`). Not a standard container (gzip, zstd, zip, bz2, xz).

## Boundary Analysis
- **Exact Boundary Byte Offset**: `4,815,675,419`
- **Last Clean Line Sample**:
  `date=2026-10-30 time=08:48:25 eventtime=1793350105999999000 tz="+0530" devname="FGT60FTK00000000" devid="FGT60FTK00000000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" `
- **First Bad Data Sample**:
  `baf714bc6e9cecdcaccc4f20d5c98c75dbc2509a55e33d53a72d00684cf09a09571f8765a965baff575a7d93a7424f0487d7`

### Hex Dump: 128 Bytes Before Boundary
```hex
61726422206c6576656c3d226e6f74696365222076643d22726f6f74222073726369703d31302e31302e34302e31373620737263706f72743d343235343620737263696e74663d22696e7465726e616c342220737263696e7466726f6c653d226c616e2220d981ded177570530d19fe99adc7d575f556c53d3938aa2a7c8e90a
```

### Hex Dump: 128 Bytes After Boundary
```hex
baf714bc6e9cecdcaccc4f20d5c98c75dbc2509a55e33d53a72d00684cf09a09571f8765a965baff575a7d93a7424f0487d7b05096b2065bd11dd3f8bdc3caeacd6853dca7cff0222526503f9240668489e8ab71b2067078aa4ce4c6fb25bc993f5a2c0cbe4e34f3b76677fa28eec92f27e83138a1bcc507263942ef15aef136
```

## Bad Region Characteristics
| Metric | Value | Expected for Uniform Random |
|---|---|---|
| Shannon Entropy | 7.9995 bits/byte | 8.0000 bits/byte |
| 0x00 Byte Share | 0.566% | 0.391% (1/256) |
| 0x0A (\n) Rate | 0.391% | 0.391% (1/256) |
| Magic Bytes | `0xbaf714bc6e9cecdc` | N/A |
| Magic Match | None (Checked gzip `1f8b`, zstd `28b52ffd`, zip `504b0304`, bz2 `425a68`, xz `fd377a58`) | N/A |

## Chunks Classification
| Chunk # | Start Byte | End Byte | Classification | Total Lines | Parsed | Malformed | Skipped |
|---|---|---|---|---|---|---|---|
| 0 | 0 | 67,109,068 | text | 127,094 | 127,094 | 0 | False |
| 1 | 67,109,068 | 134,218,193 | text | 127,085 | 127,085 | 0 | False |
| 2 | 134,218,193 | 201,327,220 | text | 127,169 | 127,169 | 0 | False |
| 3 | 201,327,220 | 268,436,422 | text | 127,188 | 127,188 | 0 | False |
| 4 | 268,436,422 | 335,545,365 | text | 126,693 | 126,693 | 0 | False |
| 5 | 335,545,365 | 402,654,294 | text | 127,205 | 127,205 | 0 | False |
| 6 | 402,654,294 | 469,763,589 | text | 127,102 | 127,102 | 0 | False |
| 7 | 469,763,589 | 536,872,563 | text | 127,185 | 127,185 | 0 | False |
| 8 | 536,872,563 | 603,981,933 | text | 127,154 | 127,154 | 0 | False |
| 9 | 603,981,933 | 671,090,840 | text | 127,871 | 127,871 | 0 | False |
| 10 | 671,090,840 | 738,199,943 | text | 127,192 | 127,192 | 0 | False |
| 11 | 738,199,943 | 805,308,990 | text | 127,089 | 127,089 | 0 | False |
| 12 | 805,308,990 | 872,418,045 | text | 127,504 | 127,504 | 0 | False |
| 13 | 872,418,045 | 939,527,112 | text | 127,168 | 127,168 | 0 | False |
| 14 | 939,527,112 | 1,000,000,514 | text | 114,557 | 114,557 | 0 | False |
