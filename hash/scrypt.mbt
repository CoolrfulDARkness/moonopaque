///|
/// 32-bit left rotation used by RFC 7914 §3 Salsa20/8 Core.
fn scrypt_rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// Loads a little-endian 32-bit unsigned integer from `data` at byte offset `off`.
fn scrypt_load_le32_bytes(data : Bytes, off : Int32) -> UInt32 {
  data[off].to_uint() |
  (data[off + 1].to_uint() << 8) |
  (data[off + 2].to_uint() << 16) |
  (data[off + 3].to_uint() << 24)
}

///|
/// RFC 7914 §3 Salsa20/8 Core on 16 little-endian 32-bit words in place.
fn scrypt_salsa20_8_core(b : FixedArray[UInt32]) -> Unit {
  let mut x0 = b[0]
  let mut x1 = b[1]
  let mut x2 = b[2]
  let mut x3 = b[3]
  let mut x4 = b[4]
  let mut x5 = b[5]
  let mut x6 = b[6]
  let mut x7 = b[7]
  let mut x8 = b[8]
  let mut x9 = b[9]
  let mut x10 = b[10]
  let mut x11 = b[11]
  let mut x12 = b[12]
  let mut x13 = b[13]
  let mut x14 = b[14]
  let mut x15 = b[15]

  // 4 double-rounds = 8 rounds
  for _ in 0..<4 {
    // Column round
    x4 = x4 ^ scrypt_rotl32(x0 + x12, 7)
    x8 = x8 ^ scrypt_rotl32(x4 + x0, 9)
    x12 = x12 ^ scrypt_rotl32(x8 + x4, 13)
    x0 = x0 ^ scrypt_rotl32(x12 + x8, 18)

    x9 = x9 ^ scrypt_rotl32(x5 + x1, 7)
    x13 = x13 ^ scrypt_rotl32(x9 + x5, 9)
    x1 = x1 ^ scrypt_rotl32(x13 + x9, 13)
    x5 = x5 ^ scrypt_rotl32(x1 + x13, 18)

    x14 = x14 ^ scrypt_rotl32(x10 + x6, 7)
    x2 = x2 ^ scrypt_rotl32(x14 + x10, 9)
    x6 = x6 ^ scrypt_rotl32(x2 + x14, 13)
    x10 = x10 ^ scrypt_rotl32(x6 + x2, 18)

    x3 = x3 ^ scrypt_rotl32(x15 + x11, 7)
    x7 = x7 ^ scrypt_rotl32(x3 + x15, 9)
    x11 = x11 ^ scrypt_rotl32(x7 + x3, 13)
    x15 = x15 ^ scrypt_rotl32(x11 + x7, 18)

    // Row round
    x1 = x1 ^ scrypt_rotl32(x0 + x3, 7)
    x2 = x2 ^ scrypt_rotl32(x1 + x0, 9)
    x3 = x3 ^ scrypt_rotl32(x2 + x1, 13)
    x0 = x0 ^ scrypt_rotl32(x3 + x2, 18)

    x6 = x6 ^ scrypt_rotl32(x5 + x4, 7)
    x7 = x7 ^ scrypt_rotl32(x6 + x5, 9)
    x4 = x4 ^ scrypt_rotl32(x7 + x6, 13)
    x5 = x5 ^ scrypt_rotl32(x4 + x7, 18)

    x11 = x11 ^ scrypt_rotl32(x10 + x9, 7)
    x8 = x8 ^ scrypt_rotl32(x11 + x10, 9)
    x9 = x9 ^ scrypt_rotl32(x8 + x11, 13)
    x10 = x10 ^ scrypt_rotl32(x9 + x8, 18)

    x12 = x12 ^ scrypt_rotl32(x15 + x14, 7)
    x13 = x13 ^ scrypt_rotl32(x12 + x15, 9)
    x14 = x14 ^ scrypt_rotl32(x13 + x12, 13)
    x15 = x15 ^ scrypt_rotl32(x14 + x13, 18)
  }

  b[0] = b[0] + x0
  b[1] = b[1] + x1
  b[2] = b[2] + x2
  b[3] = b[3] + x3
  b[4] = b[4] + x4
  b[5] = b[5] + x5
  b[6] = b[6] + x6
  b[7] = b[7] + x7
  b[8] = b[8] + x8
  b[9] = b[9] + x9
  b[10] = b[10] + x10
  b[11] = b[11] + x11
  b[12] = b[12] + x12
  b[13] = b[13] + x13
  b[14] = b[14] + x14
  b[15] = b[15] + x15
}

///|
/// RFC 7914 §4 scryptBlockMix on `2 * r` 64-byte blocks (`32 * r` 32-bit words).
/// Reads from `src` and writes interleaved even/odd chunks to `dst`.
fn scrypt_block_mix(
  src : FixedArray[UInt32],
  dst : FixedArray[UInt32],
  x : FixedArray[UInt32],
  r : Int32,
) -> Unit {
  let two_r = 2 * r
  let last_off = (two_r - 1) * 16
  for k in 0..<16 {
    x[k] = src[last_off + k]
  }
  for i in 0..<two_r {
    let in_off = i * 16
    for k in 0..<16 {
      x[k] = x[k] ^ src[in_off + k]
    }
    scrypt_salsa20_8_core(x)
    let out_chunk = if (i & 1) == 0 { i >> 1 } else { r + (i >> 1) }
    let out_off = out_chunk * 16
    for k in 0..<16 {
      dst[out_off + k] = x[k]
    }
  }
}

///|
/// RFC 7914 §5 scryptROMix for a single `128 * r`-byte slice at byte offset `b_off`.
fn scrypt_romix(
  b_init : Bytes,
  b_out : FixedArray[Byte],
  b_off : Int32,
  n : Int32,
  r : Int32,
  v : FixedArray[UInt32],
  x_buf : FixedArray[UInt32],
  y_buf : FixedArray[UInt32],
  tmp : FixedArray[UInt32],
) -> Unit {
  let block_words = 32 * r
  let mut x = x_buf
  let mut y = y_buf

  for w in 0..<block_words {
    x[w] = scrypt_load_le32_bytes(b_init, b_off + w * 4)
  }

  // Step 1: Populate V[0..N-1]
  for i in 0..<n {
    let v_off = i * block_words
    for w in 0..<block_words {
      v[v_off + w] = x[w]
    }
    scrypt_block_mix(x, y, tmp, r)
    let swap = x
    x = y
    y = swap
  }

  // Step 2: Random-access mixing using Integerify(X) mod N
  let mask = (n - 1).reinterpret_as_uint()
  let integerify_idx = (2 * r - 1) * 16
  for _ in 0..<n {
    let j = (x[integerify_idx] & mask).reinterpret_as_int()
    let v_off = j * block_words
    for w in 0..<block_words {
      x[w] = x[w] ^ v[v_off + w]
    }
    scrypt_block_mix(x, y, tmp, r)
    let swap = x
    x = y
    y = swap
  }

  for w in 0..<block_words {
    store_le32(b_out, b_off + w * 4, x[w])
  }
}

///|
/// Checked RFC 7914 scrypt password-based key derivation function.
///
/// Validates all RFC 7914 §6 parameters before allocating:
/// - `n` must be a power of 2 strictly greater than 1 (`n > 1 && (n & (n - 1)) == 0`)
/// - `r > 0`, `p > 0`, `dk_len > 0`
/// - `p * 128 * r` and `n * 32 * r` must fit within 32-bit signed buffer limits
///
/// Returns `None` if any parameter is invalid.
pub fn scrypt_checked(
  password : Bytes,
  salt : Bytes,
  n : Int32,
  r : Int32,
  p : Int32,
  dk_len : Int32,
) -> Bytes? {
  if n <= 1 || (n & (n - 1)) != 0 || r <= 0 || p <= 0 || dk_len <= 0 {
    return None
  }
  let max_int32 = 0x7FFFFFFFL
  let n64 = n.to_int64()
  let r64 = r.to_int64()
  let p64 = p.to_int64()
  let block_bytes64 = 128L * r64
  if block_bytes64 > max_int32 {
    return None
  }
  let total_bytes64 = p64 * block_bytes64
  if total_bytes64 > max_int32 {
    return None
  }
  let block_words64 = 32L * r64
  let v_words64 = n64 * block_words64
  if v_words64 > max_int32 {
    return None
  }

  let block_bytes = block_bytes64.to_int()
  let total_bytes = total_bytes64.to_int()
  let block_words = block_words64.to_int()
  let v_words = v_words64.to_int()

  // Step 1: B = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r)
  let b_init = pbkdf2_hmac_sha256(password, salt, 1, total_bytes)
  let b_out = FixedArray::make(total_bytes, b'\x00')

  // Reusable ROMix buffers across all p parallel blocks
  let v = FixedArray::make(v_words, 0U)
  let x_buf = FixedArray::make(block_words, 0U)
  let y_buf = FixedArray::make(block_words, 0U)
  let tmp = FixedArray::make(16, 0U)

  // Step 2: For i = 0..p-1, B[i] = scryptROMix(B[i], N)
  for i in 0..<p {
    scrypt_romix(b_init, b_out, i * block_bytes, n, r, v, x_buf, y_buf, tmp)
  }

  // Step 3: DK = PBKDF2-HMAC-SHA256(P, B', 1, dkLen)
  let b_mixed = Bytes::makei(total_bytes, i => b_out[i])
  Some(pbkdf2_hmac_sha256(password, b_mixed, 1, dk_len))
}

///|
/// RFC 7914 scrypt password-based key derivation function.
///
/// Aborts if parameters do not satisfy RFC 7914 §6 requirements
/// (`n > 1` power of 2, `r > 0`, `p > 0`, `dk_len > 0`, and non-overflowing
/// working set sizes). Use `scrypt_checked` for fallible parameter handling.
pub fn scrypt(
  password : Bytes,
  salt : Bytes,
  n : Int32,
  r : Int32,
  p : Int32,
  dk_len : Int32,
) -> Bytes {
  match scrypt_checked(password, salt, n, r, p, dk_len) {
    Some(dk) => dk
    None => abort("scrypt: invalid parameters")
  }
}
