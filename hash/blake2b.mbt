///|
let blake2b_iv : FixedArray[UInt64] = [
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
]

///|
let blake2b_sigma : FixedArray[Int32] = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13,
  6, 1, 12, 0, 2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9,
  4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10,
  15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14,
  1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13, 11, 7, 14, 12,
  1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1,
  4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
]

///|
fn blake2b_g(
  v : FixedArray[UInt64],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
fn blake2b_compress(
  h : FixedArray[UInt64],
  m : FixedArray[UInt64],
  t_lo : UInt64,
  t_hi : UInt64,
  is_last : Bool,
) -> Unit {
  let v = FixedArray::make(16, 0UL)
  for i in 0..<8 {
    v[i] = h[i]
    v[i + 8] = blake2b_iv[i]
  }
  v[12] = v[12] ^ t_lo
  v[13] = v[13] ^ t_hi
  if is_last {
    v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFUL
  }
  for round in 0..<12 {
    let s_off = round % 10 * 16
    blake2b_g(
      v,
      0,
      4,
      8,
      12,
      m[blake2b_sigma[s_off]],
      m[blake2b_sigma[s_off + 1]],
    )
    blake2b_g(
      v,
      1,
      5,
      9,
      13,
      m[blake2b_sigma[s_off + 2]],
      m[blake2b_sigma[s_off + 3]],
    )
    blake2b_g(
      v,
      2,
      6,
      10,
      14,
      m[blake2b_sigma[s_off + 4]],
      m[blake2b_sigma[s_off + 5]],
    )
    blake2b_g(
      v,
      3,
      7,
      11,
      15,
      m[blake2b_sigma[s_off + 6]],
      m[blake2b_sigma[s_off + 7]],
    )
    blake2b_g(
      v,
      0,
      5,
      10,
      15,
      m[blake2b_sigma[s_off + 8]],
      m[blake2b_sigma[s_off + 9]],
    )
    blake2b_g(
      v,
      1,
      6,
      11,
      12,
      m[blake2b_sigma[s_off + 10]],
      m[blake2b_sigma[s_off + 11]],
    )
    blake2b_g(
      v,
      2,
      7,
      8,
      13,
      m[blake2b_sigma[s_off + 12]],
      m[blake2b_sigma[s_off + 13]],
    )
    blake2b_g(
      v,
      3,
      4,
      9,
      14,
      m[blake2b_sigma[s_off + 14]],
      m[blake2b_sigma[s_off + 15]],
    )
  }
  for i in 0..<8 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
/// Computes unkeyed RFC 7693 BLAKE2b with output length `out_len` in `1..=64`.
pub fn blake2b(data : Bytes, out_len : Int32) -> Bytes {
  if out_len < 1 || out_len > 64 {
    abort("blake2b: out_len must be between 1 and 64")
  }
  let h = FixedArray::makei(8, i => blake2b_iv[i])
  h[0] = h[0] ^ 0x01010000UL ^ out_len.to_uint64()
  let m = FixedArray::make(16, 0UL)
  let len = data.length()
  let mut off = 0
  let mut t_lo = 0UL
  while off + 128 < len {
    for i in 0..<16 {
      m[i] = load_le64_bytes(data, off + i * 8)
    }
    t_lo = t_lo + 128UL
    blake2b_compress(h, m, t_lo, 0UL, false)
    off += 128
  }
  let rem = len - off
  let last_block = FixedArray::make(128, b'\x00')
  for i in 0..<rem {
    last_block[i] = data[off + i]
  }
  for i in 0..<16 {
    m[i] = load_le64(last_block, i * 8)
  }
  t_lo = t_lo + rem.to_uint64()
  blake2b_compress(h, m, t_lo, 0UL, true)
  let full = FixedArray::make(64, b'\x00')
  for i in 0..<8 {
    store_le64(full, i * 8, h[i])
  }
  Bytes::makei(out_len, i => full[i])
}
