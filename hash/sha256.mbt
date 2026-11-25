///|
let sha256_k : FixedArray[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn sha256_init_state() -> FixedArray[UInt32] {
  [
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
    0x1f83d9abU, 0x5be0cd19U,
  ]
}

///|
fn sha256_compress(state : FixedArray[UInt32], w : FixedArray[UInt32]) -> Unit {
  for i in 16..<64 {
    let w15 = w[i - 15]
    let w2 = w[i - 2]
    let s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3)
    let s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >> 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  for i in 0..<64 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ ((e ^ 0xFFFFFFFFU) & g)
    let temp1 = h + s1 + ch + sha256_k[i] + w[i]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

///|
fn sha256_compress_bytes(
  state : FixedArray[UInt32],
  data : Bytes,
  off : Int32,
  w : FixedArray[UInt32],
) -> Unit {
  for i in 0..<16 {
    w[i] = load_be32_bytes(data, off + i * 4)
  }
  sha256_compress(state, w)
}

///|
fn sha256_compress_buf(
  state : FixedArray[UInt32],
  buf : FixedArray[Byte],
  w : FixedArray[UInt32],
) -> Unit {
  for i in 0..<16 {
    w[i] = load_be32(buf, i * 4)
  }
  sha256_compress(state, w)
}

///|
/// Finishes SHA-256 given an initial state, bytes already hashed (`prefix_len`),
/// and remaining message `data`.
fn sha256_from_state(
  init_state : FixedArray[UInt32],
  prefix_len : UInt64,
  data : Bytes,
) -> Bytes {
  let state = FixedArray::makei(8, i => init_state[i])
  let w = FixedArray::make(64, 0U)
  let len = data.length()
  let mut off = 0
  while off + 64 <= len {
    sha256_compress_bytes(state, data, off, w)
    off += 64
  }
  let rem = len - off
  let block = FixedArray::make(64, b'\x00')
  for i in 0..<rem {
    block[i] = data[off + i]
  }
  block[rem] = b'\x80'
  if rem >= 56 {
    sha256_compress_buf(state, block, w)
    for i in 0..<64 {
      block[i] = b'\x00'
    }
  }
  let total_bits = (prefix_len + len.to_uint64()) * 8UL
  store_be64(block, 56, total_bits)
  sha256_compress_buf(state, block, w)
  let out = FixedArray::make(32, b'\x00')
  for i in 0..<8 {
    store_be32(out, i * 4, state[i])
  }
  Bytes::makei(32, i => out[i])
}

///|
/// Computes the FIPS 180-4 SHA-256 digest (32 bytes).
pub fn sha256(data : Bytes) -> Bytes {
  sha256_from_state(sha256_init_state(), 0UL, data)
}
