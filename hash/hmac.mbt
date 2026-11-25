///|
fn hmac_sha256_key_states(
  key : Bytes,
) -> (FixedArray[UInt32], FixedArray[UInt32]) {
  let k = if key.length() > 64 { sha256(key) } else { key }
  let ipad = FixedArray::make(64, b'\x36')
  let opad = FixedArray::make(64, b'\x5c')
  for i in 0..<k.length() {
    let kb = k[i].to_uint()
    ipad[i] = (kb ^ 0x36U).to_byte()
    opad[i] = (kb ^ 0x5cU).to_byte()
  }
  let w = FixedArray::make(64, 0U)
  let inner_state = sha256_init_state()
  sha256_compress_buf(inner_state, ipad, w)
  let outer_state = sha256_init_state()
  sha256_compress_buf(outer_state, opad, w)
  (inner_state, outer_state)
}

///|
fn hmac_sha256_with_states(
  inner_state : FixedArray[UInt32],
  outer_state : FixedArray[UInt32],
  msg : Bytes,
) -> Bytes {
  let inner_hash = sha256_from_state(inner_state, 64UL, msg)
  sha256_from_state(outer_state, 64UL, inner_hash)
}

///|
/// Computes RFC 2104 HMAC-SHA256 (32 bytes).
pub fn hmac_sha256(key : Bytes, msg : Bytes) -> Bytes {
  let (inner_state, outer_state) = hmac_sha256_key_states(key)
  hmac_sha256_with_states(inner_state, outer_state, msg)
}

///|
fn hmac_sha512_key_states(
  key : Bytes,
) -> (FixedArray[UInt64], FixedArray[UInt64]) {
  let k = if key.length() > 128 { sha512(key) } else { key }
  let ipad = FixedArray::make(128, b'\x36')
  let opad = FixedArray::make(128, b'\x5c')
  for i in 0..<k.length() {
    let kb = k[i].to_uint()
    ipad[i] = (kb ^ 0x36U).to_byte()
    opad[i] = (kb ^ 0x5cU).to_byte()
  }
  let w = FixedArray::make(80, 0UL)
  let inner_state = sha512_init_state()
  sha512_compress_buf(inner_state, ipad, w)
  let outer_state = sha512_init_state()
  sha512_compress_buf(outer_state, opad, w)
  (inner_state, outer_state)
}

///|
fn hmac_sha512_with_states(
  inner_state : FixedArray[UInt64],
  outer_state : FixedArray[UInt64],
  msg : Bytes,
) -> Bytes {
  let inner_hash = sha512_from_state(inner_state, 128UL, msg)
  sha512_from_state(outer_state, 128UL, inner_hash)
}

///|
/// Computes RFC 2104 HMAC-SHA512 (64 bytes).
pub fn hmac_sha512(key : Bytes, msg : Bytes) -> Bytes {
  let (inner_state, outer_state) = hmac_sha512_key_states(key)
  hmac_sha512_with_states(inner_state, outer_state, msg)
}
