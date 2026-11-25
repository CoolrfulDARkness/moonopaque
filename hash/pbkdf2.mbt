///|
/// RFC 8018 PBKDF2 with HMAC-SHA256.
pub fn pbkdf2_hmac_sha256(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  dk_len : Int32,
) -> Bytes {
  if iterations <= 0 || dk_len < 0 {
    abort("pbkdf2_hmac_sha256: invalid iterations or dk_len")
  }
  if dk_len == 0 {
    return b""
  }
  let (inner_state, outer_state) = hmac_sha256_key_states(password)
  let blocks = (dk_len + 31) / 32
  let out = FixedArray::make(dk_len, b'\x00')
  let t = FixedArray::make(32, b'\x00')
  let mut off = 0
  for block_idx in 1..<=blocks {
    let mut u = hmac_sha256_with_states(
      inner_state,
      outer_state,
      concat_bytes([salt, i2osp(block_idx, 4)]),
    )
    for k in 0..<32 {
      t[k] = u[k]
    }
    for _ in 2..<=iterations {
      u = hmac_sha256_with_states(inner_state, outer_state, u)
      for k in 0..<32 {
        t[k] = (t[k].to_uint() ^ u[k].to_uint()).to_byte()
      }
    }
    let take = if dk_len - off < 32 { dk_len - off } else { 32 }
    for k in 0..<take {
      out[off + k] = t[k]
    }
    off += take
  }
  Bytes::makei(dk_len, i => out[i])
}

///|
/// RFC 8018 PBKDF2 with HMAC-SHA512.
pub fn pbkdf2_hmac_sha512(
  password : Bytes,
  salt : Bytes,
  iterations : Int32,
  dk_len : Int32,
) -> Bytes {
  if iterations <= 0 || dk_len < 0 {
    abort("pbkdf2_hmac_sha512: invalid iterations or dk_len")
  }
  if dk_len == 0 {
    return b""
  }
  let (inner_state, outer_state) = hmac_sha512_key_states(password)
  let blocks = (dk_len + 63) / 64
  let out = FixedArray::make(dk_len, b'\x00')
  let t = FixedArray::make(64, b'\x00')
  let mut off = 0
  for block_idx in 1..<=blocks {
    let mut u = hmac_sha512_with_states(
      inner_state,
      outer_state,
      concat_bytes([salt, i2osp(block_idx, 4)]),
    )
    for k in 0..<64 {
      t[k] = u[k]
    }
    for _ in 2..<=iterations {
      u = hmac_sha512_with_states(inner_state, outer_state, u)
      for k in 0..<64 {
        t[k] = (t[k].to_uint() ^ u[k].to_uint()).to_byte()
      }
    }
    let take = if dk_len - off < 64 { dk_len - off } else { 64 }
    for k in 0..<take {
      out[off + k] = t[k]
    }
    off += take
  }
  Bytes::makei(dk_len, i => out[i])
}
