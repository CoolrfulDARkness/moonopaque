///|
/// RFC 5869 HKDF-Extract with SHA-256.
/// When `salt` is empty, automatically substitutes 32 zero bytes.
pub fn hkdf_extract_sha256(salt : Bytes, ikm : Bytes) -> Bytes {
  let actual_salt = if salt.length() == 0 {
    Bytes::make(32, b'\x00')
  } else {
    salt
  }
  hmac_sha256(actual_salt, ikm)
}

///|
/// RFC 5869 HKDF-Expand with SHA-256.
pub fn hkdf_expand_sha256(prk : Bytes, info : Bytes, length : Int32) -> Bytes {
  if length < 0 || length > 255 * 32 {
    abort("hkdf_expand_sha256: length out of range")
  }
  if length == 0 {
    return b""
  }
  let (inner_state, outer_state) = hmac_sha256_key_states(prk)
  let n = (length + 31) / 32
  let out = FixedArray::make(length, b'\x00')
  let mut t = b""
  let mut off = 0
  for i in 1..<=n {
    let input = concat_bytes([t, info, Bytes::make(1, i.to_byte())])
    t = hmac_sha256_with_states(inner_state, outer_state, input)
    let take = if length - off < 32 { length - off } else { 32 }
    for j in 0..<take {
      out[off + j] = t[j]
    }
    off += take
  }
  Bytes::makei(length, i => out[i])
}

///|
/// RFC 5869 HKDF-Extract with SHA-512.
/// When `salt` is empty, automatically substitutes 64 zero bytes.
pub fn hkdf_extract_sha512(salt : Bytes, ikm : Bytes) -> Bytes {
  let actual_salt = if salt.length() == 0 {
    Bytes::make(64, b'\x00')
  } else {
    salt
  }
  hmac_sha512(actual_salt, ikm)
}

///|
/// RFC 5869 HKDF-Expand with SHA-512.
pub fn hkdf_expand_sha512(prk : Bytes, info : Bytes, length : Int32) -> Bytes {
  if length < 0 || length > 255 * 64 {
    abort("hkdf_expand_sha512: length out of range")
  }
  if length == 0 {
    return b""
  }
  let (inner_state, outer_state) = hmac_sha512_key_states(prk)
  let n = (length + 63) / 64
  let out = FixedArray::make(length, b'\x00')
  let mut t = b""
  let mut off = 0
  for i in 1..<=n {
    let input = concat_bytes([t, info, Bytes::make(1, i.to_byte())])
    t = hmac_sha512_with_states(inner_state, outer_state, input)
    let take = if length - off < 64 { length - off } else { 64 }
    for j in 0..<take {
      out[off + j] = t[j]
    }
    off += take
  }
  Bytes::makei(length, i => out[i])
}
