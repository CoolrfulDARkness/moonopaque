///|
let oversize_dst_prefix : Bytes = b"H2C-OVERSIZE-DST-"

///|
fn expand_message_xmd_generic(
  hash : (Bytes) -> Bytes,
  b_in_bytes : Int32,
  s_in_bytes : Int32,
  msg : Bytes,
  dst : Bytes,
  len_in_bytes : Int32,
) -> Bytes {
  if len_in_bytes < 0 || len_in_bytes > 65535 {
    abort("expand_message_xmd: len_in_bytes out of range")
  }
  let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes
  if ell > 255 {
    abort("expand_message_xmd: ell exceeds 255")
  }
  if len_in_bytes == 0 {
    return b""
  }
  let effective_dst = if dst.length() > 255 {
    hash(concat_bytes([oversize_dst_prefix, dst]))
  } else {
    dst
  }
  let dst_prime = concat_bytes([effective_dst, i2osp(effective_dst.length(), 1)])
  let z_pad = Bytes::make(s_in_bytes, b'\x00')
  let l_i_b_str = i2osp(len_in_bytes, 2)
  let msg_prime = concat_bytes([z_pad, msg, l_i_b_str, i2osp(0, 1), dst_prime])
  let b_0 = hash(msg_prime)
  let out = FixedArray::make(len_in_bytes, b'\x00')
  let mut b_prev = hash(concat_bytes([b_0, i2osp(1, 1), dst_prime]))
  let first_take = if len_in_bytes < b_in_bytes {
    len_in_bytes
  } else {
    b_in_bytes
  }
  for j in 0..<first_take {
    out[j] = b_prev[j]
  }
  let mut off = first_take
  for i in 2..<=ell {
    let xored = xor_bytes(b_0, b_prev)
    b_prev = hash(concat_bytes([xored, i2osp(i, 1), dst_prime]))
    let take = if len_in_bytes - off < b_in_bytes {
      len_in_bytes - off
    } else {
      b_in_bytes
    }
    for j in 0..<take {
      out[off + j] = b_prev[j]
    }
    off += take
  }
  Bytes::makei(len_in_bytes, i => out[i])
}

///|
/// RFC 9380 §5.3.1 `expand_message_xmd` instantiated with SHA-256
/// (`b_in_bytes = 32`, `s_in_bytes = 64`), with automatic §5.3.3 oversize DST handling.
pub fn expand_message_xmd_sha256(
  msg : Bytes,
  dst : Bytes,
  len_in_bytes : Int32,
) -> Bytes {
  expand_message_xmd_generic(sha256, 32, 64, msg, dst, len_in_bytes)
}

///|
/// RFC 9380 §5.3.1 `expand_message_xmd` instantiated with SHA-512
/// (`b_in_bytes = 64`, `s_in_bytes = 128`), with automatic §5.3.3 oversize DST handling.
pub fn expand_message_xmd_sha512(
  msg : Bytes,
  dst : Bytes,
  len_in_bytes : Int32,
) -> Bytes {
  expand_message_xmd_generic(sha512, 64, 128, msg, dst, len_in_bytes)
}
