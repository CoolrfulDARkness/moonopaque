///|
/// Constant-time comparison of two byte sequences.
/// Returns false immediately if lengths differ; otherwise accumulates XOR
/// across all bytes without early return.
pub fn ct_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0U
  for i in 0..<a.length() {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  diff == 0U
}

///|
/// I2OSP (RFC 8017 §4.1): converts a non-negative integer to a big-endian
/// byte string of the specified length.
pub fn i2osp(value : Int32, length : Int32) -> Bytes {
  if length < 0 || value < 0 {
    abort("i2osp: value and length must be non-negative")
  }
  if length == 0 {
    if value != 0 {
      abort("i2osp: integer too large for length 0")
    }
    return b""
  }
  let buf = FixedArray::make(length, b'\x00')
  let mut v = value.to_uint64()
  for i = length - 1; i >= 0; i = i - 1 {
    buf[i] = (v & 0xFFUL).to_byte()
    v = v >> 8
  }
  if v != 0UL {
    abort("i2osp: integer too large for target length")
  }
  Bytes::makei(length, i => buf[i])
}

///|
/// Bitwise XOR of two equal-length byte sequences.
pub fn xor_bytes(a : Bytes, b : Bytes) -> Bytes {
  let len = a.length()
  if len != b.length() {
    abort("xor_bytes: inputs must have equal length")
  }
  Bytes::makei(len, i => (a[i].to_uint() ^ b[i].to_uint()).to_byte())
}

///|
/// Concatenates an array of byte sequences into a single `Bytes`.
pub fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for part in parts {
    total += part.length()
  }
  if total == 0 {
    return b""
  }
  let buf = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for part in parts {
    let plen = part.length()
    for i in 0..<plen {
      buf[offset + i] = part[i]
    }
    offset += plen
  }
  Bytes::makei(total, i => buf[i])
}

///|
fn nibble_to_hex(n : UInt32) -> Char {
  match n {
    0U => '0'
    1U => '1'
    2U => '2'
    3U => '3'
    4U => '4'
    5U => '5'
    6U => '6'
    7U => '7'
    8U => '8'
    9U => '9'
    10U => 'a'
    11U => 'b'
    12U => 'c'
    13U => 'd'
    14U => 'e'
    _ => 'f'
  }
}

///|
fn hex_to_nibble(c : Char) -> UInt32? {
  match c {
    '0' => Some(0U)
    '1' => Some(1U)
    '2' => Some(2U)
    '3' => Some(3U)
    '4' => Some(4U)
    '5' => Some(5U)
    '6' => Some(6U)
    '7' => Some(7U)
    '8' => Some(8U)
    '9' => Some(9U)
    'a' | 'A' => Some(10U)
    'b' | 'B' => Some(11U)
    'c' | 'C' => Some(12U)
    'd' | 'D' => Some(13U)
    'e' | 'E' => Some(14U)
    'f' | 'F' => Some(15U)
    _ => None
  }
}

///|
/// Encodes bytes as a lowercase hexadecimal string.
pub fn hex_encode(data : Bytes) -> String {
  let sb = StringBuilder(capacity=data.length() * 2)
  for i in 0..<data.length() {
    let b = data[i].to_uint()
    sb.write_char(nibble_to_hex(b >> 4))
    sb.write_char(nibble_to_hex(b & 0x0FU))
  }
  sb.to_string()
}

///|
/// Decodes a hexadecimal string (case-insensitive) into bytes.
/// Returns `None` if the input has odd length or contains invalid characters.
pub fn hex_decode(hex : String) -> Bytes? {
  let nibbles : Array[UInt32] = []
  for c in hex {
    match hex_to_nibble(c) {
      Some(n) => nibbles.push(n)
      None => return None
    }
  }
  if nibbles.length() % 2 != 0 {
    return None
  }
  let out_len = nibbles.length() / 2
  Some(
    Bytes::makei(out_len, i => {
      ((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]).to_byte()
    }),
  )
}

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn load_be32(buf : FixedArray[Byte], off : Int32) -> UInt32 {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
fn load_be32_bytes(data : Bytes, off : Int32) -> UInt32 {
  (data[off].to_uint() << 24) |
  (data[off + 1].to_uint() << 16) |
  (data[off + 2].to_uint() << 8) |
  data[off + 3].to_uint()
}

///|
fn load_be64(buf : FixedArray[Byte], off : Int32) -> UInt64 {
  (buf[off].to_uint64() << 56) |
  (buf[off + 1].to_uint64() << 48) |
  (buf[off + 2].to_uint64() << 40) |
  (buf[off + 3].to_uint64() << 32) |
  (buf[off + 4].to_uint64() << 24) |
  (buf[off + 5].to_uint64() << 16) |
  (buf[off + 6].to_uint64() << 8) |
  buf[off + 7].to_uint64()
}

///|
fn load_be64_bytes(data : Bytes, off : Int32) -> UInt64 {
  (data[off].to_uint64() << 56) |
  (data[off + 1].to_uint64() << 48) |
  (data[off + 2].to_uint64() << 40) |
  (data[off + 3].to_uint64() << 32) |
  (data[off + 4].to_uint64() << 24) |
  (data[off + 5].to_uint64() << 16) |
  (data[off + 6].to_uint64() << 8) |
  data[off + 7].to_uint64()
}

///|
fn load_le64(buf : FixedArray[Byte], off : Int32) -> UInt64 {
  buf[off].to_uint64() |
  (buf[off + 1].to_uint64() << 8) |
  (buf[off + 2].to_uint64() << 16) |
  (buf[off + 3].to_uint64() << 24) |
  (buf[off + 4].to_uint64() << 32) |
  (buf[off + 5].to_uint64() << 40) |
  (buf[off + 6].to_uint64() << 48) |
  (buf[off + 7].to_uint64() << 56)
}

///|
fn load_le64_bytes(data : Bytes, off : Int32) -> UInt64 {
  data[off].to_uint64() |
  (data[off + 1].to_uint64() << 8) |
  (data[off + 2].to_uint64() << 16) |
  (data[off + 3].to_uint64() << 24) |
  (data[off + 4].to_uint64() << 32) |
  (data[off + 5].to_uint64() << 40) |
  (data[off + 6].to_uint64() << 48) |
  (data[off + 7].to_uint64() << 56)
}

///|
fn store_le32(buf : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  buf[off] = (v & 0xFFU).to_byte()
  buf[off + 1] = ((v >> 8) & 0xFFU).to_byte()
  buf[off + 2] = ((v >> 16) & 0xFFU).to_byte()
  buf[off + 3] = ((v >> 24) & 0xFFU).to_byte()
}

///|
fn store_le64(buf : FixedArray[Byte], off : Int32, v : UInt64) -> Unit {
  buf[off] = (v & 0xFFUL).to_byte()
  buf[off + 1] = ((v >> 8) & 0xFFUL).to_byte()
  buf[off + 2] = ((v >> 16) & 0xFFUL).to_byte()
  buf[off + 3] = ((v >> 24) & 0xFFUL).to_byte()
  buf[off + 4] = ((v >> 32) & 0xFFUL).to_byte()
  buf[off + 5] = ((v >> 40) & 0xFFUL).to_byte()
  buf[off + 6] = ((v >> 48) & 0xFFUL).to_byte()
  buf[off + 7] = ((v >> 56) & 0xFFUL).to_byte()
}

///|
fn store_be32(buf : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  buf[off] = ((v >> 24) & 0xFFU).to_byte()
  buf[off + 1] = ((v >> 16) & 0xFFU).to_byte()
  buf[off + 2] = ((v >> 8) & 0xFFU).to_byte()
  buf[off + 3] = (v & 0xFFU).to_byte()
}

///|
fn store_be64(buf : FixedArray[Byte], off : Int32, v : UInt64) -> Unit {
  buf[off] = ((v >> 56) & 0xFFUL).to_byte()
  buf[off + 1] = ((v >> 48) & 0xFFUL).to_byte()
  buf[off + 2] = ((v >> 40) & 0xFFUL).to_byte()
  buf[off + 3] = ((v >> 32) & 0xFFUL).to_byte()
  buf[off + 4] = ((v >> 24) & 0xFFUL).to_byte()
  buf[off + 5] = ((v >> 16) & 0xFFUL).to_byte()
  buf[off + 6] = ((v >> 8) & 0xFFUL).to_byte()
  buf[off + 7] = (v & 0xFFUL).to_byte()
}
