///|
/// Size in bytes of an X25519 scalar, u-coordinate, public key, or shared secret (RFC 7748 §5).
pub const KEY_LEN : Int32 = 32

///|
/// Returns the fixed X25519 key / coordinate length in bytes (32).
pub fn key_len() -> Int32 {
  KEY_LEN
}

///|
/// Error types produced by RFC 7748 X25519 operations.
#derive(Eq, Debug)
pub(all) enum X25519Error {
  InvalidLength
  LowOrderPoint
}

///|
pub impl Show for X25519Error with fn output(self, logger) {
  match self {
    InvalidLength => logger.write_string("InvalidLength")
    LowOrderPoint => logger.write_string("LowOrderPoint")
  }
}

///|
/// Curve25519 Montgomery base point u = 9 (32-byte little-endian).
let basepoint : Bytes = b"\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

///|
/// RFC 7748 §5 scalar clamping (`decodeScalar25519`):
/// clears bits 0, 1, 2 and bit 255, and sets bit 254.
/// Returns `Err(InvalidLength)` if `scalar.length() != 32`.
pub fn clamp_scalar(scalar : Bytes) -> Result[Bytes, X25519Error] {
  if scalar.length() != KEY_LEN {
    return Err(InvalidLength)
  }
  let k = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    k[i] = scalar[i]
  }
  k[0] = (k[0].to_int() & 248).to_byte()
  k[31] = ((k[31].to_int() & 127) | 64).to_byte()
  Ok(Bytes::from_array(k[:]))
}

///|
/// Internal constant-time Montgomery ladder assuming 32-byte clamped `k` and 32-byte `u_bytes`.
fn montgomery_ladder(k : Bytes, u_bytes : Bytes) -> Bytes {
  let x1 = FieldElement::from_bytes_masked(u_bytes)
  let mut x2 = FieldElement::one()
  let mut z2 = FieldElement::zero()
  let mut x3 = x1
  let mut z3 = FieldElement::one()
  let mut swap = 0L
  for t = 254; t >= 0; t = t - 1 {
    let kt = ((k[t >> 3].to_int() >> (t & 7)) & 1).to_int64()
    swap = swap ^ kt
    let (nx2, nx3) = fe_cswap(swap, x2, x3)
    let (nz2, nz3) = fe_cswap(swap, z2, z3)
    x2 = nx2
    x3 = nx3
    z2 = nz2
    z3 = nz3
    swap = kt
    let a = x2.add(z2)
    let aa = a.square()
    let b = x2.sub(z2)
    let bb = b.square()
    let e = aa.sub(bb)
    let c = x3.add(z3)
    let d = x3.sub(z3)
    let da = d.mul(a)
    let cb = c.mul(b)
    x3 = da.add(cb).square()
    z3 = x1.mul(da.sub(cb).square())
    x2 = aa.mul(bb)
    z2 = e.mul(aa.add(e.mul_a24()))
  }
  let (fx2, _) = fe_cswap(swap, x2, x3)
  let (fz2, _) = fe_cswap(swap, z2, z3)
  fx2.mul(fz2.invert()).to_bytes()
}

///|
/// Constant-time check whether a 32-byte array is all zero.
fn ct_is_all_zero_32(data : Bytes) -> Bool {
  let mut acc = 0
  for i = 0; i < 32; i = i + 1 {
    acc = acc | data[i].to_int()
  }
  acc == 0
}

///|
/// RFC 7748 §5 X25519 scalar multiplication on Curve25519.
/// Internally clamps `scalar` and masks bit 255 of `u_coordinate`.
/// Per RFC 7748 §5, may return the all-zero 32-byte string for low-order points;
/// use `x25519_checked` when non-contributory outputs must be rejected (e.g., OPAQUE-3DH).
pub fn x25519(
  scalar : Bytes,
  u_coordinate : Bytes,
) -> Result[Bytes, X25519Error] {
  if u_coordinate.length() != KEY_LEN {
    return Err(InvalidLength)
  }
  let clamped = match clamp_scalar(scalar) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  Ok(montgomery_ladder(clamped, u_coordinate))
}

///|
/// RFC 7748 §6.1 contributory X25519 Diffie-Hellman (for OPAQUE-3DH).
/// Performs `x25519(scalar, u_coordinate)` and rejects all-zero outputs in constant time
/// with `Err(LowOrderPoint)`.
pub fn x25519_checked(
  scalar : Bytes,
  u_coordinate : Bytes,
) -> Result[Bytes, X25519Error] {
  let out = match x25519(scalar, u_coordinate) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  if ct_is_all_zero_32(out) {
    return Err(LowOrderPoint)
  }
  Ok(out)
}

///|
/// Computes the X25519 public key `X25519(scalar, 9)` from a 32-byte private key / seed.
pub fn x25519_base(scalar : Bytes) -> Result[Bytes, X25519Error] {
  x25519(scalar, basepoint)
}

///|
/// RFC 9807 §6.4.1.3 `DeriveDiffieHellmanKeyPair(seed)` for Curve25519.
/// Clamps the 32-byte `seed` per RFC 7748 §5 to form `sk` and computes `pk = X25519(sk, 9)`.
pub fn derive_keypair(seed : Bytes) -> Result[(Bytes, Bytes), X25519Error] {
  let sk = match clamp_scalar(seed) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let pk = montgomery_ladder(sk, basepoint)
  Ok((sk, pk))
}
