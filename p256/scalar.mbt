///|
/// Scalar modulo the NIST P-256 prime group order `n`.
/// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
/// Stored internally in Montgomery form.
pub struct Scalar {
  priv val : U256
}

///|
let n_mod : U256 = u256_from_limbs(
  0xfc632551U, 0xf3b9cac2U, 0xa7179e84U, 0xbce6faadU, 0xffffffffU, 0xffffffffU, 0x00000000U,
  0xffffffffU,
)

///|
let n0_inv : UInt32 = 0xee00bc4fU

///|
/// R mod n (Montgomery representation of 1).
let n_r : U256 = u256_from_limbs(
  0x039cdaafU, 0x0c46353dU, 0x58e8617bU, 0x43190552U, 0x00000000U, 0x00000000U, 0xffffffffU,
  0x00000000U,
)

///|
/// R^2 mod n (used to convert standard form into Montgomery form).
let n_r2 : U256 = u256_from_limbs(
  0xbe79eea2U, 0x83244c95U, 0x49bd6fa6U, 0x4699799cU, 0x2b6bec59U, 0x2845b239U, 0xf3d95620U,
  0x66e12d94U,
)

///|
/// 2^32 * R mod n (used for Horner reduction mod n).
let n_mont_2_32 : U256 = u256_from_limbs(
  0x00000000U, 0x039cdaafU, 0x0c46353dU, 0x58e8617bU, 0x43190552U, 0x00000000U, 0x00000000U,
  0xffffffffU,
)

///|
/// n - 2 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f
let n_minus_2 : U256 = u256_from_limbs(
  0xfc63254fU, 0xf3b9cac2U, 0xa7179e84U, 0xbce6faadU, 0xffffffffU, 0xffffffffU, 0x00000000U,
  0xffffffffU,
)

///|
fn scalar_to_standard(s : Scalar) -> U256 {
  u256_mont_mul(s.val, u256_from_u32(1U), n_mod, n0_inv)
}

///|
fn scalar_from_standard(v : U256) -> Scalar {
  { val: u256_mont_mul(v, n_r2, n_mod, n0_inv), }
}

///|
/// Additive identity `0` in GF(n).
pub fn Scalar::zero() -> Scalar {
  { val: u256_zero(), }
}

///|
/// Multiplicative identity `1` in GF(n).
pub fn Scalar::one() -> Scalar {
  { val: n_r, }
}

///|
/// Parse a canonical 32-byte big-endian scalar strictly less than `n`.
pub fn Scalar::from_bytes_canonical(bytes : Bytes) -> Scalar? {
  if bytes.length() != 32 {
    return None
  }
  let v = u256_from_be_bytes_32(bytes)
  if !u256_lt(v, n_mod) {
    return None
  }
  Some(scalar_from_standard(v))
}

///|
/// Reduce an arbitrary non-empty big-endian integer modulo `n` (e.g. 48 bytes for RFC 9497 §4.3 `HashToScalar`).
/// Returns `None` if `bytes` is empty.
pub fn Scalar::from_bytes_be_mod_n(bytes : Bytes) -> Scalar? {
  match u256_from_be_bytes_mod_m_mont(bytes, n_mod, n0_inv, n_r2, n_mont_2_32) {
    Some(v) => Some({ val: v, })
    None => None
  }
}

///|
/// Encode the scalar as 32 big-endian bytes.
pub fn Scalar::to_bytes(self : Scalar) -> Bytes {
  u256_to_be_bytes_32(scalar_to_standard(self))
}

///|
/// Constant-time check for `self == 0`.
pub fn Scalar::is_zero(self : Scalar) -> Bool {
  u256_is_zero(self.val)
}

///|
/// Constant-time scalar equality.
pub fn Scalar::equal(self : Scalar, other : Scalar) -> Bool {
  u256_ct_equal(self.val, other.val)
}

///|
pub impl Eq for Scalar with fn equal(self, other) {
  self.equal(other)
}

///|
/// Modular scalar addition `(self + other) mod n`.
pub fn Scalar::add(self : Scalar, other : Scalar) -> Scalar {
  { val: u256_mod_add(self.val, other.val, n_mod), }
}

///|
/// Modular scalar subtraction `(self - other) mod n`.
pub fn Scalar::sub(self : Scalar, other : Scalar) -> Scalar {
  { val: u256_mod_sub(self.val, other.val, n_mod), }
}

///|
/// Modular scalar negation `(-self) mod n`.
pub fn Scalar::neg(self : Scalar) -> Scalar {
  { val: u256_mod_sub(u256_zero(), self.val, n_mod), }
}

///|
/// Modular scalar multiplication `(self * other) mod n`.
pub fn Scalar::mul(self : Scalar, other : Scalar) -> Scalar {
  { val: u256_mont_mul(self.val, other.val, n_mod, n0_inv), }
}

///|
/// Modular multiplicative inverse `self^(n - 2) mod n`.
/// Returns `None` when `self == 0`.
pub fn Scalar::invert(self : Scalar) -> Scalar? {
  if self.is_zero() {
    return None
  }
  Some({ val: u256_mont_pow_const(self.val, n_minus_2, n_r, n_mod, n0_inv), })
}
