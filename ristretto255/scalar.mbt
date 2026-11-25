///|
/// Scalar modulo the ristretto255 prime group order:
/// L = 2^252 + 27742317777372353535851937790883648493.
/// Stored as 8 little-endian 32-bit unsigned limbs in UInt64, always strictly < L.
pub struct Scalar {
  priv limbs : FixedArray[UInt64]
}

///|
/// Group order L in 8 little-endian 32-bit limbs.
let scalar_l : FixedArray[UInt64] = [
  0x5cf5d3edUL, 0x5812631aUL, 0xa2f79cd6UL, 0x14def9deUL, 0x00000000UL, 0x00000000UL,
  0x00000000UL, 0x10000000UL,
]

///|
/// L - 2 in 8 little-endian 32-bit limbs, used for Fermat inversion s^(L-2) mod L.
let scalar_l_minus_2 : FixedArray[UInt64] = [
  0x5cf5d3ebUL, 0x5812631aUL, 0xa2f79cd6UL, 0x14def9deUL, 0x00000000UL, 0x00000000UL,
  0x00000000UL, 0x10000000UL,
]

///|
/// Barrett reduction constant floor(2^512 / L) in 9 little-endian 32-bit limbs.
let scalar_barrett_mu : FixedArray[UInt64] = [
  0x0a2c131bUL, 0xed9ce5a3UL, 0x086329a7UL, 0x2106215dUL, 0xffffffebUL, 0xffffffffUL,
  0xffffffffUL, 0xffffffffUL, 0x0000000fUL,
]

///|
const LIMB_MASK32 : UInt64 = 0xffffffffUL

///|
const LIMB_BASE32 : UInt64 = 0x1_0000_0000UL

///|
/// Raw 8-limb addition mod 2^256; returns (sum, carry in {0UL, 1UL}).
fn scalar_add_raw(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(8, 0UL)
  let mut carry = 0UL
  for i = 0; i < 8; i = i + 1 {
    let s = a[i] + b[i] + carry
    out[i] = s & LIMB_MASK32
    carry = s >> 32
  }
  (out, carry)
}

///|
/// Raw 8-limb subtraction mod 2^256; returns (diff, borrow in {0UL, 1UL}).
fn scalar_sub_raw(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(8, 0UL)
  let mut borrow = 0UL
  for i = 0; i < 8; i = i + 1 {
    let d = LIMB_BASE32 + a[i] - b[i] - borrow
    out[i] = d & LIMB_MASK32
    borrow = 1UL - (d >> 32)
  }
  (out, borrow)
}

///|
/// Constant-time limb array selection: returns b if cond == 1UL, else a.
fn scalar_ct_select_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  cond : UInt64,
) -> FixedArray[UInt64] {
  let mask = 0UL - cond
  let out = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    out[i] = a[i] ^ (mask & (a[i] ^ b[i]))
  }
  out
}

///|
/// Constant-time Barrett reduction of a 512-bit unsigned integer (16 limbs of 32 bits) mod L.
fn scalar_reduce_512(x : FixedArray[UInt64]) -> Scalar {
  // Compute prod = x * mu (16 limbs * 9 limbs -> 25 limbs).
  let prod = FixedArray::make(25, 0UL)
  for i = 0; i < 16; i = i + 1 {
    let mut carry = 0UL
    let xi = x[i]
    for j = 0; j < 9; j = j + 1 {
      let v = xi * scalar_barrett_mu[j] + prod[i + j] + carry
      prod[i + j] = v & LIMB_MASK32
      carry = v >> 32
    }
    prod[i + 9] = prod[i + 9] + carry
  }
  // q = floor(prod / 2^512) sits in prod[16..24].
  // Compute ql = (q * L) mod 2^256 (only low 8 limbs needed since 0 <= x - q*L < 2*L < 2^254).
  let ql = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    let mut carry = 0UL
    let qi = prod[16 + i]
    for j = 0; j < 8 - i; j = j + 1 {
      let v = qi * scalar_l[j] + ql[i + j] + carry
      ql[i + j] = v & LIMB_MASK32
      carry = v >> 32
    }
  }
  // r = (x[0..7] - ql[0..7]) mod 2^256 is exact in [0, 2*L - 1].
  let x_low = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    x_low[i] = x[i]
  }
  let (r, _) = scalar_sub_raw(x_low, ql)
  // Conditional subtraction of L: if r >= L (borrow == 0), take r - L; else take r.
  let (r_minus_l, borrow) = scalar_sub_raw(r, scalar_l)
  { limbs: scalar_ct_select_limbs(r_minus_l, r, borrow), }
}

///|
fn load_le_u32(bytes : Bytes, offset : Int32) -> UInt64 {
  bytes[offset].to_uint64() |
  (bytes[offset + 1].to_uint64() << 8) |
  (bytes[offset + 2].to_uint64() << 16) |
  (bytes[offset + 3].to_uint64() << 24)
}

///|
pub fn Scalar::zero() -> Scalar {
  { limbs: FixedArray::make(8, 0UL), }
}

///|
pub fn Scalar::one() -> Scalar {
  let limbs = FixedArray::make(8, 0UL)
  limbs[0] = 1UL
  { limbs, }
}

///|
/// Decode a 32-byte little-endian canonical scalar strictly in [0, L - 1].
/// Returns None if length != 32 or value >= L.
pub fn Scalar::from_bytes_canonical(bytes : Bytes) -> Scalar? {
  if bytes.length() != 32 {
    return None
  }
  let limbs = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    limbs[i] = load_le_u32(bytes, i * 4)
  }
  let (_, borrow) = scalar_sub_raw(limbs, scalar_l)
  if borrow == 1UL {
    Some({ limbs, })
  } else {
    None
  }
}

///|
/// Reduce a 64-byte little-endian unsigned integer modulo L.
/// Returns None if length != 64.
pub fn Scalar::from_bytes_wide(bytes : Bytes) -> Scalar? {
  if bytes.length() != 64 {
    return None
  }
  let x = FixedArray::make(16, 0UL)
  for i = 0; i < 16; i = i + 1 {
    x[i] = load_le_u32(bytes, i * 4)
  }
  Some(scalar_reduce_512(x))
}

///|
/// Encode canonical scalar as a 32-byte little-endian byte string.
pub fn Scalar::to_bytes(self : Scalar) -> Bytes {
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let w = self.limbs[i]
    out[i * 4] = (w & 0xffUL).to_byte()
    out[i * 4 + 1] = ((w >> 8) & 0xffUL).to_byte()
    out[i * 4 + 2] = ((w >> 16) & 0xffUL).to_byte()
    out[i * 4 + 3] = ((w >> 24) & 0xffUL).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
/// Constant-time check whether scalar equals zero.
pub fn Scalar::is_zero(self : Scalar) -> Bool {
  let mut acc = 0UL
  for i = 0; i < 8; i = i + 1 {
    acc = acc | self.limbs[i]
  }
  ct_is_zero_i64(acc.reinterpret_as_int64()) == 1L
}

///|
/// Constant-time equality comparison.
pub fn Scalar::equal(self : Scalar, other : Scalar) -> Bool {
  let mut diff = 0UL
  for i = 0; i < 8; i = i + 1 {
    diff = diff | (self.limbs[i] ^ other.limbs[i])
  }
  ct_is_zero_i64(diff.reinterpret_as_int64()) == 1L
}

///|
pub impl Eq for Scalar with fn equal(self, other) {
  self.equal(other)
}

///|
/// Constant-time addition modulo L.
pub fn Scalar::add(self : Scalar, other : Scalar) -> Scalar {
  let (sum, _) = scalar_add_raw(self.limbs, other.limbs)
  // Since self < L < 2^253 and other < L < 2^253, sum < 2*L < 2^254 (no 256-bit carry).
  let (sum_minus_l, borrow) = scalar_sub_raw(sum, scalar_l)
  { limbs: scalar_ct_select_limbs(sum_minus_l, sum, borrow), }
}

///|
/// Constant-time subtraction modulo L.
pub fn Scalar::sub(self : Scalar, other : Scalar) -> Scalar {
  let (diff, borrow) = scalar_sub_raw(self.limbs, other.limbs)
  let (diff_plus_l, _) = scalar_add_raw(diff, scalar_l)
  { limbs: scalar_ct_select_limbs(diff, diff_plus_l, borrow), }
}

///|
/// Constant-time negation modulo L.
pub fn Scalar::neg(self : Scalar) -> Scalar {
  Scalar::zero().sub(self)
}

///|
/// Constant-time multiplication modulo L.
pub fn Scalar::mul(self : Scalar, other : Scalar) -> Scalar {
  let prod = FixedArray::make(16, 0UL)
  for i = 0; i < 8; i = i + 1 {
    let mut carry = 0UL
    let ai = self.limbs[i]
    for j = 0; j < 8; j = j + 1 {
      let v = ai * other.limbs[j] + prod[i + j] + carry
      prod[i + j] = v & LIMB_MASK32
      carry = v >> 32
    }
    prod[i + 8] = prod[i + 8] + carry
  }
  scalar_reduce_512(prod)
}

///|
/// Multiplicative inverse modulo L using Fermat's Little Theorem: s^(L - 2) mod L.
/// Returns None if s == 0.
pub fn Scalar::invert(self : Scalar) -> Scalar? {
  if self.is_zero() {
    return None
  }
  let mut acc = Scalar::one()
  // Exponent L - 2 is a public constant with bit 252 as its MSB.
  for bit_idx = 252; bit_idx >= 0; bit_idx = bit_idx - 1 {
    acc = acc.mul(acc)
    let limb_idx = bit_idx >> 5
    let shift = bit_idx & 31
    if ((scalar_l_minus_2[limb_idx] >> shift) & 1UL) == 1UL {
      acc = acc.mul(self)
    }
  }
  Some(acc)
}

///|
/// Extract bit `i` (0 <= i < 256) as 0L or 1L in constant time.
fn Scalar::bit(self : Scalar, i : Int32) -> Int64 {
  let limb_idx = i >> 5
  let shift = i & 31
  ((self.limbs[limb_idx] >> shift) & 1UL).reinterpret_as_int64()
}
