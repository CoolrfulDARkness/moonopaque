///|
/// Constant-time GF(2^255 - 19) field arithmetic for RFC 7748 X25519.
/// Uses 10 signed 64-bit limbs in radix 2^25.5 (alternating 26-bit and 25-bit widths).
/// Every operation maintains non-negative strictly bounded limbs:
/// even limbs in [0, 2^26 - 1], odd limbs in [0, 2^25 - 1].
priv struct FieldElement {
  h0 : Int64
  h1 : Int64
  h2 : Int64
  h3 : Int64
  h4 : Int64
  h5 : Int64
  h6 : Int64
  h7 : Int64
  h8 : Int64
  h9 : Int64
}

///|
const MASK26 : Int64 = 0x3ffffffL

///|
const MASK25 : Int64 = 0x1ffffffL

///|
/// 2 * p limb constants (p = 2^255 - 19) for non-negative constant-time subtraction.
const TWO_P0 : Int64 = 0x7ffffdaL

///|
const TWO_P_ODD : Int64 = 0x3fffffeL

///|
const TWO_P_EVEN : Int64 = 0x7fffffeL

///|
/// RFC 7748 §5 constant a24 = (A - 2) / 4 = (486662 - 2) / 4 = 121665.
const A24 : Int64 = 121665L

///|
fn FieldElement::zero() -> FieldElement {
  {
    h0: 0L,
    h1: 0L,
    h2: 0L,
    h3: 0L,
    h4: 0L,
    h5: 0L,
    h6: 0L,
    h7: 0L,
    h8: 0L,
    h9: 0L,
  }
}

///|
fn FieldElement::one() -> FieldElement {
  {
    h0: 1L,
    h1: 0L,
    h2: 0L,
    h3: 0L,
    h4: 0L,
    h5: 0L,
    h6: 0L,
    h7: 0L,
    h8: 0L,
    h9: 0L,
  }
}

///|
/// Carry-propagate non-negative limbs t0..t9 (< 2^60) into strict [0, 2^26-1] / [0, 2^25-1] bounds.
fn fe_carry(
  t0 : Int64,
  t1 : Int64,
  t2 : Int64,
  t3 : Int64,
  t4 : Int64,
  t5 : Int64,
  t6 : Int64,
  t7 : Int64,
  t8 : Int64,
  t9 : Int64,
) -> FieldElement {
  let mut h0 = t0
  let mut h1 = t1
  let mut h2 = t2
  let mut h3 = t3
  let mut h4 = t4
  let mut h5 = t5
  let mut h6 = t6
  let mut h7 = t7
  let mut h8 = t8
  let mut h9 = t9
  // Pass 1
  let c0 = h0 >> 26
  h0 = h0 & MASK26
  h1 = h1 + c0
  let c1 = h1 >> 25
  h1 = h1 & MASK25
  h2 = h2 + c1
  let c2 = h2 >> 26
  h2 = h2 & MASK26
  h3 = h3 + c2
  let c3 = h3 >> 25
  h3 = h3 & MASK25
  h4 = h4 + c3
  let c4 = h4 >> 26
  h4 = h4 & MASK26
  h5 = h5 + c4
  let c5 = h5 >> 25
  h5 = h5 & MASK25
  h6 = h6 + c5
  let c6 = h6 >> 26
  h6 = h6 & MASK26
  h7 = h7 + c6
  let c7 = h7 >> 25
  h7 = h7 & MASK25
  h8 = h8 + c7
  let c8 = h8 >> 26
  h8 = h8 & MASK26
  h9 = h9 + c8
  let c9 = h9 >> 25
  h9 = h9 & MASK25
  h0 = h0 + c9 * 19L
  // Pass 2
  let d0 = h0 >> 26
  h0 = h0 & MASK26
  h1 = h1 + d0
  let d1 = h1 >> 25
  h1 = h1 & MASK25
  h2 = h2 + d1
  let d2 = h2 >> 26
  h2 = h2 & MASK26
  h3 = h3 + d2
  let d3 = h3 >> 25
  h3 = h3 & MASK25
  h4 = h4 + d3
  let d4 = h4 >> 26
  h4 = h4 & MASK26
  h5 = h5 + d4
  let d5 = h5 >> 25
  h5 = h5 & MASK25
  h6 = h6 + d5
  let d6 = h6 >> 26
  h6 = h6 & MASK26
  h7 = h7 + d6
  let d7 = h7 >> 25
  h7 = h7 & MASK25
  h8 = h8 + d7
  let d8 = h8 >> 26
  h8 = h8 & MASK26
  h9 = h9 + d8
  let d9 = h9 >> 25
  h9 = h9 & MASK25
  h0 = h0 + d9 * 19L
  // Final carry from h0 to h1
  let e0 = h0 >> 26
  h0 = h0 & MASK26
  h1 = h1 + e0
  { h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, }
}

///|
/// Constant-time canonical reduction from [0, 2^255 - 1] to [0, p - 1].
fn FieldElement::reduce_canonical(self : FieldElement) -> FieldElement {
  let mut q = (self.h0 + 19L) >> 26
  q = (self.h1 + q) >> 25
  q = (self.h2 + q) >> 26
  q = (self.h3 + q) >> 25
  q = (self.h4 + q) >> 26
  q = (self.h5 + q) >> 25
  q = (self.h6 + q) >> 26
  q = (self.h7 + q) >> 25
  q = (self.h8 + q) >> 26
  q = (self.h9 + q) >> 25
  // q == 1L iff self >= p, else 0L.
  let mut h0 = self.h0 + 19L * q
  let c0 = h0 >> 26
  h0 = h0 & MASK26
  let mut h1 = self.h1 + c0
  let c1 = h1 >> 25
  h1 = h1 & MASK25
  let mut h2 = self.h2 + c1
  let c2 = h2 >> 26
  h2 = h2 & MASK26
  let mut h3 = self.h3 + c2
  let c3 = h3 >> 25
  h3 = h3 & MASK25
  let mut h4 = self.h4 + c3
  let c4 = h4 >> 26
  h4 = h4 & MASK26
  let mut h5 = self.h5 + c4
  let c5 = h5 >> 25
  h5 = h5 & MASK25
  let mut h6 = self.h6 + c5
  let c6 = h6 >> 26
  h6 = h6 & MASK26
  let mut h7 = self.h7 + c6
  let c7 = h7 >> 25
  h7 = h7 & MASK25
  let mut h8 = self.h8 + c7
  let c8 = h8 >> 26
  h8 = h8 & MASK26
  let h9 = (self.h9 + c8) & MASK25
  { h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, }
}

///|
fn FieldElement::add(self : FieldElement, other : FieldElement) -> FieldElement {
  fe_carry(
    self.h0 + other.h0,
    self.h1 + other.h1,
    self.h2 + other.h2,
    self.h3 + other.h3,
    self.h4 + other.h4,
    self.h5 + other.h5,
    self.h6 + other.h6,
    self.h7 + other.h7,
    self.h8 + other.h8,
    self.h9 + other.h9,
  )
}

///|
fn FieldElement::sub(self : FieldElement, other : FieldElement) -> FieldElement {
  fe_carry(
    self.h0 + TWO_P0 - other.h0,
    self.h1 + TWO_P_ODD - other.h1,
    self.h2 + TWO_P_EVEN - other.h2,
    self.h3 + TWO_P_ODD - other.h3,
    self.h4 + TWO_P_EVEN - other.h4,
    self.h5 + TWO_P_ODD - other.h5,
    self.h6 + TWO_P_EVEN - other.h6,
    self.h7 + TWO_P_ODD - other.h7,
    self.h8 + TWO_P_EVEN - other.h8,
    self.h9 + TWO_P_ODD - other.h9,
  )
}

///|
fn FieldElement::mul_a24(self : FieldElement) -> FieldElement {
  fe_carry(
    self.h0 * A24,
    self.h1 * A24,
    self.h2 * A24,
    self.h3 * A24,
    self.h4 * A24,
    self.h5 * A24,
    self.h6 * A24,
    self.h7 * A24,
    self.h8 * A24,
    self.h9 * A24,
  )
}

///|
fn FieldElement::mul(self : FieldElement, other : FieldElement) -> FieldElement {
  let a0 = self.h0
  let a1 = self.h1
  let a2 = self.h2
  let a3 = self.h3
  let a4 = self.h4
  let a5 = self.h5
  let a6 = self.h6
  let a7 = self.h7
  let a8 = self.h8
  let a9 = self.h9
  let b0 = other.h0
  let b1 = other.h1
  let b2 = other.h2
  let b3 = other.h3
  let b4 = other.h4
  let b5 = other.h5
  let b6 = other.h6
  let b7 = other.h7
  let b8 = other.h8
  let b9 = other.h9
  let t0 = a0 * b0 +
    19L * (a2 * b8 + a4 * b6 + a6 * b4 + a8 * b2) +
    38L * (a1 * b9 + a3 * b7 + a5 * b5 + a7 * b3 + a9 * b1)
  let t1 = a0 * b1 +
    a1 * b0 +
    19L *
    (
      a2 * b9 +
      a3 * b8 +
      a4 * b7 +
      a5 * b6 +
      a6 * b5 +
      a7 * b4 +
      a8 * b3 +
      a9 * b2
    )
  let t2 = a0 * b2 +
    2L * a1 * b1 +
    a2 * b0 +
    19L * (a4 * b8 + a6 * b6 + a8 * b4) +
    38L * (a3 * b9 + a5 * b7 + a7 * b5 + a9 * b3)
  let t3 = a0 * b3 +
    a1 * b2 +
    a2 * b1 +
    a3 * b0 +
    19L * (a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4)
  let t4 = a0 * b4 +
    2L * a1 * b3 +
    a2 * b2 +
    2L * a3 * b1 +
    a4 * b0 +
    19L * (a6 * b8 + a8 * b6) +
    38L * (a5 * b9 + a7 * b7 + a9 * b5)
  let t5 = a0 * b5 +
    a1 * b4 +
    a2 * b3 +
    a3 * b2 +
    a4 * b1 +
    a5 * b0 +
    19L * (a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6)
  let t6 = a0 * b6 +
    2L * a1 * b5 +
    a2 * b4 +
    2L * a3 * b3 +
    a4 * b2 +
    2L * a5 * b1 +
    a6 * b0 +
    19L * (a8 * b8) +
    38L * (a7 * b9 + a9 * b7)
  let t7 = a0 * b7 +
    a1 * b6 +
    a2 * b5 +
    a3 * b4 +
    a4 * b3 +
    a5 * b2 +
    a6 * b1 +
    a7 * b0 +
    19L * (a8 * b9 + a9 * b8)
  let t8 = a0 * b8 +
    2L * a1 * b7 +
    a2 * b6 +
    2L * a3 * b5 +
    a4 * b4 +
    2L * a5 * b3 +
    a6 * b2 +
    2L * a7 * b1 +
    a8 * b0 +
    38L * (a9 * b9)
  let t9 = a0 * b9 +
    a1 * b8 +
    a2 * b7 +
    a3 * b6 +
    a4 * b5 +
    a5 * b4 +
    a6 * b3 +
    a7 * b2 +
    a8 * b1 +
    a9 * b0
  fe_carry(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9)
}

///|
fn FieldElement::square(self : FieldElement) -> FieldElement {
  let a0 = self.h0
  let a1 = self.h1
  let a2 = self.h2
  let a3 = self.h3
  let a4 = self.h4
  let a5 = self.h5
  let a6 = self.h6
  let a7 = self.h7
  let a8 = self.h8
  let a9 = self.h9
  let t0 = a0 * a0 +
    38L * (a2 * a8 + a4 * a6 + a5 * a5) +
    76L * (a1 * a9 + a3 * a7)
  let t1 = 2L * a0 * a1 + 38L * (a2 * a9 + a3 * a8 + a4 * a7 + a5 * a6)
  let t2 = 2L * (a0 * a2 + a1 * a1) +
    38L * (a4 * a8) +
    19L * (a6 * a6) +
    76L * (a3 * a9 + a5 * a7)
  let t3 = 2L * (a0 * a3 + a1 * a2) + 38L * (a4 * a9 + a5 * a8 + a6 * a7)
  let t4 = 2L * a0 * a4 +
    4L * a1 * a3 +
    a2 * a2 +
    38L * (a6 * a8 + a7 * a7) +
    76L * (a5 * a9)
  let t5 = 2L * (a0 * a5 + a1 * a4 + a2 * a3) + 38L * (a6 * a9 + a7 * a8)
  let t6 = 2L * (a0 * a6 + a2 * a4 + a3 * a3) +
    4L * a1 * a5 +
    19L * (a8 * a8) +
    76L * (a7 * a9)
  let t7 = 2L * (a0 * a7 + a1 * a6 + a2 * a5 + a3 * a4) + 38L * (a8 * a9)
  let t8 = 2L * (a0 * a8 + a2 * a6) +
    4L * (a1 * a7 + a3 * a5) +
    a4 * a4 +
    38L * (a9 * a9)
  let t9 = 2L * (a0 * a9 + a1 * a8 + a2 * a7 + a3 * a6 + a4 * a5)
  fe_carry(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9)
}

///|
fn FieldElement::square_n(self : FieldElement, n : Int32) -> FieldElement {
  let mut acc = self
  for i = 0; i < n; i = i + 1 {
    acc = acc.square()
  }
  acc
}

///|
/// Constant-time modular inversion via Fermat's Little Theorem:
/// self^(p - 2) = self^(2^255 - 21) mod p. Returns 0 for self == 0 (per RFC 7748 §5).
fn FieldElement::invert(self : FieldElement) -> FieldElement {
  let z2 = self.square() // 2
  let z9 = z2.square_n(2).mul(self) // 9
  let z11 = z9.mul(z2) // 11
  let t0 = z11.square().mul(z9) // 2^5 - 1
  let t1 = t0.square_n(5).mul(t0) // 2^10 - 1
  let t2 = t1.square_n(10).mul(t1) // 2^20 - 1
  let t3 = t2.square_n(20).mul(t2) // 2^40 - 1
  let t4 = t3.square_n(10).mul(t1) // 2^50 - 1
  let t5 = t4.square_n(50).mul(t4) // 2^100 - 1
  let t6 = t5.square_n(100).mul(t5) // 2^200 - 1
  let t7 = t6.square_n(50).mul(t4) // 2^250 - 1
  t7.square_n(5).mul(z11) // (2^250 - 1) * 32 + 11 = 2^255 - 21 = p - 2
}

///|
/// Constant-time conditional swap of two field elements (swap must be 0L or 1L).
fn fe_cswap(
  swap : Int64,
  a : FieldElement,
  b : FieldElement,
) -> (FieldElement, FieldElement) {
  let mask = 0L - swap
  let d0 = mask & (a.h0 ^ b.h0)
  let d1 = mask & (a.h1 ^ b.h1)
  let d2 = mask & (a.h2 ^ b.h2)
  let d3 = mask & (a.h3 ^ b.h3)
  let d4 = mask & (a.h4 ^ b.h4)
  let d5 = mask & (a.h5 ^ b.h5)
  let d6 = mask & (a.h6 ^ b.h6)
  let d7 = mask & (a.h7 ^ b.h7)
  let d8 = mask & (a.h8 ^ b.h8)
  let d9 = mask & (a.h9 ^ b.h9)
  (
    {
      h0: a.h0 ^ d0,
      h1: a.h1 ^ d1,
      h2: a.h2 ^ d2,
      h3: a.h3 ^ d3,
      h4: a.h4 ^ d4,
      h5: a.h5 ^ d5,
      h6: a.h6 ^ d6,
      h7: a.h7 ^ d7,
      h8: a.h8 ^ d8,
      h9: a.h9 ^ d9,
    },
    {
      h0: b.h0 ^ d0,
      h1: b.h1 ^ d1,
      h2: b.h2 ^ d2,
      h3: b.h3 ^ d3,
      h4: b.h4 ^ d4,
      h5: b.h5 ^ d5,
      h6: b.h6 ^ d6,
      h7: b.h7 ^ d7,
      h8: b.h8 ^ d8,
      h9: b.h9 ^ d9,
    },
  )
}

///|
fn load_le_u64(bytes : Bytes, offset : Int32) -> UInt64 {
  bytes[offset].to_uint64() |
  (bytes[offset + 1].to_uint64() << 8) |
  (bytes[offset + 2].to_uint64() << 16) |
  (bytes[offset + 3].to_uint64() << 24) |
  (bytes[offset + 4].to_uint64() << 32) |
  (bytes[offset + 5].to_uint64() << 40) |
  (bytes[offset + 6].to_uint64() << 48) |
  (bytes[offset + 7].to_uint64() << 56)
}

///|
/// RFC 7748 §5 decodeUCoordinate: unpack 32 little-endian bytes, masking bit 255.
/// Non-canonical values in [p, 2^255 - 1] are accepted and reduced modulo p.
fn FieldElement::from_bytes_masked(bytes : Bytes) -> FieldElement {
  let w0 = load_le_u64(bytes, 0)
  let w1 = load_le_u64(bytes, 8)
  let w2 = load_le_u64(bytes, 16)
  let w3 = load_le_u64(bytes, 24) & 0x7fff_ffff_ffff_ffffUL
  let h0 = (w0 & 0x3ffffffUL).reinterpret_as_int64()
  let h1 = ((w0 >> 26) & 0x1ffffffUL).reinterpret_as_int64()
  let h2 = (((w0 >> 51) | (w1 << 13)) & 0x3ffffffUL).reinterpret_as_int64()
  let h3 = ((w1 >> 13) & 0x1ffffffUL).reinterpret_as_int64()
  let h4 = ((w1 >> 38) & 0x3ffffffUL).reinterpret_as_int64()
  let h5 = (w2 & 0x1ffffffUL).reinterpret_as_int64()
  let h6 = ((w2 >> 25) & 0x3ffffffUL).reinterpret_as_int64()
  let h7 = (((w2 >> 51) | (w3 << 13)) & 0x1ffffffUL).reinterpret_as_int64()
  let h8 = ((w3 >> 12) & 0x3ffffffUL).reinterpret_as_int64()
  let h9 = ((w3 >> 38) & 0x1ffffffUL).reinterpret_as_int64()
  { h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, }
}

///|
/// RFC 7748 §5 encodeUCoordinate: canonically reduce mod p and encode as 32 little-endian bytes.
fn FieldElement::to_bytes(self : FieldElement) -> Bytes {
  let c = self.reduce_canonical()
  let h0 = c.h0
  let h1 = c.h1
  let h2 = c.h2
  let h3 = c.h3
  let h4 = c.h4
  let h5 = c.h5
  let h6 = c.h6
  let h7 = c.h7
  let h8 = c.h8
  let h9 = c.h9
  let out = FixedArray::make(32, b'\x00')
  out[0] = (h0 & 0xffL).to_byte()
  out[1] = ((h0 >> 8) & 0xffL).to_byte()
  out[2] = ((h0 >> 16) & 0xffL).to_byte()
  out[3] = (((h0 >> 24) | (h1 << 2)) & 0xffL).to_byte()
  out[4] = ((h1 >> 6) & 0xffL).to_byte()
  out[5] = ((h1 >> 14) & 0xffL).to_byte()
  out[6] = (((h1 >> 22) | (h2 << 3)) & 0xffL).to_byte()
  out[7] = ((h2 >> 5) & 0xffL).to_byte()
  out[8] = ((h2 >> 13) & 0xffL).to_byte()
  out[9] = (((h2 >> 21) | (h3 << 5)) & 0xffL).to_byte()
  out[10] = ((h3 >> 3) & 0xffL).to_byte()
  out[11] = ((h3 >> 11) & 0xffL).to_byte()
  out[12] = (((h3 >> 19) | (h4 << 6)) & 0xffL).to_byte()
  out[13] = ((h4 >> 2) & 0xffL).to_byte()
  out[14] = ((h4 >> 10) & 0xffL).to_byte()
  out[15] = ((h4 >> 18) & 0xffL).to_byte()
  out[16] = (h5 & 0xffL).to_byte()
  out[17] = ((h5 >> 8) & 0xffL).to_byte()
  out[18] = ((h5 >> 16) & 0xffL).to_byte()
  out[19] = (((h5 >> 24) | (h6 << 1)) & 0xffL).to_byte()
  out[20] = ((h6 >> 7) & 0xffL).to_byte()
  out[21] = ((h6 >> 15) & 0xffL).to_byte()
  out[22] = (((h6 >> 23) | (h7 << 3)) & 0xffL).to_byte()
  out[23] = ((h7 >> 5) & 0xffL).to_byte()
  out[24] = ((h7 >> 13) & 0xffL).to_byte()
  out[25] = (((h7 >> 21) | (h8 << 4)) & 0xffL).to_byte()
  out[26] = ((h8 >> 4) & 0xffL).to_byte()
  out[27] = ((h8 >> 12) & 0xffL).to_byte()
  out[28] = (((h8 >> 20) | (h9 << 6)) & 0xffL).to_byte()
  out[29] = ((h9 >> 2) & 0xffL).to_byte()
  out[30] = ((h9 >> 10) & 0xffL).to_byte()
  out[31] = ((h9 >> 18) & 0xffL).to_byte()
  Bytes::from_array(out[:])
}
