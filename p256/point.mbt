///|
/// Point on the NIST P-256 (secp256r1) elliptic curve
/// `y^2 = x^3 - 3x + b (mod p)` in homogeneous projective coordinates `(X : Y : Z)`.
/// The point at infinity (identity) is represented with `X = 0, Y != 0, Z = 0`.
pub struct Point {
  priv x : Fe
  priv y : Fe
  priv z : Fe
}

///|
/// Group identity element (point at infinity).
pub fn Point::identity() -> Point {
  { x: fe_zero(), y: fe_one(), z: fe_zero(), }
}

///|
/// Standard NIST P-256 base point generator `G`.
pub fn Point::generator() -> Point {
  { x: p_gx_mont, y: p_gy_mont, z: fe_one(), }
}

///|
/// Constant-time conditional select between two points.
fn point_ct_select(if_false : Point, if_true : Point, mask : UInt32) -> Point {
  {
    x: fe_ct_select(if_false.x, if_true.x, mask),
    y: fe_ct_select(if_false.y, if_true.y, mask),
    z: fe_ct_select(if_false.z, if_true.z, mask),
  }
}

///|
/// Returns true iff `self` is the identity element (point at infinity).
pub fn Point::is_identity(self : Point) -> Bool {
  fe_is_zero(self.z)
}

///|
/// Constant-time equality of two projective curve points.
pub fn Point::equal(self : Point, other : Point) -> Bool {
  let z1_zero = fe_is_zero_mask(self.z)
  let z2_zero = fe_is_zero_mask(other.z)
  let both_id = z1_zero & z2_zero
  let neither_id = z1_zero.lnot() & z2_zero.lnot()
  let x1z2 = fe_mul(self.x, other.z)
  let x2z1 = fe_mul(other.x, self.z)
  let y1z2 = fe_mul(self.y, other.z)
  let y2z1 = fe_mul(other.y, self.z)
  let xy_eq = fe_ct_equal_mask(x1z2, x2z1) & fe_ct_equal_mask(y1z2, y2z1)
  (both_id | (neither_id & xy_eq)) != 0U
}

///|
pub impl Eq for Point with fn equal(self, other) {
  self.equal(other)
}

///|
/// Point negation `-P = (X : -Y : Z)`.
pub fn Point::neg(self : Point) -> Point {
  { x: self.x, y: fe_neg(self.y), z: self.z, }
}

///|
/// Complete projective point addition for `a = -3`
/// (Renes-Costello-Batina 2015, Algorithm 4).
/// Exception-free and branchless for all inputs including `P == Q`, `P == -Q`,
/// `P == O`, `Q == O`, and `O + O`.
pub fn Point::add(self : Point, other : Point) -> Point {
  let x1 = self.x
  let y1 = self.y
  let z1 = self.z
  let x2 = other.x
  let y2 = other.y
  let z2 = other.z
  let mut t0 = fe_mul(x1, x2)
  let mut t1 = fe_mul(y1, y2)
  let mut t2 = fe_mul(z1, z2)
  let mut t3 = fe_add(x1, y1)
  let mut t4 = fe_add(x2, y2)
  t3 = fe_mul(t3, t4)
  t4 = fe_add(t0, t1)
  t3 = fe_sub(t3, t4)
  t4 = fe_add(y1, z1)
  let mut x3 = fe_add(y2, z2)
  t4 = fe_mul(t4, x3)
  x3 = fe_add(t1, t2)
  t4 = fe_sub(t4, x3)
  x3 = fe_add(x1, z1)
  let mut y3 = fe_add(x2, z2)
  x3 = fe_mul(x3, y3)
  y3 = fe_add(t0, t2)
  y3 = fe_sub(x3, y3)
  let mut z3 = fe_mul(p_b_mont, t2)
  x3 = fe_sub(y3, z3)
  z3 = fe_add(x3, x3)
  x3 = fe_add(x3, z3)
  z3 = fe_sub(t1, x3)
  x3 = fe_add(t1, x3)
  y3 = fe_mul(p_b_mont, y3)
  t1 = fe_add(t2, t2)
  t2 = fe_add(t1, t2)
  y3 = fe_sub(y3, t2)
  y3 = fe_sub(y3, t0)
  t1 = fe_add(y3, y3)
  y3 = fe_add(t1, y3)
  t1 = fe_add(t0, t0)
  t0 = fe_add(t1, t0)
  t0 = fe_sub(t0, t2)
  t1 = fe_mul(t4, y3)
  t2 = fe_mul(t0, y3)
  y3 = fe_mul(x3, z3)
  y3 = fe_add(y3, t2)
  x3 = fe_mul(t3, x3)
  x3 = fe_sub(x3, t1)
  z3 = fe_mul(t4, z3)
  t1 = fe_mul(t3, t0)
  z3 = fe_add(z3, t1)
  { x: x3, y: y3, z: z3, }
}

///|
/// Complete projective point doubling for `a = -3`
/// (Renes-Costello-Batina 2015, Algorithm 6).
fn point_double(p : Point) -> Point {
  let x = p.x
  let y = p.y
  let z = p.z
  let mut t0 = fe_sqr(x)
  let t1 = fe_sqr(y)
  let mut t2 = fe_sqr(z)
  let mut t3 = fe_mul(x, y)
  t3 = fe_add(t3, t3)
  let mut z3 = fe_mul(x, z)
  z3 = fe_add(z3, z3)
  let mut y3 = fe_mul(p_b_mont, t2)
  y3 = fe_sub(y3, z3)
  let mut x3 = fe_add(y3, y3)
  y3 = fe_add(x3, y3)
  x3 = fe_sub(t1, y3)
  y3 = fe_add(t1, y3)
  y3 = fe_mul(x3, y3)
  x3 = fe_mul(x3, t3)
  t3 = fe_add(t2, t2)
  t2 = fe_add(t2, t3)
  z3 = fe_mul(p_b_mont, z3)
  z3 = fe_sub(z3, t2)
  z3 = fe_sub(z3, t0)
  t3 = fe_add(z3, z3)
  z3 = fe_add(z3, t3)
  t3 = fe_add(t0, t0)
  t0 = fe_add(t3, t0)
  t0 = fe_sub(t0, t2)
  t0 = fe_mul(t0, z3)
  y3 = fe_add(y3, t0)
  t0 = fe_mul(y, z)
  t0 = fe_add(t0, t0)
  z3 = fe_mul(t0, z3)
  x3 = fe_sub(x3, z3)
  z3 = fe_mul(t0, t1)
  z3 = fe_add(z3, z3)
  z3 = fe_add(z3, z3)
  { x: x3, y: y3, z: z3, }
}

///|
/// Point subtraction `self - other`.
pub fn Point::sub(self : Point, other : Point) -> Point {
  self.add(other.neg())
}

///|
/// Constant-time 4-bit fixed-window scalar multiplication `s * self`.
/// Performs no secret-dependent branches or secret-indexed memory accesses.
pub fn Point::scalar_mul(self : Point, s : Scalar) -> Point {
  let table = FixedArray::make(16, Point::identity())
  table[1] = self
  for i = 2; i < 16; i = i + 1 {
    table[i] = table[i - 1].add(self)
  }
  let s_std = scalar_to_standard(s)
  let mut acc = Point::identity()
  for limb_idx = 7; limb_idx >= 0; limb_idx = limb_idx - 1 {
    let w = s_std.0[limb_idx]
    for shift = 28; shift >= 0; shift = shift - 4 {
      if limb_idx != 7 || shift != 28 {
        acc = point_double(acc)
        acc = point_double(acc)
        acc = point_double(acc)
        acc = point_double(acc)
      }
      let nibble = (w >> shift) & 0xFU
      let mut picked = Point::identity()
      for k = 1; k < 16; k = k + 1 {
        let mask = ct_eq_u32(nibble, k.reinterpret_as_uint())
        picked = point_ct_select(picked, table[k], mask)
      }
      acc = acc.add(picked)
    }
  }
  acc
}

///|
/// Constant-time base point scalar multiplication `s * G`.
pub fn Point::base_mul(s : Scalar) -> Point {
  Point::generator().scalar_mul(s)
}

///|
/// Deserialize a SEC1 compressed P-256 point (33 bytes: prefix `0x02` or `0x03`
/// followed by 32-byte big-endian `x < p`).
/// Rejects the identity element, uncompressed encodings, invalid prefixes,
/// invalid lengths, `x >= p`, and off-curve points.
pub fn Point::from_bytes_compressed(bytes : Bytes) -> Point? {
  if bytes.length() != 33 {
    return None
  }
  let prefix = bytes[0]
  let want_odd : UInt32 = if prefix == b'\x02' {
    0U
  } else if prefix == b'\x03' {
    1U
  } else {
    return None
  }
  let x_bytes = bytes[1:33].to_owned()
  let x = match fe_from_bytes_canonical(x_bytes) {
    Some(v) => v
    None => return None
  }
  // rhs = x^3 - 3*x + b
  let x2 = fe_sqr(x)
  let x3 = fe_mul(x2, x)
  let ax = fe_mul_a(x)
  let rhs = fe_add(fe_add(x3, ax), p_b_mont)
  let y_cand = fe_sqrt_candidate(rhs)
  if !fe_ct_equal(fe_sqr(y_cand), rhs) {
    return None
  }
  let got_odd = fe_sgn0(y_cand)
  let flip_mask = ct_eq_u32(got_odd, want_odd).lnot()
  let y = fe_ct_select(y_cand, fe_neg(y_cand), flip_mask)
  Some({ x, y, z: fe_one(), })
}

///|
/// Serialize a P-256 point in SEC1 compressed format.
/// Returns 33 bytes (`0x02` if `y` is even, `0x03` if `y` is odd, followed by
/// 32-byte big-endian `x`) for non-identity points, or 1 byte `[0x00]` for the
/// point at infinity (SEC1 §2.3.3).
pub fn Point::to_bytes_compressed(self : Point) -> Bytes {
  if self.is_identity() {
    return Bytes::from_array([b'\x00'])
  }
  let z_inv = fe_invert(self.z)
  let x = fe_mul(self.x, z_inv)
  let y = fe_mul(self.y, z_inv)
  let prefix = if fe_sgn0(y) == 0U { b'\x02' } else { b'\x03' }
  let x_bytes = fe_to_bytes(x)
  let out = FixedArray::make(33, b'\x00')
  out[0] = prefix
  for i = 0; i < 32; i = i + 1 {
    out[i + 1] = x_bytes[i]
  }
  Bytes::from_array(out)
}

///|
/// RFC 9380 Appendix F.2.1.2 `sqrt_ratio_3mod4(u, v)` for P-256 (`p ≡ 3 mod 4`, `Z = -10`).
/// Returns `(is_qr_mask, y)` where `is_qr_mask` is `0xFFFFFFFFU` if `u / v` is a square
/// (with `y = sqrt(u / v)`) and `0U` otherwise (with `y = sqrt(Z * u / v)`).
fn sswu_sqrt_ratio_3mod4(u : Fe, v : Fe) -> (UInt32, Fe) {
  let tv1_0 = fe_sqr(v)
  let tv2 = fe_mul(u, v)
  let tv1 = fe_mul(tv1_0, tv2)
  let y1_0 = fe_pow_c1(tv1)
  let y1 = fe_mul(y1_0, tv2)
  let y2 = fe_mul(y1, p_sswu_c2_mont)
  let tv3 = fe_mul(fe_sqr(y1), v)
  let is_qr = fe_ct_equal_mask(tv3, u)
  let y = fe_ct_select(y2, y1, is_qr)
  (is_qr, y)
}

///|
/// RFC 9380 §6.6.2 & Appendix F.2 straight-line Simplified SWU map for NIST P-256
/// (`A = -3`, `B = b`, `Z = -10`).
fn map_to_curve_sswu_fe(u : Fe) -> Point {
  let tv1_0 = fe_sqr(u)
  let tv1 = fe_mul(p_sswu_z_mont, tv1_0)
  let tv2_0 = fe_sqr(tv1)
  let tv2_1 = fe_add(tv2_0, tv1)
  let tv3_0 = fe_add(tv2_1, fe_one())
  let tv3 = fe_mul(p_b_mont, tv3_0)
  // tv4 = CMOV(Z, -tv2_1, tv2_1 != 0)
  let tv2_nz = fe_is_zero_mask(tv2_1).lnot()
  let tv4_0 = fe_ct_select(p_sswu_z_mont, fe_neg(tv2_1), tv2_nz)
  let tv4 = fe_mul_a(tv4_0)
  let tv2_2 = fe_sqr(tv3)
  let tv6_0 = fe_sqr(tv4)
  let tv5_0 = fe_mul_a(tv6_0)
  let tv2_3 = fe_add(tv2_2, tv5_0)
  let tv2_4 = fe_mul(tv2_3, tv3)
  let tv6 = fe_mul(tv6_0, tv4)
  let tv5 = fe_mul(p_b_mont, tv6)
  let tv2 = fe_add(tv2_4, tv5)
  let x_init = fe_mul(tv1, tv3)
  let (is_gx1_square, y1) = sswu_sqrt_ratio_3mod4(tv2, tv6)
  let y_init = fe_mul(fe_mul(tv1, u), y1)
  let x_num = fe_ct_select(x_init, tv3, is_gx1_square)
  let y_raw = fe_ct_select(y_init, y1, is_gx1_square)
  let e1 = ct_eq_u32(fe_sgn0(u), fe_sgn0(y_raw))
  let y_aff = fe_ct_select(fe_neg(y_raw), y_raw, e1)
  // Affine point is (x_num / tv4, y_aff), which equals projective (x_num : y_aff * tv4 : tv4).
  // tv4 is guaranteed non-zero since A != 0, Z != 0, and tv4_0 != 0.
  { x: x_num, y: fe_mul(y_aff, tv4), z: tv4, }
}

///|
/// RFC 9380 §6.6.2 & §8.2 Simplified SWU map to NIST P-256 (`Z = -10 mod p`).
/// Interprets `u_be_bytes` as a big-endian unsigned integer, reduces modulo `p`,
/// and maps to a point on P-256. Returns `None` if `u_be_bytes` is empty.
pub fn Point::map_to_curve_sswu(u_be_bytes : Bytes) -> Point? {
  match fe_from_bytes_be_mod_p(u_be_bytes) {
    Some(u) => Some(map_to_curve_sswu_fe(u))
    None => None
  }
}

///|
/// RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` curve mapping from 96 uniform bytes
/// produced by `expand_message_xmd` (SHA-256, `L = 48`, `count = 2`).
/// Splits `uniform96` into two 48-byte big-endian slices, maps each via
/// `map_to_curve_sswu`, and returns their sum (cofactor `h_eff = 1`).
/// Returns `None` if `uniform96.length() != 96`.
pub fn Point::hash_to_curve_from_uniform(uniform96 : Bytes) -> Point? {
  if uniform96.length() != 96 {
    return None
  }
  let u0 = uniform96[0:48].to_owned()
  let u1 = uniform96[48:96].to_owned()
  let q0 = match Point::map_to_curve_sswu(u0) {
    Some(p) => p
    None => return None
  }
  let q1 = match Point::map_to_curve_sswu(u1) {
    Some(p) => p
    None => return None
  }
  Some(q0.add(q1))
}
