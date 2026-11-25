///|
/// Element of the NIST P-256 base prime field GF(p), stored in Montgomery form.
/// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
///   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
priv struct Fe(U256)

///|
let p_mod : U256 = u256_from_limbs(
  0xffffffffU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U,
  0xffffffffU,
)

///|
let p0_inv : UInt32 = 0x00000001U

///|
/// R mod p (Montgomery representation of 1).
let p_r : U256 = u256_from_limbs(
  0x00000001U, 0x00000000U, 0x00000000U, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xfffffffeU,
  0x00000000U,
)

///|
/// R^2 mod p (used to convert standard form into Montgomery form).
let p_r2 : U256 = u256_from_limbs(
  0x00000003U, 0x00000000U, 0xffffffffU, 0xfffffffbU, 0xfffffffeU, 0xffffffffU, 0xfffffffdU,
  0x00000004U,
)

///|
/// 2^32 * R mod p (used for Horner reduction mod p).
let p_mont_2_32 : U256 = u256_from_limbs(
  0x00000000U, 0x00000001U, 0x00000000U, 0x00000000U, 0xffffffffU, 0xffffffffU, 0xffffffffU,
  0xfffffffeU,
)

///|
/// p - 2 = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd
let p_minus_2 : U256 = u256_from_limbs(
  0xfffffffdU, 0xffffffffU, 0xffffffffU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U,
  0xffffffffU,
)

///|
/// (p + 1) / 4 = 0x3fffffffc0000000400000000000000000000000400000000000000000000000
let p_plus_1_div_4 : U256 = u256_from_limbs(
  0x00000000U, 0x00000000U, 0x40000000U, 0x00000000U, 0x00000000U, 0x40000000U, 0xc0000000U,
  0x3fffffffU,
)

///|
/// (p - 3) / 4 = 0x3fffffffc00000004000000000000000000000003fffffffffffffffffffffff
let p_minus_3_div_4 : U256 = u256_from_limbs(
  0xffffffffU, 0xffffffffU, 0x3fffffffU, 0x00000000U, 0x00000000U, 0x40000000U, 0xc0000000U,
  0x3fffffffU,
)

///|
/// Curve parameter b in Montgomery form.
let p_b_mont : Fe = Fe(
  u256_from_limbs(
    0x29c4bddfU, 0xd89cdf62U, 0x78843090U, 0xacf005cdU, 0xf7212ed6U, 0xe5a220abU,
    0x04874834U, 0xdc30061dU,
  ),
)

///|
/// Generator G.x in Montgomery form.
let p_gx_mont : Fe = Fe(
  u256_from_limbs(
    0x18a9143cU, 0x79e730d4U, 0x5fedb601U, 0x75ba95fcU, 0x77622510U, 0x79fb732bU,
    0xa53755c6U, 0x18905f76U,
  ),
)

///|
/// Generator G.y in Montgomery form.
let p_gy_mont : Fe = Fe(
  u256_from_limbs(
    0xce95560aU, 0xddf25357U, 0xba19e45cU, 0x8b4ab8e4U, 0xdd21f325U, 0xd2e88688U,
    0x25885d85U, 0x8571ff18U,
  ),
)

///|
/// RFC 9380 SSWU constant Z = -10 mod p in Montgomery form.
let p_sswu_z_mont : Fe = Fe(
  u256_from_limbs(
    0xfffffff5U, 0xffffffffU, 0xffffffffU, 0x0000000aU, 0x00000000U, 0x00000000U,
    0x0000000bU, 0xfffffff5U,
  ),
)

///|
/// RFC 9380 Appendix F.2.1.2 constant c2 = sqrt(-Z) = sqrt(10) mod p in Montgomery form.
let p_sswu_c2_mont : Fe = Fe(
  u256_from_limbs(
    0x98a195fdU, 0xa1fd38eeU, 0x423dcf70U, 0x78400ad7U, 0x9ea8dfeeU, 0x6913c88fU,
    0x12a8f304U, 0x9051d26eU,
  ),
)

///|
fn fe_zero() -> Fe {
  Fe(u256_zero())
}

///|
fn fe_one() -> Fe {
  Fe(p_r)
}

///|
fn fe_to_standard(a : Fe) -> U256 {
  u256_mont_mul(a.0, u256_from_u32(1U), p_mod, p0_inv)
}

///|
fn fe_from_standard(a : U256) -> Fe {
  Fe(u256_mont_mul(a, p_r2, p_mod, p0_inv))
}

///|
fn fe_add(a : Fe, b : Fe) -> Fe {
  Fe(u256_mod_add(a.0, b.0, p_mod))
}

///|
fn fe_sub(a : Fe, b : Fe) -> Fe {
  Fe(u256_mod_sub(a.0, b.0, p_mod))
}

///|
fn fe_neg(a : Fe) -> Fe {
  Fe(u256_mod_sub(u256_zero(), a.0, p_mod))
}

///|
fn fe_mul(a : Fe, b : Fe) -> Fe {
  Fe(u256_mont_mul(a.0, b.0, p_mod, p0_inv))
}

///|
fn fe_sqr(a : Fe) -> Fe {
  Fe(u256_mont_mul(a.0, a.0, p_mod, p0_inv))
}

///|
/// Multiply by -3 mod p (curve parameter A = -3).
fn fe_mul_a(a : Fe) -> Fe {
  let a2 = fe_add(a, a)
  let a3 = fe_add(a2, a)
  fe_neg(a3)
}

///|
fn fe_is_zero_mask(a : Fe) -> UInt32 {
  u256_is_zero_mask(a.0)
}

///|
fn fe_is_zero(a : Fe) -> Bool {
  u256_is_zero(a.0)
}

///|
fn fe_ct_equal_mask(a : Fe, b : Fe) -> UInt32 {
  u256_ct_equal_mask(a.0, b.0)
}

///|
fn fe_ct_equal(a : Fe, b : Fe) -> Bool {
  u256_ct_equal(a.0, b.0)
}

///|
fn fe_ct_select(if_false : Fe, if_true : Fe, mask : UInt32) -> Fe {
  Fe(u256_ct_select(if_false.0, if_true.0, mask))
}

///|
/// Returns `0U` if canonical `a` is even, `1U` if odd (RFC 9380 `sgn0_m_eq_1`).
fn fe_sgn0(a : Fe) -> UInt32 {
  let std = fe_to_standard(a)
  std.0[0] & 1U
}

///|
/// Constant-time modular inversion: `a^(p - 2) mod p` (returns 0 for input 0).
fn fe_invert(a : Fe) -> Fe {
  Fe(u256_mont_pow_const(a.0, p_minus_2, p_r, p_mod, p0_inv))
}

///|
/// Candidate square root in GF(p) for p ≡ 3 (mod 4): `a^((p + 1) / 4) mod p`.
fn fe_sqrt_candidate(a : Fe) -> Fe {
  Fe(u256_mont_pow_const(a.0, p_plus_1_div_4, p_r, p_mod, p0_inv))
}

///|
/// Raises `a` to `c1 = (p - 3) / 4` mod p (RFC 9380 Appendix F.2.1.2).
fn fe_pow_c1(a : Fe) -> Fe {
  Fe(u256_mont_pow_const(a.0, p_minus_3_div_4, p_r, p_mod, p0_inv))
}

///|
/// Decode 32 big-endian bytes strictly `< p`.
fn fe_from_bytes_canonical(bytes : Bytes) -> Fe? {
  if bytes.length() != 32 {
    return None
  }
  let v = u256_from_be_bytes_32(bytes)
  if !u256_lt(v, p_mod) {
    return None
  }
  Some(fe_from_standard(v))
}

///|
/// Reduce arbitrary non-empty big-endian bytes modulo `p`.
fn fe_from_bytes_be_mod_p(bytes : Bytes) -> Fe? {
  match u256_from_be_bytes_mod_m_mont(bytes, p_mod, p0_inv, p_r2, p_mont_2_32) {
    Some(v) => Some(Fe(v))
    None => None
  }
}

///|
/// Encode a field element to 32 big-endian bytes.
fn fe_to_bytes(a : Fe) -> Bytes {
  u256_to_be_bytes_32(fe_to_standard(a))
}
