///|
/// Internal 256-bit unsigned integer represented as 8 little-endian 32-bit limbs.
priv struct U256(FixedArray[UInt32])

///|
/// Constant-time mask: returns `0xFFFFFFFFU` if `v == 0U`, else `0U`.
fn ct_is_zero_u32(v : UInt32) -> UInt32 {
  let nz = (v | (0U - v)) >> 31
  nz - 1U
}

///|
/// Constant-time mask: returns `0xFFFFFFFFU` if `a == b`, else `0U`.
fn ct_eq_u32(a : UInt32, b : UInt32) -> UInt32 {
  ct_is_zero_u32(a ^ b)
}

///|
fn u256_zero() -> U256 {
  U256(FixedArray::make(8, 0U))
}

///|
fn u256_from_limbs(
  l0 : UInt32,
  l1 : UInt32,
  l2 : UInt32,
  l3 : UInt32,
  l4 : UInt32,
  l5 : UInt32,
  l6 : UInt32,
  l7 : UInt32,
) -> U256 {
  let arr = FixedArray::make(8, 0U)
  arr[0] = l0
  arr[1] = l1
  arr[2] = l2
  arr[3] = l3
  arr[4] = l4
  arr[5] = l5
  arr[6] = l6
  arr[7] = l7
  U256(arr)
}

///|
fn u256_from_u32(v : UInt32) -> U256 {
  let arr = FixedArray::make(8, 0U)
  arr[0] = v
  U256(arr)
}

///|
/// Constant-time zero check: returns `0xFFFFFFFFU` if `a == 0`, else `0U`.
fn u256_is_zero_mask(a : U256) -> UInt32 {
  let mut acc = 0U
  for i = 0; i < 8; i = i + 1 {
    acc = acc | a.0[i]
  }
  ct_is_zero_u32(acc)
}

///|
fn u256_is_zero(a : U256) -> Bool {
  u256_is_zero_mask(a) != 0U
}

///|
/// Constant-time equality: returns `0xFFFFFFFFU` if `a == b`, else `0U`.
fn u256_ct_equal_mask(a : U256, b : U256) -> UInt32 {
  let mut diff = 0U
  for i = 0; i < 8; i = i + 1 {
    diff = diff | (a.0[i] ^ b.0[i])
  }
  ct_is_zero_u32(diff)
}

///|
fn u256_ct_equal(a : U256, b : U256) -> Bool {
  u256_ct_equal_mask(a, b) != 0U
}

///|
/// Constant-time conditional select: returns `if_true` when `mask == 0xFFFFFFFFU`,
/// `if_false` when `mask == 0U`.
fn u256_ct_select(if_false : U256, if_true : U256, mask : UInt32) -> U256 {
  let nmask = mask.lnot()
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = (if_false.0[i] & nmask) | (if_true.0[i] & mask)
  }
  U256(out)
}

///|
/// Returns true iff `a < b` (constant-time).
fn u256_lt(a : U256, b : U256) -> Bool {
  let mut borrow = 0UL
  for i = 0; i < 8; i = i + 1 {
    let diff = a.0[i].to_uint64() - b.0[i].to_uint64() - borrow
    borrow = (diff >> 63) & 1UL
  }
  borrow != 0UL
}

///|
/// Decode 32 big-endian bytes into a `U256`. Caller guarantees `bytes.length() == 32`.
fn u256_from_be_bytes_32(bytes : Bytes) -> U256 {
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    let off = (7 - i) * 4
    let b0 = bytes[off].to_uint()
    let b1 = bytes[off + 1].to_uint()
    let b2 = bytes[off + 2].to_uint()
    let b3 = bytes[off + 3].to_uint()
    out[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }
  U256(out)
}

///|
/// Encode a `U256` to 32 big-endian bytes.
fn u256_to_be_bytes_32(a : U256) -> Bytes {
  let buf = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let w = a.0[7 - i]
    let off = i * 4
    buf[off] = ((w >> 24) & 0xFFU).to_byte()
    buf[off + 1] = ((w >> 16) & 0xFFU).to_byte()
    buf[off + 2] = ((w >> 8) & 0xFFU).to_byte()
    buf[off + 3] = (w & 0xFFU).to_byte()
  }
  Bytes::from_array(buf)
}

///|
/// Constant-time modular addition `(a + b) mod m`, assuming `0 <= a, b < m`.
fn u256_mod_add(a : U256, b : U256, m : U256) -> U256 {
  let s = FixedArray::make(8, 0U)
  let mut carry = 0UL
  for i = 0; i < 8; i = i + 1 {
    let acc = a.0[i].to_uint64() + b.0[i].to_uint64() + carry
    s[i] = acc.to_uint()
    carry = acc >> 32
  }
  let d = FixedArray::make(8, 0U)
  let mut borrow = 0UL
  for i = 0; i < 8; i = i + 1 {
    let diff = s[i].to_uint64() - m.0[i].to_uint64() - borrow
    d[i] = diff.to_uint()
    borrow = (diff >> 63) & 1UL
  }
  // underflow == 1 iff s < m (keep s); else select d (s - m)
  let underflow = ((carry - borrow) >> 63).to_uint()
  let keep_s = 0U - underflow
  let take_d = keep_s.lnot()
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = (s[i] & keep_s) | (d[i] & take_d)
  }
  U256(out)
}

///|
/// Constant-time modular subtraction `(a - b) mod m`, assuming `0 <= a, b < m`.
fn u256_mod_sub(a : U256, b : U256, m : U256) -> U256 {
  let d = FixedArray::make(8, 0U)
  let mut borrow = 0UL
  for i = 0; i < 8; i = i + 1 {
    let diff = a.0[i].to_uint64() - b.0[i].to_uint64() - borrow
    d[i] = diff.to_uint()
    borrow = (diff >> 63) & 1UL
  }
  let s = FixedArray::make(8, 0U)
  let mut carry = 0UL
  for i = 0; i < 8; i = i + 1 {
    let acc = d[i].to_uint64() + m.0[i].to_uint64() + carry
    s[i] = acc.to_uint()
    carry = acc >> 32
  }
  // borrow == 1 iff a < b (select d + m); else select d
  let mask = 0U - borrow.to_uint()
  let nmask = mask.lnot()
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = (d[i] & nmask) | (s[i] & mask)
  }
  U256(out)
}

///|
/// Constant-time CIOS Montgomery multiplication: computes `a * b * R^(-1) mod m`
/// where `R = 2^256`, `m0_inv = -m[0]^(-1) mod 2^32`, and `0 <= a, b < m`.
fn u256_mont_mul(a : U256, b : U256, m : U256, m0_inv : UInt32) -> U256 {
  let t = FixedArray::make(10, 0U)
  for i = 0; i < 8; i = i + 1 {
    let bi = b.0[i].to_uint64()
    let mut c = 0UL
    for j = 0; j < 8; j = j + 1 {
      let acc = t[j].to_uint64() + a.0[j].to_uint64() * bi + c
      t[j] = acc.to_uint()
      c = acc >> 32
    }
    let acc_hi = t[8].to_uint64() + c
    t[8] = acc_hi.to_uint()
    t[9] = (acc_hi >> 32).to_uint()

    let q = (t[0] * m0_inv).to_uint64()
    let acc0 = t[0].to_uint64() + q * m.0[0].to_uint64()
    c = acc0 >> 32
    for j = 1; j < 8; j = j + 1 {
      let acc = t[j].to_uint64() + q * m.0[j].to_uint64() + c
      t[j - 1] = acc.to_uint()
      c = acc >> 32
    }
    let acc8 = t[8].to_uint64() + c
    t[7] = acc8.to_uint()
    c = acc8 >> 32
    t[8] = t[9] + c.to_uint()
  }
  // Final conditional subtraction: t < 2*m
  let d = FixedArray::make(8, 0U)
  let mut borrow = 0UL
  for i = 0; i < 8; i = i + 1 {
    let diff = t[i].to_uint64() - m.0[i].to_uint64() - borrow
    d[i] = diff.to_uint()
    borrow = (diff >> 63) & 1UL
  }
  let underflow = ((t[8].to_uint64() - borrow) >> 63).to_uint()
  let keep_t = 0U - underflow
  let take_d = keep_t.lnot()
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = (t[i] & keep_t) | (d[i] & take_d)
  }
  U256(out)
}

///|
/// Constant-time exponentiation in Montgomery form for a public 256-bit exponent `exp`.
fn u256_mont_pow_const(
  base : U256,
  exp : U256,
  mont_one : U256,
  m : U256,
  m0_inv : UInt32,
) -> U256 {
  let mut res = mont_one
  let mut started = false
  for limb_idx = 7; limb_idx >= 0; limb_idx = limb_idx - 1 {
    let w = exp.0[limb_idx]
    for bit = 31; bit >= 0; bit = bit - 1 {
      let set = ((w >> bit) & 1U) != 0U
      if started {
        res = u256_mont_mul(res, res, m, m0_inv)
      }
      if set {
        if started {
          res = u256_mont_mul(res, base, m, m0_inv)
        } else {
          res = base
          started = true
        }
      }
    }
  }
  res
}

///|
/// Reduce an arbitrary non-empty big-endian byte string modulo `m` into Montgomery form.
fn u256_from_be_bytes_mod_m_mont(
  bytes : Bytes,
  m : U256,
  m0_inv : UInt32,
  r2 : U256,
  mont_2_32 : U256,
) -> U256? {
  let len = bytes.length()
  if len == 0 {
    return None
  }
  let rem = len % 4
  let mut acc = u256_zero()
  if rem > 0 {
    let mut w = 0U
    for i = 0; i < rem; i = i + 1 {
      w = (w << 8) | bytes[i].to_uint()
    }
    acc = u256_mont_mul(u256_from_u32(w), r2, m, m0_inv)
  }
  let mut off = rem
  while off < len {
    let w = (bytes[off].to_uint() << 24) |
      (bytes[off + 1].to_uint() << 16) |
      (bytes[off + 2].to_uint() << 8) |
      bytes[off + 3].to_uint()
    let w_mont = u256_mont_mul(u256_from_u32(w), r2, m, m0_inv)
    acc = u256_mod_add(u256_mont_mul(acc, mont_2_32, m, m0_inv), w_mont, m)
    off = off + 4
  }
  Some(acc)
}
