///|
fn wb_hex_to_bytes(hex : String) -> Bytes {
  let clean : Array[Byte] = []
  let mut hi = -1
  for c in hex {
    let v = match c {
      '0'..<='9' => c.to_int() - '0'.to_int()
      'a'..<='f' => c.to_int() - 'a'.to_int() + 10
      'A'..<='F' => c.to_int() - 'A'.to_int() + 10
      ' ' | '\n' | '\r' | '\t' => -1
      _ => abort("invalid hex char")
    }
    if v >= 0 {
      if hi < 0 {
        hi = v
      } else {
        clean.push(((hi << 4) | v).to_byte())
        hi = -1
      }
    }
  }
  Bytes::from_array(clean[:])
}

///|
/// RFC 9496 Appendix A.4: Square Root of a Ratio of Field Elements (all 6 vectors).
test "rfc9496 appendix a.4 sqrt_ratio_m1" {
  let vectors : Array[(String, String, Bool, String)] = [
    (
      "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000",
      true, "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
      true, "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0100000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000",
      false, "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0200000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
      false, "3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54",
    ),
    (
      "0400000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000",
      true, "0200000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "0100000000000000000000000000000000000000000000000000000000000000", "0400000000000000000000000000000000000000000000000000000000000000",
      true, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
    ),
  ]
  for v in vectors {
    let (u_hex, v_hex, expected_sq, r_hex) = v
    let (u_ok, u) = FieldElement::from_bytes_canonical(wb_hex_to_bytes(u_hex))
    let (v_ok, vv) = FieldElement::from_bytes_canonical(wb_hex_to_bytes(v_hex))
    assert_eq(u_ok, 1L)
    assert_eq(v_ok, 1L)
    let (was_sq, r) = sqrt_ratio_m1(u, vv)
    assert_eq(was_sq == 1L, expected_sq)
    assert_eq(r.to_bytes(), wb_hex_to_bytes(r_hex))
  }
}

///|
test "field arithmetic identities and non-canonical coset identity" {
  // Constants sanity checks in GF(p).
  let one = FieldElement::one()
  let zero = FieldElement::zero()
  assert_eq(fe_sqrt_m1.square().add(one).ct_is_zero(), 1L)
  assert_eq(fe_minus_one.add(one).ct_is_zero(), 1L)
  assert_eq(fe_minus_one.neg().ct_eq(one), 1L)
  assert_eq(zero.neg().ct_is_zero(), 1L)
  assert_eq(fe_d.add(fe_d).ct_eq(fe_two_d), 1L)
  assert_eq(fe_sqrt_ad_minus_one.square().ct_eq(fe_d.neg().sub(one)), 1L)
  assert_eq(
    fe_invsqrt_a_minus_d.square().mul(fe_minus_one.sub(fe_d)).ct_eq(one),
    1L,
  )
  assert_eq(fe_one_minus_d_sq.ct_eq(one.sub(fe_d.square())), 1L)
  assert_eq(fe_d_minus_one_sq.ct_eq(fe_d.sub(one).square()), 1L)
  // 4-torsion coset representatives of ristretto255 identity:
  // (0, 1, 1, 0), (0, -1, 1, 0), (i, 0, 1, 0), (-i, 0, 1, 0)
  let id0 = Element::identity()
  let id1 : Element = { x: zero, y: fe_minus_one, z: one, t: zero, }
  let id2 : Element = { x: fe_sqrt_m1, y: zero, z: one, t: zero, }
  let id3 : Element = { x: fe_sqrt_m1.neg(), y: zero, z: one, t: zero, }
  let zero_bytes = Bytes::make(32, b'\x00')
  for pt in [id0, id1, id2, id3] {
    assert_true(pt.is_identity())
    assert_true(pt.equal(id0))
    assert_eq(pt.to_bytes(), zero_bytes)
  }
}
