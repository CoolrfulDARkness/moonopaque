///|
/// Whitebox tests verifying GF(2^255 - 19) field arithmetic invariants.
test "field arithmetic square, mul_a24, invert, cswap, and non-canonical decode" {
  // 0.invert() == 0
  let zero = FieldElement::zero()
  let one = FieldElement::one()
  assert_eq(zero.invert().to_bytes(), zero.to_bytes())
  assert_eq(one.invert().to_bytes(), one.to_bytes())

  // Test square() == mul(self), invert() * x == 1, mul_a24() == mul(121665)
  let fe_a24 : FieldElement = {
    h0: 121665L,
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
  let samples : Array[Bytes] = [
    b"\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\xec\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
    b"\xe6\xdb\x68\x67\x58\x30\x30\xdb\x35\x94\xc1\xa4\x24\xb1\x5f\x7c\x72\x66\x24\xec\x26\xb3\x35\x3b\x10\xa9\x03\xa6\xd0\xab\x1c\x4c",
    b"\xe5\x21\x0f\x12\x78\x68\x11\xd3\xf4\xb7\x95\x9d\x05\x38\xae\x2c\x31\xdb\xe7\x10\x6f\xc0\x3c\x3e\xfc\x4c\xd5\x49\xc7\x15\xa4\x93",
  ]
  for raw in samples {
    let x = FieldElement::from_bytes_masked(raw)
    assert_eq(x.square().to_bytes(), x.mul(x).to_bytes())
    assert_eq(x.mul(x.invert()).to_bytes(), one.to_bytes())
    assert_eq(x.mul_a24().to_bytes(), x.mul(fe_a24).to_bytes())
    // cswap with 0 and 1
    let (a0, b0) = fe_cswap(0L, x, one)
    assert_eq(a0.to_bytes(), x.to_bytes())
    assert_eq(b0.to_bytes(), one.to_bytes())
    let (a1, b1) = fe_cswap(1L, x, one)
    assert_eq(a1.to_bytes(), one.to_bytes())
    assert_eq(b1.to_bytes(), x.to_bytes())
  }

  // Non-canonical p = 2^255 - 19 reduces to 0, p + 1 reduces to 1, 2^255 - 1 reduces to 18
  let fe_p = FieldElement::from_bytes_masked(
    b"\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
  )
  assert_eq(fe_p.to_bytes(), zero.to_bytes())
  let fe_p_plus_1 = FieldElement::from_bytes_masked(
    b"\xee\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
  )
  assert_eq(fe_p_plus_1.to_bytes(), one.to_bytes())
  let fe_max = FieldElement::from_bytes_masked(Bytes::make(32, b'\xff'))
  let expected_18 = FixedArray::make(32, b'\x00')
  expected_18[0] = b'\x12'
  assert_eq(fe_max.to_bytes(), Bytes::from_array(expected_18[:]))
}
