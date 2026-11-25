///|
fn must_hex(hex : String) -> Bytes {
  match @hash.hex_decode(hex) {
    Some(b) => b
    None => abort("invalid hex literal in test")
  }
}

///|
test "suite constants and context strings" {
  assert_eq(@oprf.element_len(@oprf.Ristretto255Sha512), 32)
  assert_eq(@oprf.scalar_len(@oprf.Ristretto255Sha512), 32)
  assert_eq(@oprf.output_len(@oprf.Ristretto255Sha512), 64)
  assert_eq(
    @oprf.context_string(@oprf.Ristretto255Sha512),
    b"OPRFV1-\x00-ristretto255-SHA512",
  )

  assert_eq(@oprf.element_len(@oprf.P256Sha256), 33)
  assert_eq(@oprf.scalar_len(@oprf.P256Sha256), 32)
  assert_eq(@oprf.output_len(@oprf.P256Sha256), 32)
  assert_eq(@oprf.context_string(@oprf.P256Sha256), b"OPRFV1-\x00-P256-SHA256")
}

///|
/// RFC 9497 Appendix A.1.1: OPRF(ristretto255, SHA-512) DeriveKeyPair + Test Vectors 1 & 2.
test "rfc9497 appendix a.1.1 ristretto255-sha512 oprf vectors" {
  let suite = @oprf.Ristretto255Sha512
  let seed = must_hex(
    "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
  )
  let key_info = must_hex("74657374206b6579")
  let expected_sk = must_hex(
    "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
  )

  // DeriveKeyPair
  let (sk_s, pk_s) = match @oprf.derive_key_pair(suite, seed, key_info) {
    Ok(kp) => kp
    Err(e) => abort("derive_key_pair failed: " + Show::to_string(e))
  }
  assert_eq(sk_s, expected_sk)
  assert_eq(pk_s.length(), 32)
  let sk_scalar = @ristretto255.Scalar::from_bytes_canonical(sk_s).unwrap()
  assert_eq(pk_s, @ristretto255.Element::base_mul(sk_scalar).to_bytes())

  // A.1.1.1 Test Vector 1, Batch Size 1
  let input1 = must_hex("00")
  let blind1 = must_hex(
    "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
  )
  let expected_blinded1 = must_hex(
    "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
  )
  let expected_eval1 = must_hex(
    "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
  )
  let expected_out1 = must_hex(
    "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
  )

  let (state1, blinded1) = match
    @oprf.blind_with_scalar(suite, input1, blind1) {
    Ok(v) => v
    Err(e) => abort("blind_with_scalar tv1 failed: " + Show::to_string(e))
  }
  assert_eq(state1.suite(), suite)
  assert_eq(state1.blind_bytes(), blind1)
  assert_eq(blinded1, expected_blinded1)

  let eval1 = match @oprf.blind_evaluate(suite, sk_s, blinded1) {
    Ok(v) => v
    Err(e) => abort("blind_evaluate tv1 failed: " + Show::to_string(e))
  }
  assert_eq(eval1, expected_eval1)

  let out1 = match @oprf.finalize(state1, input1, eval1) {
    Ok(v) => v
    Err(e) => abort("finalize tv1 failed: " + Show::to_string(e))
  }
  assert_eq(out1, expected_out1)

  let direct1 = match @oprf.evaluate(suite, sk_s, input1) {
    Ok(v) => v
    Err(e) => abort("evaluate tv1 failed: " + Show::to_string(e))
  }
  assert_eq(direct1, expected_out1)

  // A.1.1.2 Test Vector 2, Batch Size 1
  let input2 = must_hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
  let blind2 = must_hex(
    "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
  )
  let expected_blinded2 = must_hex(
    "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
  )
  let expected_eval2 = must_hex(
    "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
  )
  let expected_out2 = must_hex(
    "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
  )

  let (state2, blinded2) = match
    @oprf.blind_with_scalar(suite, input2, blind2) {
    Ok(v) => v
    Err(e) => abort("blind_with_scalar tv2 failed: " + Show::to_string(e))
  }
  assert_eq(blinded2, expected_blinded2)

  let eval2 = match @oprf.blind_evaluate(suite, sk_s, blinded2) {
    Ok(v) => v
    Err(e) => abort("blind_evaluate tv2 failed: " + Show::to_string(e))
  }
  assert_eq(eval2, expected_eval2)

  let out2 = match @oprf.finalize(state2, input2, eval2) {
    Ok(v) => v
    Err(e) => abort("finalize tv2 failed: " + Show::to_string(e))
  }
  assert_eq(out2, expected_out2)

  let direct2 = match @oprf.evaluate(suite, sk_s, input2) {
    Ok(v) => v
    Err(e) => abort("evaluate tv2 failed: " + Show::to_string(e))
  }
  assert_eq(direct2, expected_out2)
}

///|
/// RFC 9497 Appendix A.3.1: OPRF(P-256, SHA-256) DeriveKeyPair + Test Vectors 1 & 2.
test "rfc9497 appendix a.3.1 p256-sha256 oprf vectors" {
  let suite = @oprf.P256Sha256
  let seed = must_hex(
    "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
  )
  let key_info = must_hex("74657374206b6579")
  let expected_sk = must_hex(
    "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf",
  )

  // DeriveKeyPair
  let (sk_s, pk_s) = match @oprf.derive_key_pair(suite, seed, key_info) {
    Ok(kp) => kp
    Err(e) => abort("derive_key_pair failed: " + Show::to_string(e))
  }
  assert_eq(sk_s, expected_sk)
  assert_eq(pk_s.length(), 33)
  let sk_scalar = @p256.Scalar::from_bytes_canonical(sk_s).unwrap()
  assert_eq(pk_s, @p256.Point::base_mul(sk_scalar).to_bytes_compressed())

  // A.3.1.1 Test Vector 1, Batch Size 1
  let input1 = must_hex("00")
  let blind1 = must_hex(
    "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
  )
  let expected_blinded1 = must_hex(
    "03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d",
  )
  let expected_eval1 = must_hex(
    "030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832",
  )
  let expected_out1 = must_hex(
    "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd",
  )

  let (state1, blinded1) = match
    @oprf.blind_with_scalar(suite, input1, blind1) {
    Ok(v) => v
    Err(e) => abort("blind_with_scalar tv1 failed: " + Show::to_string(e))
  }
  assert_eq(state1.suite(), suite)
  assert_eq(state1.blind_bytes(), blind1)
  assert_eq(blinded1, expected_blinded1)

  let eval1 = match @oprf.blind_evaluate(suite, sk_s, blinded1) {
    Ok(v) => v
    Err(e) => abort("blind_evaluate tv1 failed: " + Show::to_string(e))
  }
  assert_eq(eval1, expected_eval1)

  let out1 = match @oprf.finalize(state1, input1, eval1) {
    Ok(v) => v
    Err(e) => abort("finalize tv1 failed: " + Show::to_string(e))
  }
  assert_eq(out1, expected_out1)

  let direct1 = match @oprf.evaluate(suite, sk_s, input1) {
    Ok(v) => v
    Err(e) => abort("evaluate tv1 failed: " + Show::to_string(e))
  }
  assert_eq(direct1, expected_out1)

  // A.3.1.2 Test Vector 2, Batch Size 1
  let input2 = must_hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
  let blind2 = must_hex(
    "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
  )
  let expected_blinded2 = must_hex(
    "03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838",
  )
  let expected_eval2 = must_hex(
    "03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c",
  )
  let expected_out2 = must_hex(
    "c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce",
  )

  let (state2, blinded2) = match
    @oprf.blind_with_scalar(suite, input2, blind2) {
    Ok(v) => v
    Err(e) => abort("blind_with_scalar tv2 failed: " + Show::to_string(e))
  }
  assert_eq(blinded2, expected_blinded2)

  let eval2 = match @oprf.blind_evaluate(suite, sk_s, blinded2) {
    Ok(v) => v
    Err(e) => abort("blind_evaluate tv2 failed: " + Show::to_string(e))
  }
  assert_eq(eval2, expected_eval2)

  let out2 = match @oprf.finalize(state2, input2, eval2) {
    Ok(v) => v
    Err(e) => abort("finalize tv2 failed: " + Show::to_string(e))
  }
  assert_eq(out2, expected_out2)

  let direct2 = match @oprf.evaluate(suite, sk_s, input2) {
    Ok(v) => v
    Err(e) => abort("evaluate tv2 failed: " + Show::to_string(e))
  }
  assert_eq(direct2, expected_out2)
}

///|
test "blind_from_random_bytes roundtrip and oblivious consistency" {
  let suites : Array[@oprf.OprfSuite] = [
    @oprf.Ristretto255Sha512,
    @oprf.P256Sha256,
  ]
  let seed = Bytes::make(32, b'\x42')
  let inputs : Array[Bytes] = [b"", b"correct horse battery staple"]
  for suite in suites {
    let (sk_s, _) = @oprf.derive_key_pair(suite, seed, b"OPAQUE-DeriveKeyPair").unwrap()
    for input in inputs {
      let rand1 = Bytes::make(32, b'\x11')
      let rand2 = Bytes::make(32, b'\x22')
      let (st1, blinded1) = @oprf.blind_from_random_bytes(suite, input, rand1).unwrap()
      let (st2, blinded2) = @oprf.blind_from_random_bytes(suite, input, rand2).unwrap()
      assert_true(blinded1 != blinded2)
      assert_true(st1.blind_bytes() != st2.blind_bytes())
      assert_eq(blinded1.length(), @oprf.element_len(suite))
      assert_eq(st1.blind_bytes().length(), @oprf.scalar_len(suite))

      let eval1 = @oprf.blind_evaluate(suite, sk_s, blinded1).unwrap()
      let eval2 = @oprf.blind_evaluate(suite, sk_s, blinded2).unwrap()
      let out1 = @oprf.finalize(st1, input, eval1).unwrap()
      let out2 = @oprf.finalize(st2, input, eval2).unwrap()
      let direct = @oprf.evaluate(suite, sk_s, input).unwrap()
      assert_eq(out1, direct)
      assert_eq(out2, direct)
      assert_eq(out1.length(), @oprf.output_len(suite))
    }
  }
}

///|
test "hash_to_group and hash_to_scalar basic and oversize dst" {
  let long_dst = Bytes::make(300, b'\x61')
  for suite in [@oprf.Ristretto255Sha512, @oprf.P256Sha256] {
    let g1 = @oprf.hash_to_group(suite, b"abc", b"custom-dst").unwrap()
    let g2 = @oprf.hash_to_group(suite, b"abc", b"custom-dst").unwrap()
    let g3 = @oprf.hash_to_group(suite, b"abc", long_dst).unwrap()
    assert_eq(g1, g2)
    assert_eq(g1.length(), @oprf.element_len(suite))
    assert_eq(g3.length(), @oprf.element_len(suite))
    assert_true(g1 != g3)

    let s1 = @oprf.hash_to_scalar(suite, b"abc", b"custom-dst").unwrap()
    let s2 = @oprf.hash_to_scalar(suite, b"abc", b"custom-dst").unwrap()
    let s3 = @oprf.hash_to_scalar(suite, b"abc", long_dst).unwrap()
    assert_eq(s1, s2)
    assert_eq(s1.length(), @oprf.scalar_len(suite))
    assert_eq(s3.length(), @oprf.scalar_len(suite))
    assert_true(s1 != s3)
  }
}

///|
test "negative security checks: zero and invalid scalars" {
  let zero32 = Bytes::make(32, b'\x00')
  let all_ff32 = Bytes::make(32, b'\xff')
  let short_scalar = Bytes::make(31, b'\x01')
  let long_scalar = Bytes::make(33, b'\x01')
  // Group orders (non-canonical: equal to order)
  let ristretto_order = must_hex(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let p256_order = must_hex(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
  )

  for suite in [@oprf.Ristretto255Sha512, @oprf.P256Sha256] {
    let valid_blind = @oprf.hash_to_scalar(suite, b"seed", b"dst").unwrap()
    let (_, valid_blinded) = @oprf.blind_with_scalar(suite, b"msg", valid_blind).unwrap()
    let order_bytes = match suite {
      @oprf.Ristretto255Sha512 => ristretto_order
      @oprf.P256Sha256 => p256_order
    }

    // Zero blind scalar rejected
    assert_true(
      @oprf.blind_with_scalar(suite, b"msg", zero32) is Err(@oprf.ZeroScalar),
    )

    // Non-canonical / wrong-length blind scalars rejected
    assert_true(
      @oprf.blind_with_scalar(suite, b"msg", all_ff32)
      is Err(@oprf.InvalidScalar),
    )
    assert_true(
      @oprf.blind_with_scalar(suite, b"msg", order_bytes)
      is Err(@oprf.InvalidScalar),
    )
    assert_true(
      @oprf.blind_with_scalar(suite, b"msg", short_scalar)
      is Err(@oprf.InvalidScalar),
    )
    assert_true(
      @oprf.blind_with_scalar(suite, b"msg", long_scalar)
      is Err(@oprf.InvalidScalar),
    )

    // Zero & invalid server secret keys rejected in blind_evaluate & evaluate
    assert_true(
      @oprf.blind_evaluate(suite, zero32, valid_blinded)
      is Err(@oprf.ZeroScalar),
    )
    assert_true(
      @oprf.blind_evaluate(suite, all_ff32, valid_blinded)
      is Err(@oprf.InvalidScalar),
    )
    assert_true(
      @oprf.blind_evaluate(suite, order_bytes, valid_blinded)
      is Err(@oprf.InvalidScalar),
    )
    assert_true(@oprf.evaluate(suite, zero32, b"msg") is Err(@oprf.ZeroScalar))
    assert_true(
      @oprf.evaluate(suite, all_ff32, b"msg") is Err(@oprf.InvalidScalar),
    )
    assert_true(
      @oprf.evaluate(suite, order_bytes, b"msg") is Err(@oprf.InvalidScalar),
    )
  }
}

///|
test "negative security checks: identity, off-curve, and invalid elements" {
  // Ristretto255 invalid & identity elements
  let r_suite = @oprf.Ristretto255Sha512
  let (r_sk, _) = @oprf.derive_key_pair(r_suite, Bytes::make(32, b'\x07'), b"k").unwrap()
  let (r_state, _) = @oprf.blind_from_random_bytes(
    r_suite,
    b"hello",
    Bytes::make(32, b'\x09'),
  ).unwrap()
  let r_bad_elements : Array[Bytes] = [
    // Identity element (all zeros)
    Bytes::make(32, b'\x00'),
    // Non-canonical encoding (RFC 9496 A.2)
    must_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    // Negative field element (odd LSB)
    must_hex("0100000000000000000000000000000000000000000000000000000000000000"),
    // Non-square x^2 (RFC 9496 A.2)
    must_hex("26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"),
    // Wrong lengths
    b"",
    Bytes::make(31, b'\x02'),
    Bytes::make(33, b'\x02'),
  ]
  for bad in r_bad_elements {
    assert_eq(
      @oprf.blind_evaluate(r_suite, r_sk, bad),
      Err(@oprf.InvalidElement),
    )
    assert_eq(@oprf.finalize(r_state, b"hello", bad), Err(@oprf.InvalidElement))
  }

  // P-256 invalid, off-curve, uncompressed, and identity elements
  let p_suite = @oprf.P256Sha256
  let (p_sk, _) = @oprf.derive_key_pair(p_suite, Bytes::make(32, b'\x07'), b"k").unwrap()
  let (p_state, _) = @oprf.blind_from_random_bytes(
    p_suite,
    b"hello",
    Bytes::make(32, b'\x09'),
  ).unwrap()
  // Off-curve x = 5: 5^3 - 3*5 + b is non-residue mod p? Let's test x = 5 or x = p (out of field) + known off-curve point
  let p_bad_elements : Array[Bytes] = [
    // Point at infinity (1-byte SEC1 identity)
    Bytes::from_array([b'\x00']),
    // 33 zero bytes (invalid prefix 0x00)
    Bytes::make(33, b'\x00'),
    // Invalid prefix 0x04 with 33 bytes
    must_hex(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ),
    // Uncompressed generator (65 bytes) must be rejected
    must_hex(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ),
    // x = p (non-canonical field coordinate)
    must_hex(
      "02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    ),
    // Off-curve point (x = 7 has no square root for x^3 - 3x + b mod p)
    must_hex(
      "020000000000000000000000000000000000000000000000000000000000000007",
    ),
    // Wrong lengths
    b"",
    Bytes::make(32, b'\x02'),
  ]
  for bad in p_bad_elements {
    assert_eq(
      @oprf.blind_evaluate(p_suite, p_sk, bad),
      Err(@oprf.InvalidElement),
    )
    assert_eq(@oprf.finalize(p_state, b"hello", bad), Err(@oprf.InvalidElement))
  }
}

///|
test "input length boundary > 65535 returns InvalidInput" {
  let oversized = Bytes::make(65536, b'\x55')
  for suite in [@oprf.Ristretto255Sha512, @oprf.P256Sha256] {
    let (sk_s, _) = @oprf.derive_key_pair(
      suite,
      Bytes::make(32, b'\x01'),
      b"info",
    ).unwrap()
    let (state, blinded) = @oprf.blind_from_random_bytes(
      suite,
      b"ok",
      Bytes::make(32, b'\x02'),
    ).unwrap()
    let evaluated = @oprf.blind_evaluate(suite, sk_s, blinded).unwrap()

    assert_eq(
      @oprf.derive_key_pair(suite, Bytes::make(32, b'\x01'), oversized),
      Err(@oprf.InvalidInput),
    )
    assert_true(
      @oprf.blind_with_scalar(suite, oversized, state.blind_bytes())
      is Err(@oprf.InvalidInput),
    )
    assert_true(
      @oprf.blind_from_random_bytes(suite, oversized, Bytes::make(32, b'\x02'))
      is Err(@oprf.InvalidInput),
    )
    assert_eq(
      @oprf.finalize(state, oversized, evaluated),
      Err(@oprf.InvalidInput),
    )
    assert_eq(@oprf.evaluate(suite, sk_s, oversized), Err(@oprf.InvalidInput))
  }
}
