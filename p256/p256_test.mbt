///|
fn hex_nibble(c : Int32) -> Int32 {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    abort("invalid hex character")
  }
}

///|
fn hex_to_bytes(s : String) -> Bytes {
  let len = s.length()
  if len % 2 != 0 {
    abort("hex string must have even length")
  }
  let out = FixedArray::make(len / 2, b'\x00')
  for i = 0; i < len / 2; i = i + 1 {
    let hi = hex_nibble(s[i * 2].to_int())
    let lo = hex_nibble(s[i * 2 + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn bytes_to_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
test "generator, 2G, 3G, n*G == O, and complete addition edge cases" {
  let g = @p256.Point::generator()
  let id = @p256.Point::identity()

  assert_true(id.is_identity())
  assert_true(!g.is_identity())

  // Standard compressed G
  assert_eq(
    bytes_to_hex(g.to_bytes_compressed()),
    "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  )

  // Identity serialization is 1 byte [0x00]
  assert_eq(bytes_to_hex(id.to_bytes_compressed()), "00")

  // 2G via G + G and scalar_mul(2)
  let two = @p256.Scalar::one().add(@p256.Scalar::one())
  let three = two.add(@p256.Scalar::one())
  let g2_add = g.add(g)
  let g2_mul = @p256.Point::base_mul(two)
  assert_true(g2_add.equal(g2_mul))
  assert_eq(
    bytes_to_hex(g2_add.to_bytes_compressed()),
    "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
  )

  // 3G
  let g3_add = g2_add.add(g)
  let g3_mul = @p256.Point::base_mul(three)
  assert_true(g3_add.equal(g3_mul))
  assert_eq(
    bytes_to_hex(g3_add.to_bytes_compressed()),
    "025ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
  )

  // Complete addition edge cases
  assert_true(id.add(id).is_identity())
  assert_true(id.add(id).equal(id))
  assert_true(id.add(g).equal(g))
  assert_true(g.add(id).equal(g))
  assert_true(id.neg().is_identity())
  assert_true(id.neg().equal(id))
  assert_true(id.neg().add(g).equal(g))
  assert_true(g.add(g.neg()).is_identity())
  assert_true(g.sub(g).is_identity())
  assert_true(g3_add.sub(g).equal(g2_add))
  assert_true(g2_add.sub(g3_add).equal(g.neg()))

  // 0 * G == O, 1 * G == G, (n - 1) * G == -G, n * G == (n-1)*G + G == O
  assert_true(@p256.Point::base_mul(@p256.Scalar::zero()).is_identity())
  assert_true(@p256.Point::base_mul(@p256.Scalar::one()).equal(g))
  assert_true(id.scalar_mul(three).is_identity())
  let n_minus_1 = @p256.Scalar::zero().sub(@p256.Scalar::one())
  let nm1_g = @p256.Point::base_mul(n_minus_1)
  assert_true(nm1_g.equal(g.neg()))
  assert_true(nm1_g.add(g).is_identity())
}

///|
test "ECDH commutativity and scalar multiplication distributivity" {
  let s1 = @p256.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "deadbeefcafebabe0123456789abcdef112233445566778899aabbccddeeff01",
    ),
  ).unwrap()
  let s2 = @p256.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "fedcba987654321000112233445566778899aabbccddeeff0123456789abcdef",
    ),
  ).unwrap()

  let p1 = @p256.Point::base_mul(s1)
  let p2 = @p256.Point::base_mul(s2)
  assert_eq(
    bytes_to_hex(p1.to_bytes_compressed()),
    "02962cef3235886c8a181837a38fe0b39667d7f12e1a678df937246f78e4238189",
  )
  assert_eq(
    bytes_to_hex(p2.to_bytes_compressed()),
    "03532fc8cecb21a53a8daefb99354d630692ea3d668e087633f8adaaac0f36b7f5",
  )

  // ECDH commutativity: s1 * (s2 * G) == s2 * (s1 * G) == (s1 * s2) * G
  let shared1 = p2.scalar_mul(s1)
  let shared2 = p1.scalar_mul(s2)
  let shared3 = @p256.Point::base_mul(s1.mul(s2))
  assert_true(shared1.equal(shared2))
  assert_true(shared1.equal(shared3))
  assert_eq(
    bytes_to_hex(shared1.to_bytes_compressed()),
    "0275d095a225a55aca382baaf25f258e729a727bb8786858fb88394ccbe7c3f53b",
  )

  // Distributivity: (s1 + s2) * G == s1 * G + s2 * G
  let sum_pt = @p256.Point::base_mul(s1.add(s2))
  assert_true(sum_pt.equal(p1.add(p2)))
  let diff_pt = @p256.Point::base_mul(s1.sub(s2))
  assert_true(diff_pt.equal(p1.sub(p2)))
}

///|
test "SEC1 compressed round-trip and strict validation" {
  // Round-trip for points with odd y (G) and even y (3G) and their negations
  let g = @p256.Point::generator()
  let g_neg = g.neg()
  let g3 = g.add(g).add(g)
  let pts = [g, g_neg, g3, g3.neg()]
  for i = 0; i < pts.length(); i = i + 1 {
    let enc = pts[i].to_bytes_compressed()
    assert_eq(enc.length(), 33)
    let dec = @p256.Point::from_bytes_compressed(enc)
    assert_true(dec is Some(_))
    assert_true(dec.unwrap().equal(pts[i]))
  }

  // Reject identity (1 byte [0x00]) and 33 zero bytes
  assert_true(@p256.Point::from_bytes_compressed(hex_to_bytes("00")) is None)
  assert_true(
    @p256.Point::from_bytes_compressed(
      hex_to_bytes(
        "000000000000000000000000000000000000000000000000000000000000000000",
      ),
    )
    is None,
  )

  // Reject wrong lengths
  assert_true(
    @p256.Point::from_bytes_compressed(Bytes::make(0, b'\x00')) is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(
      hex_to_bytes(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      ),
    )
    is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(
      hex_to_bytes(
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29600",
      ),
    )
    is None,
  )

  // Reject uncompressed (0x04), invalid prefix (0x00, 0x01, 0x05, 0xff)
  let gx_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  let gy_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("04" + gx_hex + gy_hex))
    is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("04" + gx_hex)) is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("01" + gx_hex)) is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("00" + gx_hex)) is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("05" + gx_hex)) is None,
  )

  // Reject x >= p (x == p, x == p + 1, x == 2^256 - 1)
  let p_hex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
  let p_plus_1_hex = "ffffffff00000001000000000000000000000001000000000000000000000000"
  let all_ff_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("02" + p_hex)) is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("03" + p_hex)) is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("02" + p_plus_1_hex))
    is None,
  )
  assert_true(
    @p256.Point::from_bytes_compressed(hex_to_bytes("02" + all_ff_hex)) is None,
  )

  // Reject off-curve points (x = 1, 2, 3, 4, 7 have non-square x^3 - 3x + b mod p)
  let off_x = [
    "0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000004",
    "0000000000000000000000000000000000000000000000000000000000000007",
  ]
  for i = 0; i < off_x.length(); i = i + 1 {
    assert_true(
      @p256.Point::from_bytes_compressed(hex_to_bytes("02" + off_x[i])) is None,
    )
    assert_true(
      @p256.Point::from_bytes_compressed(hex_to_bytes("03" + off_x[i])) is None,
    )
  }
}

///|
test "RFC 9380 Appendix J.1.1 P256_XMD:SHA-256_SSWU_RO_ all 5 vectors" {
  // Each tuple: (u0_hex, u1_hex, uniform96_hex, q0_comp_hex, q1_comp_hex, p_comp_hex)
  let vectors : Array[(String, String, String, String, String, String)] = [
    // Vector 1: msg = ""
    (
      "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009", "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
      "e9db2339d6240aa7f935f4f5d4bfd0029892a0a7386395f6c80d1fbbddfbbfe7911fb1901894d8648f91a1789e36ae4cc545d05bde0a591a05d71b0033db300bfb8416ae59fe22028dc0d7f5f6e87e2dc7dae2c61988273516292a0899c26fab",
      "03ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5", "0251cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
      "032c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
    ),
    // Vector 2: msg = "abc"
    (
      "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1", "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0",
      "2618a37b4a06920b349c38a8f864389b279f7c1acfb175a93c45e1c6b037aa6a6c4e8934f5ae7098209b3cf1303a3d294a488a239e5fb5dab4d1bd11b18dd0176eb4976aa16b8b986484e08c71b53a4c9168ac6bca8d1428b1bc5a7db28743db",
      "035219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48", "02019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f",
      "020bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
    ),
    // Vector 3: msg = "abcdef0123456789"
    (
      "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c", "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb",
      "661aaab605a5f90d4428b5f7a5da0917d59437be449736e4c8b9d9344f7f9a3e7a0fc3233037cdbd6033274d71551cd33139307317dc4af64a8126bf80f39bdf7ea776c23f078fd262ee783139c37afe31429cd1a1634060e8b5cae7875b2ed0",
      "02a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2", "037da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66",
      "0365038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
    ),
    // Vector 4: msg = "q128_" + "q"*128
    (
      "3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919", "76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33",
      "643a06ab5c9782004f4072576bb5e9f790d7cef92a30040dbba209a081cb2328093ba23d65c7b481192b4b1836c403761c7c1d617b517e05b1f2abe077d66e8e96b22fb42b65c44259adca73453ce4dc088cba912bc60cb66f9cf455d4722026",
      "03c76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efebddf0e6398", "03418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f391826794eb5a75",
      "024be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
    ),
    // Vector 5: msg = "a512_" + "a"*512
    (
      "4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec", "4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee",
      "7a1bccc4c274126f4eb9aaeb2d3beec75e108614642f4b6078f3977b8abc4324c3d0d3a942370c8cf9c930f7abd8d2ff9394f016f3d2589a5efa34cbfc29d144d95f26f63d52ae11de174041c7cdae688f39158c0f4cdcf71ea17fbaed5353f5",
      "02d88b989ee9d1295df413d4456c5c850b8b2fb0f5402cc5c4c7e815412e926db8", "02a281e34e628f3a4d2a53fa87ff973537d68ad4fbc28d3be5e8d9f6a2571c5a4b",
      "02457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
    ),
  ]

  for i = 0; i < vectors.length(); i = i + 1 {
    let (u0_hex, u1_hex, uni96_hex, q0_hex, q1_hex, p_hex) = vectors[i]
    let q0 = @p256.Point::map_to_curve_sswu(hex_to_bytes(u0_hex)).unwrap()
    let q1 = @p256.Point::map_to_curve_sswu(hex_to_bytes(u1_hex)).unwrap()
    assert_eq(bytes_to_hex(q0.to_bytes_compressed()), q0_hex)
    assert_eq(bytes_to_hex(q1.to_bytes_compressed()), q1_hex)

    let p_sum = q0.add(q1)
    assert_eq(bytes_to_hex(p_sum.to_bytes_compressed()), p_hex)

    let uni96 = hex_to_bytes(uni96_hex)
    // Also verify 48-byte slices directly into map_to_curve_sswu
    let q0_from_48 = @p256.Point::map_to_curve_sswu(uni96[0:48].to_owned()).unwrap()
    let q1_from_48 = @p256.Point::map_to_curve_sswu(uni96[48:96].to_owned()).unwrap()
    assert_true(q0_from_48.equal(q0))
    assert_true(q1_from_48.equal(q1))

    // Verify hash_to_curve_from_uniform
    let p_h2c = @p256.Point::hash_to_curve_from_uniform(uni96).unwrap()
    assert_eq(bytes_to_hex(p_h2c.to_bytes_compressed()), p_hex)
    assert_true(p_h2c.equal(p_sum))
  }
}

///|
test "SSWU exceptional cases and invalid input lengths" {
  // Exceptional case 1: u = 0
  let q_zero = @p256.Point::map_to_curve_sswu(hex_to_bytes("00")).unwrap()
  assert_eq(
    bytes_to_hex(q_zero.to_bytes_compressed()),
    "02a528bd8696bdaf996c65b982d94959d3146fe6a020693090bdba13132375f224",
  )
  // Verify deserialization confirms point is strictly on curve
  assert_true(
    @p256.Point::from_bytes_compressed(q_zero.to_bytes_compressed()) is Some(_),
  )

  // Exceptional case 2: Z * u^2 = -1 mod p => u = sqrt(10)^(-1) mod p
  let u_exc1 = hex_to_bytes(
    "95d527d249c8dc5cadbf4c70bb59aaab72c14fffbad5622bd147b86a639ec6d9",
  )
  let q_exc1 = @p256.Point::map_to_curve_sswu(u_exc1).unwrap()
  assert_eq(
    bytes_to_hex(q_exc1.to_bytes_compressed()),
    "03a528bd8696bdaf996c65b982d94959d3146fe6a020693090bdba13132375f224",
  )
  assert_true(
    @p256.Point::from_bytes_compressed(q_exc1.to_bytes_compressed()) is Some(_),
  )

  // Invalid inputs
  assert_true(@p256.Point::map_to_curve_sswu(Bytes::make(0, b'\x00')) is None)
  assert_true(
    @p256.Point::hash_to_curve_from_uniform(Bytes::make(0, b'\x00')) is None,
  )
  assert_true(
    @p256.Point::hash_to_curve_from_uniform(Bytes::make(95, b'\x00')) is None,
  )
  assert_true(
    @p256.Point::hash_to_curve_from_uniform(Bytes::make(97, b'\x00')) is None,
  )
}

///|
test "Scalar arithmetic, inversion, canonical parsing, and mod n reduction" {
  let zero = @p256.Scalar::zero()
  let one = @p256.Scalar::one()
  assert_true(zero.is_zero())
  assert_true(!one.is_zero())
  assert_true(zero.equal(zero))
  assert_true(!zero.equal(one))
  assert_eq(
    bytes_to_hex(zero.to_bytes()),
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(
    bytes_to_hex(one.to_bytes()),
    "0000000000000000000000000000000000000000000000000000000000000001",
  )

  // Canonical parsing boundaries: n - 1 ok; n, n + 1, 0xff..ff, wrong lengths rejected
  let n_minus_1_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
  let n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  let n_plus_1_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"
  let all_ff_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

  let nm1 = @p256.Scalar::from_bytes_canonical(hex_to_bytes(n_minus_1_hex)).unwrap()
  assert_true(nm1.add(one).is_zero())
  assert_true(nm1.equal(one.neg()))
  assert_true(@p256.Scalar::from_bytes_canonical(hex_to_bytes(n_hex)) is None)
  assert_true(
    @p256.Scalar::from_bytes_canonical(hex_to_bytes(n_plus_1_hex)) is None,
  )
  assert_true(
    @p256.Scalar::from_bytes_canonical(hex_to_bytes(all_ff_hex)) is None,
  )
  assert_true(
    @p256.Scalar::from_bytes_canonical(Bytes::make(31, b'\x00')) is None,
  )
  assert_true(
    @p256.Scalar::from_bytes_canonical(Bytes::make(33, b'\x00')) is None,
  )

  // Arithmetic ground-truth vectors
  let s1 = @p256.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "deadbeefcafebabe0123456789abcdef112233445566778899aabbccddeeff01",
    ),
  ).unwrap()
  let s2 = @p256.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "fedcba987654321000112233445566778899aabbccddeeff0123456789abcdef",
    ),
  ).unwrap()

  assert_eq(
    bytes_to_hex(s1.add(s2).to_bytes()),
    "dd8a79894152eccd0134679ace013466dcd4e3527b2cc802a71436716b37a79f",
  )
  assert_eq(
    bytes_to_hex(s1.sub(s2).to_bytes()),
    "dfd1045654aa88af0112233445566777456f83362fa0270e8c41412850a65663",
  )
  assert_eq(
    bytes_to_hex(s1.mul(s2).to_bytes()),
    "ef8ed65f259de40a94ea7e93f6588c6942a62c85229483d432b8b118554975aa",
  )
  assert_eq(
    bytes_to_hex(s1.neg().to_bytes()),
    "2152410f35014542fedcba9876543210abc4c76951b126fc5a0f0ef61e742650",
  )
  assert_true(zero.neg().is_zero())

  // Inversion
  assert_true(zero.invert() is None)
  assert_true(one.invert().unwrap().equal(one))
  assert_true(nm1.invert().unwrap().equal(nm1))
  let s1_inv = s1.invert().unwrap()
  assert_eq(
    bytes_to_hex(s1_inv.to_bytes()),
    "cfc0b8ee5c99be4513f687be98c726ebdcc871a473478040d371e9e074b22ff0",
  )
  assert_true(s1.mul(s1_inv).equal(one))

  // from_bytes_be_mod_n: empty -> None, 48-byte HashToScalar, 48x0xFF, 33-byte, 1-byte
  assert_true(
    @p256.Scalar::from_bytes_be_mod_n(Bytes::make(0, b'\x00')) is None,
  )
  let u48 = hex_to_bytes(
    "e9db2339d6240aa7f935f4f5d4bfd0029892a0a7386395f6c80d1fbbddfbbfe7911fb1901894d8648f91a1789e36ae4c",
  )
  assert_eq(
    bytes_to_hex(@p256.Scalar::from_bytes_be_mod_n(u48).unwrap().to_bytes()),
    "ea9e7842a65e877967185802b29b436d0e9406aac5713e727f8cf3200052307f",
  )
  let ff48 = Bytes::make(48, b'\xff')
  assert_eq(
    bytes_to_hex(@p256.Scalar::from_bytes_be_mod_n(ff48).unwrap().to_bytes()),
    "431905529c0166ce652e96b7ccca0a99679b73e19ad16947f01cf013fc632550",
  )
  let u33 = hex_to_bytes(
    "00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63257b",
  )
  assert_eq(
    bytes_to_hex(@p256.Scalar::from_bytes_be_mod_n(u33).unwrap().to_bytes()),
    "000000000000000000000000000000000000000000000000000000000000002a",
  )
  let u1 = hex_to_bytes("ab")
  assert_eq(
    bytes_to_hex(@p256.Scalar::from_bytes_be_mod_n(u1).unwrap().to_bytes()),
    "00000000000000000000000000000000000000000000000000000000000000ab",
  )
  // Exact multiple of n reduces to 0
  assert_true(
    @p256.Scalar::from_bytes_be_mod_n(hex_to_bytes(n_hex)).unwrap().is_zero(),
  )
}
