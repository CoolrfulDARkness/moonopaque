///|
fn hex_to_bytes(hex : String) -> Bytes {
  let out : Array[Byte] = []
  let mut hi = -1
  for c in hex {
    let v = match c {
      '0'..<='9' => c.to_int() - '0'.to_int()
      'a'..<='f' => c.to_int() - 'a'.to_int() + 10
      'A'..<='F' => c.to_int() - 'A'.to_int() + 10
      ' ' | '\n' | '\r' | '\t' => -1
      _ => abort("invalid hex character")
    }
    if v >= 0 {
      if hi < 0 {
        hi = v
      } else {
        out.push(((hi << 4) | v).to_byte())
        hi = -1
      }
    }
  }
  Bytes::from_array(out[:])
}

///|
fn scalar_from_u8(n : Int32) -> @ristretto255.Scalar {
  let arr = FixedArray::make(32, b'\x00')
  arr[0] = (n & 0xff).to_byte()
  @ristretto255.Scalar::from_bytes_canonical(Bytes::from_array(arr[:])).unwrap()
}

///|
/// RFC 9496 Appendix A.1: Multiples of the Generator (B[0] .. B[15]).
test "rfc9496 appendix a.1 multiples of generator" {
  let expected : Array[String] = [
    "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000", "e2f2ae0a 6abc4e71 a884a961 c500515f 58e30b6a a582dd8d b6a65945 e08d2d76",
    "6a493210 f7499cd1 7fecb510 ae0cea23 a110e8d5 b901f8ac add3095c 73a3b919", "94741f5d 5d52755e ce4f23f0 44ee27d5 d1ea1e2b d196b462 166b1615 2a9d0259",
    "da808627 73358b46 6ffadfe0 b3293ab3 d9fd53c5 ea6c9553 58f56832 2daf6a57", "e882b131 016b52c1 d3337080 187cf768 423efccb b517bb49 5ab812c4 160ff44e",
    "f64746d3 c92b1305 0ed8d802 36a7f000 7c3b3f96 2f5ba793 d19a601e bb1df403", "44f53520 926ec81f bd5a3878 45beb7df 85a96a24 ece18738 bdcfa6a7 822a176d",
    "903293d8 f2287ebe 10e2374d c1a53e0b c887e592 699f02d0 77d5263c dd55601c", "02622ace 8f7303a3 1cafc63f 8fc48fdc 16e1c8c8 d234b2f0 d6685282 a9076031",
    "20706fd7 88b2720a 1ed2a5da d4952b01 f413bcf0 e7564de8 cdc81668 9e2db95f", "bce83f8b a5dd2fa5 72864c24 ba1810f9 522bc600 4afe9587 7ac73241 cafdab42",
    "e4549ee1 6b9aa030 99ca208c 67adafca fa4c3f3e 4e5303de 6026e3ca 8ff84460", "aa52e000 df2e16f5 5fb1032f c33bc427 42dad6bd 5a8fc0be 0167436c 5948501f",
    "46376b80 f409b29d c2b5f6f0 c5259199 0896e571 6f41477c d30085ab 7f10301e", "e0c418f7 c8d9c4cd d7395b93 ea124f3a d99021bb 681dfc33 02a9d99a 2e53e64e",
  ]
  let g = @ristretto255.Element::generator()
  let mut cur = @ristretto255.Element::identity()
  for i = 0; i < expected.length(); i = i + 1 {
    let want = hex_to_bytes(expected[i])
    // Check repeated addition encoding
    assert_eq(cur.to_bytes(), want)
    // Check base_mul matches
    let s = scalar_from_u8(i)
    let by_base = @ristretto255.Element::base_mul(s)
    assert_eq(by_base.to_bytes(), want)
    assert_true(by_base.equal(cur))
    // Check decode round-trip & equality
    let decoded = @ristretto255.Element::from_bytes(want).unwrap()
    assert_true(decoded.equal(cur))
    assert_eq(decoded.to_bytes(), want)
    assert_eq(decoded.is_identity(), i == 0)
    cur = cur.add(g)
  }
}

///|
/// RFC 9496 Appendix A.2: Invalid Encodings (all 29 official vectors + wrong lengths).
test "rfc9496 appendix a.2 invalid encodings" {
  let invalid : Array[String] = [
    // Non-canonical field encodings (4)
    "00ffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff", "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffff7f",
    "f3ffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffff7f", "edffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffff7f",
    // Negative field elements (8)
     "01000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000", "01ffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffff7f",
    "ed57ffd8 c914fb20 1471d1c3 d245ce3c 746fcbe6 3a3679d5 1b6a516e bebe0e20", "c34c4e18 26e5d403 b78e246e 88aa051c 36ccf0aa febffe13 7d148a2b f9104562",
    "c940e5a4 404157cf b1628b10 8db051a8 d439e1a4 21394ec4 ebccb9ec 92a8ac78", "47cfc549 7c53dc8e 61c91d17 fd626ffb 1c49e2bc a94eed05 2281b510 b1117a24",
    "f1c6165d 33367351 b0da8f6e 4511010c 68174a03 b6581212 c71c0e1d 026c3c72", "87260f7a 2f124951 18360f02 c26a470f 450dadf3 4a413d21 042b43b9 d93e1309",
    // Non-square x^2 (8)
     "26948d35 ca62e643 e26a8317 7332e6b6 afeb9d08 e4268b65 0f1f5bbd 8d81d371", "4eac077a 713c57b4 f4397629 a4145982 c661f480 44dd3f96 427d40b1 47d9742f",
    "de6a7b00 deadc788 eb6b6c8d 20c0ae96 c2f20190 78fa604f ee5b87d6 e989ad7b", "bcab477b e20861e0 1e4a0e29 5284146a 510150d9 817763ca f1a6f4b4 22d67042",
    "2a292df7 e32cabab bd9de088 d1d1abec 9fc0440f 637ed2fb a145094d c14bea08", "f4a9e534 fc0d216c 44b218fa 0c42d996 35a0127e e2e53c71 2f706096 49fdff22",
    "8268436f 8c412619 6cf64b3c 7ddbda90 746a3786 25f9813d d9b84570 77256731", "2810e5cb c2cc4d4e ece54f61 c6f69758 e289aa7a b440b3cb eaa21995 c2f4232b",
    // Negative x * y value (8)
     "3eb858e7 8f5a7254 d8c97311 74a94f76 755fd394 1c0ac937 35c07ba1 4579630e", "a45fdc55 c76448c0 49a1ab33 f17023ed fb2be358 1e9c7aad e8a61252 15e04220",
    "d483fe81 3c6ba647 ebbfd3ec 41adca1c 6130c2be eee9d9bf 065c8d15 1c5f396e", "8a2e1d30 050198c6 5a544831 23960ccc 38aef684 8e1ec8f5 f780e852 3769ba32",
    "32888462 f8b486c6 8ad7dd96 10be5192 bbeaf3b4 43951ac1 a8118419 d9fa097b", "22714250 1b9d4355 ccba2904 04bde415 75b03769 3cef1f43 8c47f8fb f35d1165",
    "5c37cc49 1da847cf eb9281d4 07efc41e 15144c87 6e0170b4 99a96a22 ed31e01e", "44542511 7cb8c90e dcbc7c1c c0e74f74 7f2c1efa 5630a967 c64f2877 92a48a4b",
    // s = -1, which causes y = 0 (1)
     "ecffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffff7f",
  ]
  assert_eq(invalid.length(), 29)
  for h in invalid {
    assert_true(@ristretto255.Element::from_bytes(hex_to_bytes(h)) is None)
  }
  // Wrong lengths
  assert_true(
    @ristretto255.Element::from_bytes(Bytes::make(0, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Element::from_bytes(Bytes::make(31, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Element::from_bytes(Bytes::make(33, b'\x00')) is None,
  )
}

///|
/// RFC 9496 Appendix A.3: Group Elements from Uniform Byte Strings (all 11 official vectors).
test "rfc9496 appendix a.3 from_uniform_bytes" {
  let pairs : Array[(String, String)] = [
    (
      "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
      "3066f82a 1a747d45 120d1740 f1435853 1a8f04bb ffe6a819 f86dfe50 f44a0a46",
    ),
    (
      "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
      "f26e5b6f 7d362d2d 2a94c5d0 e7602cb4 773c95a2 e5c31a64 f133189f a76ed61b",
    ),
    (
      "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
      "006ccd2a 9e6867e6 a2c5cea8 3d3302cc 9de128dd 2a9a57dd 8ee7b9d7 ffe02826",
    ),
    (
      "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
      "f8f0c87c f237953c 5890aec3 99816900 5dae3eca 1fbb0454 8c635953 c817f92a",
    ),
    (
      "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
      "ae81e7de df20a497 e10c304a 765c1767 a42d6e06 029758d2 d7e8ef7c c4c41179",
    ),
    (
      "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
      "e2705652 ff9f5e44 d3e841bf 1c251cf7 dddb77d1 40870d1a b2ed64f1 a9ce8628",
    ),
    (
      "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
      "80bd0726 2511cdde 4863f8a7 434cef69 6750681c b9510eea 557088f7 6d9e5065",
    ),
    // 4 equivalent inputs producing the same encoded output
    (
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000",
      "30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f",
    ),
    (
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f",
    ),
    (
      "0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f",
    ),
    (
      "00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080",
      "30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f",
    ),
  ]
  for pair in pairs {
    let (in_hex, out_hex) = pair
    let elem = @ristretto255.Element::from_uniform_bytes(hex_to_bytes(in_hex)).unwrap()
    let expected = hex_to_bytes(out_hex)
    assert_eq(elem.to_bytes(), expected)
    let redecoded = @ristretto255.Element::from_bytes(expected).unwrap()
    assert_true(elem.equal(redecoded))
  }
  // Wrong lengths rejected
  assert_true(
    @ristretto255.Element::from_uniform_bytes(Bytes::make(0, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Element::from_uniform_bytes(Bytes::make(32, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Element::from_uniform_bytes(Bytes::make(63, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Element::from_uniform_bytes(Bytes::make(65, b'\x00')) is None,
  )
}

///|
/// Scalar canonical decoding boundaries, wide reduction, and arithmetic.
test "scalar canonical bounds wide reduction and arithmetic" {
  let zero = @ristretto255.Scalar::zero()
  let one = @ristretto255.Scalar::one()
  assert_true(zero.is_zero())
  assert_false(one.is_zero())
  assert_true(zero.invert() is None)
  assert_true(one.invert().unwrap().equal(one))
  assert_true(zero.neg().is_zero())
  // Canonical boundaries: L - 1 accepted; L, L + 1, 2^256 - 1 rejected.
  let l_minus_1_bytes = hex_to_bytes(
    "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let l_bytes = hex_to_bytes(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let l_plus_1_bytes = hex_to_bytes(
    "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let l_minus_1 = @ristretto255.Scalar::from_bytes_canonical(l_minus_1_bytes).unwrap()
  assert_eq(l_minus_1.to_bytes(), l_minus_1_bytes)
  assert_true(l_minus_1.add(one).is_zero())
  assert_true(one.neg().equal(l_minus_1))
  assert_true(zero.sub(one).equal(l_minus_1))
  assert_true(@ristretto255.Scalar::from_bytes_canonical(l_bytes) is None)
  assert_true(
    @ristretto255.Scalar::from_bytes_canonical(l_plus_1_bytes) is None,
  )
  assert_true(
    @ristretto255.Scalar::from_bytes_canonical(Bytes::make(32, b'\xff')) is None,
  )
  assert_true(
    @ristretto255.Scalar::from_bytes_canonical(Bytes::make(31, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Scalar::from_bytes_canonical(Bytes::make(33, b'\x00')) is None,
  )
  // Wide reduction test vectors (64 bytes -> canonical mod L).
  let wide_cases : Array[(String, String)] = [
    (
      "edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "ecd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
      "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    ),
    (
      "eed3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000",
      "1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f",
    ),
    (
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903",
    ),
    (
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      "7a3c6282f02d37a05023b60d5428e6cc5961d4c31221937adae0b574e4d07205",
    ),
    (
      "43a384838ff6fdd7fb32db153c123e83bdfaf972d432cee0c314f2f6ee862702dfbc0a89674523e1abebaffceedbea0d00000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    (
      "5a344a8870e006050d55a09a6f89c5e087171838e89a3addaaf6c125e9f17b01efcdab8967452301efcdab896745230100000000000000000000000000000000",
      "2a00000000000000000000000000000000000000000000000000000000000000",
    ),
  ]
  for pair in wide_cases {
    let (in_hex, out_hex) = pair
    let s = @ristretto255.Scalar::from_bytes_wide(hex_to_bytes(in_hex)).unwrap()
    assert_eq(s.to_bytes(), hex_to_bytes(out_hex))
  }
  assert_true(
    @ristretto255.Scalar::from_bytes_wide(Bytes::make(63, b'\x00')) is None,
  )
  assert_true(
    @ristretto255.Scalar::from_bytes_wide(Bytes::make(65, b'\x00')) is None,
  )
  // Exact arithmetic checks against reference values
  let a = @ristretto255.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "cdab8967452301efcdab8967452301efcdab8967452301efcdab896745230100",
    ),
  ).unwrap()
  let b = @ristretto255.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "32547698badcfe1032547698badcfe1032547698badcfe1032547698badcfe00",
    ),
  ).unwrap()
  assert_eq(
    a.add(b).to_bytes(),
    hex_to_bytes(
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00",
    ),
  )
  assert_eq(
    a.sub(b).to_bytes(),
    hex_to_bytes(
      "882b092ca5a9143672f40a726940e1f29b5713cf8a4602de9b5713cf8a46020f",
    ),
  )
  assert_eq(
    a.mul(b).to_bytes(),
    hex_to_bytes(
      "265d164635ebecf8a8d38213fbe1c38abc33c52b649b50e0f6c1bff32b8cf303",
    ),
  )
  let a_inv = a.invert().unwrap()
  assert_eq(
    a_inv.to_bytes(),
    hex_to_bytes(
      "fb4b8d499997fffa366e5f8fba2d8d15ab33efe8333c0a7033caa77e0af57a09",
    ),
  )
  assert_true(a.mul(a_inv).equal(one))
  assert_eq(
    a.neg().to_bytes(),
    hex_to_bytes(
      "20286cf5d43f116908f16d3b99d6dd2532547698badcfe1032547698badcfe0f",
    ),
  )
  // Field laws: associativity, commutativity, distributivity
  let c = @ristretto255.Scalar::from_bytes_wide(
    hex_to_bytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    ),
  ).unwrap()
  assert_true(a.add(b).equal(b.add(a)))
  assert_true(a.add(b).add(c).equal(a.add(b.add(c))))
  assert_true(a.mul(b).equal(b.mul(a)))
  assert_true(a.mul(b).mul(c).equal(a.mul(b.mul(c))))
  assert_true(a.mul(b.add(c)).equal(a.mul(b).add(a.mul(c))))
  assert_true(a.sub(b).add(b).equal(a))
}

///|
/// Group algebraic laws: associativity, distributivity, scalar mul, inversion, identity.
test "group laws and scalar multiplication identities" {
  let id = @ristretto255.Element::identity()
  let g = @ristretto255.Element::generator()
  let zero = @ristretto255.Scalar::zero()
  let one = @ristretto255.Scalar::one()
  let l_minus_1 = @ristretto255.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    ),
  ).unwrap()
  // Identity checks
  assert_true(id.is_identity())
  assert_false(g.is_identity())
  assert_true(g.scalar_mul(zero).is_identity())
  assert_true(g.scalar_mul(one).equal(g))
  assert_true(id.add(g).equal(g))
  assert_true(g.add(id).equal(g))
  assert_true(g.sub(g).is_identity())
  assert_true(g.add(g.neg()).is_identity())
  // Order L check: (L - 1)*G + G == identity and (L - 1)*G == -G
  let neg_g = @ristretto255.Element::base_mul(l_minus_1)
  assert_true(neg_g.equal(g.neg()))
  assert_true(neg_g.add(g).is_identity())
  // Non-trivial scalars and derived element P
  let a = @ristretto255.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "cdab8967452301efcdab8967452301efcdab8967452301efcdab896745230100",
    ),
  ).unwrap()
  let b = @ristretto255.Scalar::from_bytes_canonical(
    hex_to_bytes(
      "32547698badcfe1032547698badcfe1032547698badcfe1032547698badcfe00",
    ),
  ).unwrap()
  let p = @ristretto255.Element::from_uniform_bytes(
    hex_to_bytes(
      "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
    ),
  ).unwrap()
  // (a * b) * G == a * (b * G) == b * (a * G)
  let ab_g = @ristretto255.Element::base_mul(a.mul(b))
  let a_bg = @ristretto255.Element::base_mul(b).scalar_mul(a)
  let b_ag = @ristretto255.Element::base_mul(a).scalar_mul(b)
  assert_true(ab_g.equal(a_bg))
  assert_true(ab_g.equal(b_ag))
  assert_eq(ab_g.to_bytes(), a_bg.to_bytes())
  // (a + b) * P == a * P + b * P
  assert_true(
    p.scalar_mul(a.add(b)).equal(p.scalar_mul(a).add(p.scalar_mul(b))),
  )
  // (a - b) * P == a * P - b * P
  assert_true(
    p.scalar_mul(a.sub(b)).equal(p.scalar_mul(a).sub(p.scalar_mul(b))),
  )
  // OPRF blind/unblind identity: (s * s^-1) * P == P and s^-1 * (s * P) == P
  let a_inv = a.invert().unwrap()
  assert_true(p.scalar_mul(a).scalar_mul(a_inv).equal(p))
  assert_true(p.scalar_mul(a.mul(a_inv)).equal(p))
  // Element addition associativity & commutativity
  let q = @ristretto255.Element::base_mul(a)
  let r = @ristretto255.Element::base_mul(b)
  assert_true(p.add(q).equal(q.add(p)))
  assert_true(p.add(q).add(r).equal(p.add(q.add(r))))
  assert_true(p.add(q).sub(q).equal(p))
}
