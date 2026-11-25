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
/// RFC 7748 §5.2 Test Vector 1 & Test Vector 2.
test "rfc7748 section 5.2 test vectors 1 and 2" {
  // Test Vector 1
  let s1 = hex_to_bytes(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let u1 = hex_to_bytes(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  let expected1 = hex_to_bytes(
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  )
  assert_eq(@x25519.x25519(s1, u1), Ok(expected1))
  assert_eq(@x25519.x25519_checked(s1, u1), Ok(expected1))

  // Test Vector 2 (also tests bit 255 masking since u2[31] == 0x93 has bit 7 set!)
  let s2 = hex_to_bytes(
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
  )
  let u2 = hex_to_bytes(
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
  )
  let expected2 = hex_to_bytes(
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
  )
  assert_eq(@x25519.x25519(s2, u2), Ok(expected2))
  assert_eq(@x25519.x25519_checked(s2, u2), Ok(expected2))
}

///|
/// RFC 7748 §5.2 Iterated Test Vectors: 1 iteration and 1,000 iterations.
test "rfc7748 section 5.2 iterated 1 and 1000 times" {
  let init = hex_to_bytes(
    "0900000000000000000000000000000000000000000000000000000000000000",
  )
  let expected_1 = hex_to_bytes(
    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
  )
  let expected_1000 = hex_to_bytes(
    "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
  )
  let mut k = init
  let mut u = init
  for i = 1; i <= 1000; i = i + 1 {
    let next_k = @x25519.x25519(k, u).unwrap()
    u = k
    k = next_k
    if i == 1 {
      assert_eq(k, expected_1)
    }
  }
  assert_eq(k, expected_1000)
}

///|
/// RFC 7748 §6.1 Alice-Bob Diffie-Hellman key exchange test vector.
test "rfc7748 section 6.1 diffie-hellman test vector" {
  let alice_sk = hex_to_bytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let alice_pk_expected = hex_to_bytes(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  let bob_sk = hex_to_bytes(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let bob_pk_expected = hex_to_bytes(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let shared_expected = hex_to_bytes(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  assert_eq(@x25519.x25519_base(alice_sk), Ok(alice_pk_expected))
  assert_eq(@x25519.x25519_base(bob_sk), Ok(bob_pk_expected))
  assert_eq(@x25519.x25519(alice_sk, bob_pk_expected), Ok(shared_expected))
  assert_eq(@x25519.x25519(bob_sk, alice_pk_expected), Ok(shared_expected))
  assert_eq(
    @x25519.x25519_checked(alice_sk, bob_pk_expected),
    Ok(shared_expected),
  )
  assert_eq(
    @x25519.x25519_checked(bob_sk, alice_pk_expected),
    Ok(shared_expected),
  )
}

///|
/// RFC 7748 low-order points (all 12 canonical/non-canonical small-order points + p+2^255 variants):
/// raw `x25519` returns all-zero bytes, while `x25519_checked` returns `Err(LowOrderPoint)`.
test "rfc7748 all 12 low-order points rejected by x25519_checked" {
  let sk = hex_to_bytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let zero32 = Bytes::make(32, b'\x00')
  let low_order_points : Array[String] = [
    // 1. u = 0 (order 2)
    "0000000000000000000000000000000000000000000000000000000000000000",
    // 2. u = 1 (order 4)
     "0100000000000000000000000000000000000000000000000000000000000000",
    // 3. u = 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    // 4. u = 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8 on twist)
     "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    // 5. u = p - 1 = 2^255 - 20 (order 4 on twist)
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // 6. u = p = 2^255 - 19 (== 0 mod p)
     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // 7. u = p + 1 = 2^255 - 18 (== 1 mod p)
     "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // 8. u = 0 + 2^255 (bit 255 set)
     "0000000000000000000000000000000000000000000000000000000000000080",
    // 9. u = 1 + 2^255 (bit 255 set)
     "0100000000000000000000000000000000000000000000000000000000000080",
    // 10. order-8 point #3 + 2^255
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
    // 11. order-8 point #4 + 2^255
     "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    // 12. u = (p - 1) + 2^255
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // 13. u = p + 2^255 (== 0 mod p)
     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // 14. u = (p + 1) + 2^255 (== 1 mod p)
     "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ]
  for pt_hex in low_order_points {
    let pt = hex_to_bytes(pt_hex)
    assert_eq(@x25519.x25519(sk, pt), Ok(zero32))
    assert_eq(@x25519.x25519_checked(sk, pt), Err(@x25519.LowOrderPoint))
  }
}

///|
/// Clamp scalar bit invariants, idempotency, and RFC 9807 C.1.3 / C.2.2 Curve25519 cross-checks.
test "clamp_scalar, derive_keypair, and rfc9807 curve25519 cross-checks" {
  assert_eq(@x25519.KEY_LEN, 32)
  assert_eq(@x25519.key_len(), 32)
  // Clamping edge cases: all-0x00 and all-0xff
  let c0 = @x25519.clamp_scalar(Bytes::make(32, b'\x00')).unwrap()
  assert_eq(c0[0], b'\x00')
  assert_eq(c0[31], b'\x40')
  assert_eq(@x25519.clamp_scalar(c0), Ok(c0))
  let cff = @x25519.clamp_scalar(Bytes::make(32, b'\xff')).unwrap()
  assert_eq(cff[0], b'\xf8')
  assert_eq(cff[31], b'\x7f')
  assert_eq(@x25519.clamp_scalar(cff), Ok(cff))

  // RFC 9807 Appendix C.1.3 (Real Test Vector 3 - Curve25519)
  let r3_srv_sk = hex_to_bytes(
    "c06139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d564",
  )
  let r3_srv_pk = hex_to_bytes(
    "a41e28269b4e97a66468cc00c5a57753e192e152766989770688aa90486ef031",
  )
  assert_eq(@x25519.x25519_base(r3_srv_sk), Ok(r3_srv_pk))

  let r3_cli_seed = hex_to_bytes(
    "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b",
  )
  let r3_cli_epk = hex_to_bytes(
    "10a83b9117d3798cb2957fbdb0268a0d63dbf9d66bde5c00c78affd80026c911",
  )
  let (r3_cli_sk, r3_cli_pk) = @x25519.derive_keypair(r3_cli_seed).unwrap()
  assert_eq(r3_cli_pk, r3_cli_epk)
  assert_eq(@x25519.x25519_base(r3_cli_sk), Ok(r3_cli_epk))

  let r3_srv_seed = hex_to_bytes(
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
  )
  let r3_srv_epk = hex_to_bytes(
    "41f55f0bef355cfb34ccd468fdacad75865ee7efef95f4cb6c25d477f7205026",
  )
  let (r3_srv_esk, r3_srv_epk_got) = @x25519.derive_keypair(r3_srv_seed).unwrap()
  assert_eq(r3_srv_epk_got, r3_srv_epk)
  assert_eq(
    @x25519.x25519_checked(r3_cli_sk, r3_srv_epk),
    @x25519.x25519_checked(r3_srv_esk, r3_cli_epk),
  )

  // RFC 9807 Appendix C.2.2 (Fake Test Vector 2 - Curve25519)
  let f2_cli_sk = hex_to_bytes(
    "288bf63470199221847bb035d99f96531adf8badd14cb1571b48f7a506649660",
  )
  let f2_cli_pk = hex_to_bytes(
    "3c64a3153854cc9f0c23aab3c1a19106ec8bab4730736d1d003880a1d5a59005",
  )
  assert_eq(@x25519.x25519_base(f2_cli_sk), Ok(f2_cli_pk))

  let f2_srv_sk = hex_to_bytes(
    "30fbe7e830be1fe8d2187c97414e3826040cbe49b893b64229bab5e85a588846",
  )
  let f2_srv_pk = hex_to_bytes(
    "78b3040047ff26572a7619617601a61b9c81899bee92f00cfcaa5eed96863555",
  )
  assert_eq(@x25519.x25519_base(f2_srv_sk), Ok(f2_srv_pk))

  let f2_cli_seed = hex_to_bytes(
    "a270dc715dc2b4612bc7864312a05c3e9788ee1bad1f276d1e15bdeb4c355e94",
  )
  let f2_cli_epk = hex_to_bytes(
    "c059b7ba2aec863933ae48816360c7a9022e83d822704f3b0b86c0502a66e574",
  )
  assert_eq(@x25519.derive_keypair(f2_cli_seed).unwrap().1, f2_cli_epk)

  let f2_srv_seed = hex_to_bytes(
    "360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2",
  )
  let f2_srv_epk = hex_to_bytes(
    "2d9055eb8f83e1b497370adad5cc2a417bf9be436a792def0c7b7ccb92b9e275",
  )
  assert_eq(@x25519.derive_keypair(f2_srv_seed).unwrap().1, f2_srv_epk)
}

///|
/// Invalid input lengths and Show/Debug formatting for X25519Error.
test "invalid lengths and error traits" {
  let ok32 = Bytes::make(32, b'\x09')
  let bad0 = Bytes::make(0, b'\x00')
  let bad31 = Bytes::make(31, b'\x00')
  let bad33 = Bytes::make(33, b'\x00')

  for bad in [bad0, bad31, bad33] {
    assert_eq(@x25519.clamp_scalar(bad), Err(@x25519.InvalidLength))
    assert_eq(@x25519.x25519(bad, ok32), Err(@x25519.InvalidLength))
    assert_eq(@x25519.x25519(ok32, bad), Err(@x25519.InvalidLength))
    assert_eq(@x25519.x25519_checked(bad, ok32), Err(@x25519.InvalidLength))
    assert_eq(@x25519.x25519_checked(ok32, bad), Err(@x25519.InvalidLength))
    assert_eq(@x25519.x25519_base(bad), Err(@x25519.InvalidLength))
    assert_eq(@x25519.derive_keypair(bad), Err(@x25519.InvalidLength))
  }

  assert_eq(Show::to_string(@x25519.InvalidLength), "InvalidLength")
  assert_eq(Show::to_string(@x25519.LowOrderPoint), "LowOrderPoint")
}
