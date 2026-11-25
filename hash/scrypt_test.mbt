///|
test "RFC 7914 §12 scrypt test vector 1 (empty P/S, N=16, r=1, p=1)" {
  let dk = @hash.scrypt(b"", b"", 16, 1, 1, 64)
  assert_eq(dk.length(), 64)
  assert_eq(
    @hash.hex_encode(dk),
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
  )
}

///|
test "RFC 7914 §12 scrypt test vector 2 (N=1024, r=8, p=16)" {
  let dk = @hash.scrypt(b"password", b"NaCl", 1024, 8, 16, 64)
  assert_eq(dk.length(), 64)
  assert_eq(
    @hash.hex_encode(dk),
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
  )
}

///|
test "RFC 7914 §12 scrypt test vector 3 (N=16384, r=8, p=1)" {
  let dk = @hash.scrypt(b"pleaseletmein", b"SodiumChloride", 16384, 8, 1, 64)
  assert_eq(dk.length(), 64)
  assert_eq(
    @hash.hex_encode(dk),
    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
  )
}

///|
test "scrypt_checked invalid parameters and overflow guards" {
  // N must be a power of 2 strictly greater than 1
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", -16, 1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 0, 1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 1, 1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 3, 1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 6, 1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 15, 1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 1000, 8, 1, 32), None)

  // r, p, dk_len must be strictly positive
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, 0, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, -1, 1, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, 1, 0, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, 1, -2, 32), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, 1, 1, 0), None)
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, 1, 1, -32), None)

  // Overflow guards on block/buffer sizes
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 16, 0x01000000, 1, 32), None)
  assert_eq(
    @hash.scrypt_checked(b"pw", b"salt", 16, 1024, 0x00100000, 32),
    None,
  )
  assert_eq(@hash.scrypt_checked(b"pw", b"salt", 0x40000000, 8, 1, 32), None)
}

///|
test "scrypt boundary cases and consistency with scrypt_checked" {
  // Smallest valid power of 2: N=2, r=1, p=1
  let dk_checked = @hash.scrypt_checked(b"opaque", b"salt", 2, 1, 1, 32)
  let dk_direct = @hash.scrypt(b"opaque", b"salt", 2, 1, 1, 32)
  assert_eq(dk_checked, Some(dk_direct))
  assert_eq(dk_direct.length(), 32)

  // Prefix consistency across different dk_len (PBKDF2 final stage property)
  let dk16 = @hash.scrypt(b"", b"", 16, 1, 1, 16)
  let dk64 = @hash.scrypt(b"", b"", 16, 1, 1, 64)
  assert_eq(@hash.hex_encode(dk16), "77d6576238657b203b19ca42c18a0497")
  assert_eq(dk64.length(), 64)

  // Sensitivity to password, salt, N, r, p
  let base = @hash.scrypt(b"pw", b"salt", 16, 1, 1, 32)
  assert_false(
    @hash.ct_equal(base, @hash.scrypt(b"pw2", b"salt", 16, 1, 1, 32)),
  )
  assert_false(
    @hash.ct_equal(base, @hash.scrypt(b"pw", b"salt2", 16, 1, 1, 32)),
  )
  assert_false(@hash.ct_equal(base, @hash.scrypt(b"pw", b"salt", 32, 1, 1, 32)))
  assert_false(@hash.ct_equal(base, @hash.scrypt(b"pw", b"salt", 16, 2, 1, 32)))
  assert_false(@hash.ct_equal(base, @hash.scrypt(b"pw", b"salt", 16, 1, 2, 32)))
}
