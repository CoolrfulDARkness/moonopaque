///|
fn repeat_byte(b : Byte, count : Int32) -> Bytes {
  Bytes::make(count, b)
}

///|
fn make_seq_bytes(start : Int32, count : Int32) -> Bytes {
  Bytes::makei(count, i => (start + i).to_byte())
}

///|
fn must_hex(hex : String) -> Bytes {
  match @hash.hex_decode(hex) {
    Some(b) => b
    None => abort("invalid hex literal in test")
  }
}

///|
test "bytes utilities: ct_equal, i2osp, xor_bytes, concat_bytes, hex" {
  // ct_equal
  assert_true(@hash.ct_equal(b"", b""))
  assert_true(@hash.ct_equal(b"opaque", b"opaque"))
  assert_false(@hash.ct_equal(b"opaque", b"opaquf"))
  assert_false(@hash.ct_equal(b"opaque", b"opaqu"))
  assert_false(@hash.ct_equal(b"\x00\x01", b"\x00\x02"))

  // i2osp
  assert_eq(@hash.hex_encode(@hash.i2osp(0, 0)), "")
  assert_eq(@hash.hex_encode(@hash.i2osp(0, 1)), "00")
  assert_eq(@hash.hex_encode(@hash.i2osp(255, 1)), "ff")
  assert_eq(@hash.hex_encode(@hash.i2osp(0x0102, 2)), "0102")
  assert_eq(@hash.hex_encode(@hash.i2osp(0x123456, 4)), "00123456")

  // xor_bytes
  assert_eq(
    @hash.hex_encode(@hash.xor_bytes(must_hex("a5f00f"), must_hex("5af0ff"))),
    "ff00f0",
  )
  assert_eq(@hash.xor_bytes(b"", b""), b"")

  // concat_bytes
  assert_eq(@hash.concat_bytes([]), b"")
  assert_eq(@hash.concat_bytes([b"ab", b"", b"cde", b"f"]), b"abcdef")

  // hex_encode / hex_decode
  assert_eq(@hash.hex_encode(b""), "")
  assert_eq(@hash.hex_encode(b"\x00\x09\x0a\x1f\xab\xff"), "00090a1fabff")
  assert_eq(@hash.hex_decode(""), Some(b""))
  assert_eq(@hash.hex_decode("00090A1faBFf"), Some(b"\x00\x09\x0a\x1f\xab\xff"))
  assert_eq(@hash.hex_decode("abc"), None)
  assert_eq(@hash.hex_decode("zzzz"), None)
  assert_eq(@hash.hex_decode("0g"), None)
}

///|
test "NIST FIPS 180-4 SHA-256 test vectors" {
  // Empty string
  assert_eq(
    @hash.hex_encode(@hash.sha256(b"")),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  // "abc"
  assert_eq(
    @hash.hex_encode(@hash.sha256(b"abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  // 448-bit (56-byte) multi-block boundary message
  assert_eq(
    @hash.hex_encode(
      @hash.sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
  // 112-byte multi-block message
  assert_eq(
    @hash.hex_encode(
      @hash.sha256(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      ),
    ),
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
  )
}

///|
test "NIST FIPS 180-4 SHA-512 test vectors" {
  // Empty string
  assert_eq(
    @hash.hex_encode(@hash.sha512(b"")),
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  // "abc"
  assert_eq(
    @hash.hex_encode(@hash.sha512(b"abc")),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  // 896-bit (112-byte) multi-block boundary message
  assert_eq(
    @hash.hex_encode(
      @hash.sha512(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      ),
    ),
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
}

///|
test "RFC 4231 HMAC-SHA256 test vectors" {
  // Case 1
  assert_eq(
    @hash.hex_encode(@hash.hmac_sha256(repeat_byte(b'\x0b', 20), b"Hi There")),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  // Case 2
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
    ),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
  // Case 3
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha256(repeat_byte(b'\xaa', 20), repeat_byte(b'\xdd', 50)),
    ),
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
  )
  // Case 4
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha256(
        must_hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        repeat_byte(b'\xcd', 50),
      ),
    ),
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
  )
  // Case 6 (key > block size)
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha256(
        repeat_byte(b'\xaa', 131),
        b"Test Using Larger Than Block-Size Key - Hash Key First",
      ),
    ),
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
  )
  // Case 7 (key > block size and data > block size)
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha256(
        repeat_byte(b'\xaa', 131),
        b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
      ),
    ),
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
  )
}

///|
test "RFC 4231 HMAC-SHA512 test vectors" {
  // Case 1
  assert_eq(
    @hash.hex_encode(@hash.hmac_sha512(repeat_byte(b'\x0b', 20), b"Hi There")),
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
  )
  // Case 2
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha512(b"Jefe", b"what do ya want for nothing?"),
    ),
    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
  )
  // Case 3
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha512(repeat_byte(b'\xaa', 20), repeat_byte(b'\xdd', 50)),
    ),
    "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
  )
  // Case 4
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha512(
        must_hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
        repeat_byte(b'\xcd', 50),
      ),
    ),
    "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
  )
  // Case 6 (key > 128-byte block size)
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha512(
        repeat_byte(b'\xaa', 131),
        b"Test Using Larger Than Block-Size Key - Hash Key First",
      ),
    ),
    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
  )
  // Case 7
  assert_eq(
    @hash.hex_encode(
      @hash.hmac_sha512(
        repeat_byte(b'\xaa', 131),
        b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
      ),
    ),
    "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
  )
}

///|
test "RFC 5869 HKDF-SHA256 test vectors (Cases 1, 2, 3)" {
  // Case 1
  let ikm1 = repeat_byte(b'\x0b', 22)
  let salt1 = must_hex("000102030405060708090a0b0c")
  let info1 = must_hex("f0f1f2f3f4f5f6f7f8f9")
  let prk1 = @hash.hkdf_extract_sha256(salt1, ikm1)
  assert_eq(
    @hash.hex_encode(prk1),
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
  )
  let okm1 = @hash.hkdf_expand_sha256(prk1, info1, 42)
  assert_eq(
    @hash.hex_encode(okm1),
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  )

  // Case 2 (longer inputs/outputs)
  let ikm2 = make_seq_bytes(0x00, 80)
  let salt2 = make_seq_bytes(0x60, 80)
  let info2 = make_seq_bytes(0xb0, 80)
  let prk2 = @hash.hkdf_extract_sha256(salt2, ikm2)
  assert_eq(
    @hash.hex_encode(prk2),
    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
  )
  let okm2 = @hash.hkdf_expand_sha256(prk2, info2, 82)
  assert_eq(
    @hash.hex_encode(okm2),
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
  )

  // Case 3 (empty salt & empty info)
  let prk3 = @hash.hkdf_extract_sha256(b"", ikm1)
  assert_eq(
    @hash.hex_encode(prk3),
    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
  )
  let okm3 = @hash.hkdf_expand_sha256(prk3, b"", 42)
  assert_eq(
    @hash.hex_encode(okm3),
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
  )
}

///|
test "RFC 5869 HKDF-SHA512 test vectors" {
  let ikm = repeat_byte(b'\x0b', 22)
  let salt = must_hex("000102030405060708090a0b0c")
  let info = must_hex("f0f1f2f3f4f5f6f7f8f9")
  let prk1 = @hash.hkdf_extract_sha512(salt, ikm)
  assert_eq(
    @hash.hex_encode(prk1),
    "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
  )
  let okm1 = @hash.hkdf_expand_sha512(prk1, info, 82)
  assert_eq(
    @hash.hex_encode(okm1),
    "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137be3fb62f3cf32b84feba8f1eb1b563e20d97",
  )

  // Empty salt -> 64 zero bytes
  let prk3 = @hash.hkdf_extract_sha512(b"", ikm)
  assert_eq(
    @hash.hex_encode(prk3),
    "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
  )
  let okm3 = @hash.hkdf_expand_sha512(prk3, b"", 42)
  assert_eq(
    @hash.hex_encode(okm3),
    "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
  )
}

///|
test "RFC 9380 Appendix K.1 expand_message_xmd(SHA-256)" {
  let dst = b"QUUX-V01-CS02-with-expander-SHA256-128"
  let q128 = @hash.concat_bytes([b"q128_", repeat_byte(b'q', 128)])
  let a512 = @hash.concat_bytes([b"a512_", repeat_byte(b'a', 512)])

  // len = 0x20
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"", dst, 0x20)),
    "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"abc", dst, 0x20)),
    "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
  )
  assert_eq(
    @hash.hex_encode(
      @hash.expand_message_xmd_sha256(b"abcdef0123456789", dst, 0x20),
    ),
    "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(q128, dst, 0x20)),
    "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(a512, dst, 0x20)),
    "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
  )

  // len = 0x80 (multi-block output)
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"", dst, 0x80)),
    "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"abc", dst, 0x80)),
    "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(a512, dst, 0x80)),
    "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487",
  )
}

///|
test "RFC 9380 Appendix K.2 expand_message_xmd(SHA-256) Long DST (> 255 bytes)" {
  let long_dst = @hash.concat_bytes([
    b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-",
    repeat_byte(b'1', 208),
  ])
  assert_eq(long_dst.length(), 256)
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"", long_dst, 0x20)),
    "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"abc", long_dst, 0x20)),
    "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha256(b"abc", long_dst, 0x80)),
    "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267",
  )
}

///|
test "RFC 9380 Appendix K.3 expand_message_xmd(SHA-512)" {
  let dst = b"QUUX-V01-CS02-with-expander-SHA512-256"
  let q128 = @hash.concat_bytes([b"q128_", repeat_byte(b'q', 128)])
  let a512 = @hash.concat_bytes([b"a512_", repeat_byte(b'a', 512)])

  // len = 0x20
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(b"", dst, 0x20)),
    "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(b"abc", dst, 0x20)),
    "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(q128, dst, 0x20)),
    "7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(a512, dst, 0x20)),
    "57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4",
  )

  // len = 0x80
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(b"", dst, 0x80)),
    "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(b"abc", dst, 0x80)),
    "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1",
  )
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(a512, dst, 0x80)),
    "05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b",
  )
}

///|
test "RFC 8018 / RFC 6070 PBKDF2-HMAC-SHA256 & PBKDF2-HMAC-SHA512 test vectors" {
  // PBKDF2-HMAC-SHA256
  assert_eq(
    @hash.hex_encode(@hash.pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)),
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
  )
  assert_eq(
    @hash.hex_encode(@hash.pbkdf2_hmac_sha256(b"password", b"salt", 2, 32)),
    "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
  )
  assert_eq(
    @hash.hex_encode(@hash.pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32)),
    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
  )
  assert_eq(
    @hash.hex_encode(
      @hash.pbkdf2_hmac_sha256(
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
        40,
      ),
    ),
    "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
  )

  // PBKDF2-HMAC-SHA512
  assert_eq(
    @hash.hex_encode(@hash.pbkdf2_hmac_sha512(b"password", b"salt", 1, 64)),
    "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
  )
  assert_eq(
    @hash.hex_encode(@hash.pbkdf2_hmac_sha512(b"password", b"salt", 2, 64)),
    "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
  )
  assert_eq(
    @hash.hex_encode(@hash.pbkdf2_hmac_sha512(b"password", b"salt", 4096, 64)),
    "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
  )
  assert_eq(
    @hash.hex_encode(
      @hash.pbkdf2_hmac_sha512(
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
        40,
      ),
    ),
    "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd953",
  )
}

///|
test "RFC 7693 BLAKE2b test vectors" {
  // Empty message, 64-byte digest
  assert_eq(
    @hash.hex_encode(@hash.blake2b(b"", 64)),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  )
  // "abc", 64-byte digest (RFC 7693 Appendix A)
  assert_eq(
    @hash.hex_encode(@hash.blake2b(b"abc", 64)),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  )
  // "abc", 32-byte digest
  assert_eq(
    @hash.hex_encode(@hash.blake2b(b"abc", 32)),
    "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
  )
}

///|
test "RFC 9106 Section 5.3 Argon2id official test vector and standard KSF vectors" {
  // Official RFC 9106 §5.3 Argon2id test vector:
  // p=4, T=32, m=32, t=3, v=0x13, y=2, P=0x01*32, S=0x02*16, K=0x03*8, X=0x04*12
  let rfc_tag = @hash.argon2id_full(
    repeat_byte(b'\x01', 32),
    repeat_byte(b'\x02', 16),
    repeat_byte(b'\x03', 8),
    repeat_byte(b'\x04', 12),
    3,
    32,
    4,
    32,
  )
  assert_eq(
    @hash.hex_encode(rfc_tag),
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
  )

  // Standard argon2id (no secret/ad), cross-verified against reference argon2 implementation
  assert_eq(
    @hash.hex_encode(@hash.argon2id(b"password", b"somesalt", 2, 64, 1, 32)),
    "16a1a498734609dd01456da406de9f3d9da93e6c86c300a12fc1465214ce4922",
  )
  assert_eq(
    @hash.hex_encode(
      @hash.argon2id(b"password", b"somesalt12345678", 3, 128, 4, 64),
    ),
    "59c52e37702b815978cd263524f38218c0514dac4ae64d1415c1cfcaecd1ad0bf6bb86aef4410925a4bb51de2ded9f5c9fec9c1ba6a214b92c269cb07eb6f34d",
  )
  assert_eq(
    @hash.hex_encode(
      @hash.argon2id(b"test_opaque_pw", b"0123456789abcdef", 1, 32, 2, 32),
    ),
    "479fa14874e3786ecfe9576e8f365c6842dee6e8d9dcbe691dae79f60bd8b08c",
  )
  // Large segment (>128 blocks/slice, triggering multiple address blocks) + tag_len > 64 (H' multi-block)
  assert_eq(
    @hash.hex_encode(
      @hash.argon2id(b"opaque-big-seg", b"0123456789abcdef", 1, 1024, 1, 96),
    ),
    "01176404729b12853d4490490b788086a968cd1507bac8198336ab57d10e848b6175717bacd67298c488b8cce3ba919d30a2a17b0e4a1a11eaefe004f428759e2bd18f791014bd75f1536cc83bb76b48f7c3c97ce14a0b89eda5acd8c528760a",
  )
}

///|
test "block boundary and oversize DST edge cases" {
  // SHA-256 55-byte and 64-byte exact block boundaries
  assert_eq(
    @hash.hex_encode(@hash.sha256(repeat_byte(b'a', 55))),
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
  )
  assert_eq(
    @hash.hex_encode(@hash.sha256(repeat_byte(b'a', 64))),
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
  )
  // SHA-512 111-byte and 128-byte exact block boundaries
  assert_eq(
    @hash.hex_encode(@hash.sha512(repeat_byte(b'a', 111))),
    "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
  )
  assert_eq(
    @hash.hex_encode(@hash.sha512(repeat_byte(b'a', 128))),
    "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
  )
  // BLAKE2b exact 128-byte block, 129-byte multi-block, and 1-byte output
  assert_eq(
    @hash.hex_encode(@hash.blake2b(repeat_byte(b'b', 128), 64)),
    "1647cd53f8be2af17c7bebbd4543efb60950ebd3ba3979f68d3c1902644f083861baa7920716b04f30f0f66f9001b4ab86838503964f2ff449d424fa5619fc99",
  )
  assert_eq(
    @hash.hex_encode(@hash.blake2b(repeat_byte(b'b', 129), 32)),
    "e07bda70cd80e294099c00563ead9110ee1f4eee86e2cefc8be3b669552a5cfb",
  )
  assert_eq(@hash.hex_encode(@hash.blake2b(b"abc", 1)), "6b")
  // expand_message_xmd_sha512 with oversize DST (260 bytes > 255)
  let long_dst_512 = @hash.concat_bytes([
    b"OPAQUE-OVERSIZE-SHA512-",
    repeat_byte(b'x', 237),
  ])
  assert_eq(long_dst_512.length(), 260)
  assert_eq(
    @hash.hex_encode(@hash.expand_message_xmd_sha512(b"abc", long_dst_512, 48)),
    "27cfb5d33dd746769480fd33628f751e190c982f9df006946614592bbf7dae16c0b3fb8446859757c5586e56104ce5e0",
  )
}
