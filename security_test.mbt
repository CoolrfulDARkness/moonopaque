///|
fn sec_hex(hex : String) -> Bytes {
  match @hash.hex_decode(hex) {
    Some(b) => b
    None => abort("invalid hex literal in security test")
  }
}

///|
fn sec_flip_bit(b : Bytes, index : Int32, mask : UInt32) -> Bytes {
  Bytes::makei(b.length(), i => {
    if i == index {
      (b[i].to_uint() ^ mask).to_byte()
    } else {
      b[i]
    }
  })
}

///|
fn sec_replace_slice(b : Bytes, offset : Int32, replacement : Bytes) -> Bytes {
  let rep_len = replacement.length()
  Bytes::makei(b.length(), i => {
    if i >= offset && i < offset + rep_len {
      replacement[i - offset]
    } else {
      b[i]
    }
  })
}

///|
fn sec_slice(b : Bytes, start : Int32, len : Int32) -> Bytes {
  Bytes::makei(len, i => b[start + i])
}

///|
fn sec_append_zero(b : Bytes) -> Bytes {
  let len = b.length()
  Bytes::makei(len + 1, i => if i < len { b[i] } else { b'\x00' })
}

///|
fn[T] sec_unwrap_ok(
  res : Result[T, @moonopaque.OpaqueError],
  label : String,
) -> T raise {
  match res {
    Ok(v) => v
    Err(e) => fail(label + " failed: " + Show::to_string(e))
  }
}

///|
fn sec_register_user(
  config : @moonopaque.Config,
  server_setup : @moonopaque.ServerSetup,
  password : Bytes,
  cred_id : Bytes,
  client_id : Bytes?,
  server_id : Bytes?,
  reg_rand : Bytes,
  env_nonce : Bytes,
) -> (@moonopaque.RegistrationRecord, Bytes) raise {
  let (reg_state, reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      config, password, reg_rand,
    ),
    "create_registration_request_with_random",
  )
  let reg_resp = sec_unwrap_ok(
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, cred_id,
    ),
    "create_registration_response",
  )
  sec_unwrap_ok(
    @moonopaque.finalize_registration_request(
      config, reg_state, reg_resp, client_id, server_id, env_nonce,
    ),
    "finalize_registration_request",
  )
}

///|
fn sec_suite_offsets(
  suite : @moonopaque.CipherSuite,
) -> (Int32, Int32, Int32, Int32) {
  // Returns (noe, npk, cr_len, record_env_offset)
  match suite {
    Ristretto255Sha512 | Ristretto255Curve25519Sha512 => (32, 32, 192, 96)
    P256Sha256 => (33, 33, 162, 65)
  }
}

///|
fn sec_both_suites() -> Array[@moonopaque.CipherSuite] {
  [
    @moonopaque.CipherSuite::Ristretto255Sha512,
    @moonopaque.CipherSuite::P256Sha256,
  ]
}

///|
test "security 01: wrong password rejected (Ristretto255-SHA512)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-01")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x11')),
    "from_seed",
  )
  let cred_id = b"alice@example.com"
  let password = b"CorrectHorseBatteryStaple"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    Some(cred_id),
    Some(b"auth.example.com"),
    Bytes::make(32, b'\x12'),
    Bytes::make(32, b'\x13'),
  )
  let wrong_passwords : Array[Bytes] = [
    b"WrongHorseBatteryStaple",
    b"",
    sec_flip_bit(password, 0, 0x01U),
    sec_flip_bit(password, password.length() - 1, 0x80U),
  ]
  for i = 0; i < wrong_passwords.length(); i = i + 1 {
    let seed = Bytes::make(32, (0x20 + i).to_byte())
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(config, wrong_passwords[i], seed),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        Some(b"auth.example.com"),
        Some(cred_id),
        record,
        cred_id,
        ke1,
        Bytes::make(32, (0x30 + i).to_byte()),
        Bytes::make(32, (0x40 + i).to_byte()),
        Bytes::make(32, (0x50 + i).to_byte()),
      ),
      "generate_ke2",
    )
    assert_eq(
      @moonopaque.generate_ke3(
        config,
        client_state,
        Some(cred_id),
        Some(b"auth.example.com"),
        ke2,
      ),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
  }
}

///|
test "security 02: wrong password rejected (P256-SHA256)" {
  let suite = @moonopaque.CipherSuite::P256Sha256
  let config = @moonopaque.Config::p256_sha256(context=b"sec-02")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x11')),
    "from_seed",
  )
  let cred_id = b"bob@example.com"
  let password = b"CorrectHorseBatteryStaple"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    Some(cred_id),
    Some(b"auth.example.com"),
    Bytes::make(32, b'\x12'),
    Bytes::make(32, b'\x13'),
  )
  let wrong_passwords : Array[Bytes] = [
    b"WrongHorseBatteryStaple",
    b"",
    sec_flip_bit(password, 0, 0x01U),
    sec_flip_bit(password, password.length() - 1, 0x01U),
  ]
  for i = 0; i < wrong_passwords.length(); i = i + 1 {
    let seed = Bytes::make(32, (0x20 + i).to_byte())
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(config, wrong_passwords[i], seed),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        Some(b"auth.example.com"),
        Some(cred_id),
        record,
        cred_id,
        ke1,
        Bytes::make(32, (0x30 + i).to_byte()),
        Bytes::make(32, (0x40 + i).to_byte()),
        Bytes::make(32, (0x50 + i).to_byte()),
      ),
      "generate_ke2",
    )
    assert_eq(
      @moonopaque.generate_ke3(
        config,
        client_state,
        Some(cred_id),
        Some(b"auth.example.com"),
        ke2,
      ),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
  }
}

///|
test "security 03: unknown user anti-enumeration fake KE2 (Ristretto255-SHA512)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-03")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x21')),
    "from_seed",
  )
  let server_id = Some(b"auth.example.com")
  let real_id = b"real-user"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    b"real-password",
    real_id,
    Some(real_id),
    server_id,
    Bytes::make(32, b'\x22'),
    Bytes::make(32, b'\x23'),
  )
  let (_, real_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"real-password",
      Bytes::make(32, b'\x24'),
    ),
    "real ke1",
  )
  let (_, real_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_id,
      Some(real_id),
      record,
      real_id,
      real_ke1,
      Bytes::make(32, b'\x25'),
      Bytes::make(32, b'\x26'),
      Bytes::make(32, b'\x27'),
    ),
    "real ke2",
  )
  let ghost_id = b"ghost@example.com"
  let (ghost_state, ghost_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"guessed-password",
      Bytes::make(32, b'\x28'),
    ),
    "ghost ke1",
  )
  let (_, fake_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2_for_unknown_user(
      config,
      server_setup,
      server_id,
      Some(ghost_id),
      ghost_id,
      ghost_ke1,
      Bytes::make(32, b'\x29'),
    ),
    "generate_ke2_for_unknown_user",
  )
  let real_bytes = real_ke2.to_bytes()
  let fake_bytes = fake_ke2.to_bytes()
  assert_eq(fake_bytes.length(), real_bytes.length())
  assert_eq(fake_bytes.length(), 320)
  let parsed_fake = sec_unwrap_ok(
    @moonopaque.KE2::from_bytes(suite, fake_bytes),
    "KE2::from_bytes(fake)",
  )
  assert_eq(parsed_fake, fake_ke2)
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      ghost_state,
      Some(ghost_id),
      server_id,
      parsed_fake,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )
}

///|
test "security 04: unknown user anti-enumeration fake KE2 (P256-SHA256)" {
  let suite = @moonopaque.CipherSuite::P256Sha256
  let config = @moonopaque.Config::p256_sha256(context=b"sec-04")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x21')),
    "from_seed",
  )
  let server_id = Some(b"auth.example.com")
  let real_id = b"real-user"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    b"real-password",
    real_id,
    Some(real_id),
    server_id,
    Bytes::make(32, b'\x22'),
    Bytes::make(32, b'\x23'),
  )
  let (_, real_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"real-password",
      Bytes::make(32, b'\x24'),
    ),
    "real ke1",
  )
  let (_, real_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_id,
      Some(real_id),
      record,
      real_id,
      real_ke1,
      Bytes::make(32, b'\x25'),
      Bytes::make(32, b'\x26'),
      Bytes::make(32, b'\x27'),
    ),
    "real ke2",
  )
  let ghost_id = b"ghost@example.com"
  let (ghost_state, ghost_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"guessed-password",
      Bytes::make(32, b'\x28'),
    ),
    "ghost ke1",
  )
  let (_, fake_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2_for_unknown_user(
      config,
      server_setup,
      server_id,
      Some(ghost_id),
      ghost_id,
      ghost_ke1,
      Bytes::make(32, b'\x29'),
    ),
    "generate_ke2_for_unknown_user",
  )
  let real_bytes = real_ke2.to_bytes()
  let fake_bytes = fake_ke2.to_bytes()
  assert_eq(fake_bytes.length(), real_bytes.length())
  assert_eq(fake_bytes.length(), 259)
  let parsed_fake = sec_unwrap_ok(
    @moonopaque.KE2::from_bytes(suite, fake_bytes),
    "KE2::from_bytes(fake)",
  )
  assert_eq(parsed_fake, fake_ke2)
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      ghost_state,
      Some(ghost_id),
      server_id,
      parsed_fake,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )
}

///|
test "security 05: tampered envelope auth_tag rejected (Ristretto255-SHA512)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-05")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x31')),
    "from_seed",
  )
  let cred_id = b"env-tag-user"
  let password = b"envelope-password"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    None,
    None,
    Bytes::make(32, b'\x32'),
    Bytes::make(32, b'\x33'),
  )
  let rec_bytes = record.to_bytes()
  // Flip 1 bit at first byte and last byte of auth_tag (offset 128..192)
  let positions = [128, rec_bytes.length() - 1, 96]
  for i = 0; i < positions.length(); i = i + 1 {
    let bad_record = sec_unwrap_ok(
      @moonopaque.RegistrationRecord::from_bytes(
        suite,
        sec_flip_bit(rec_bytes, positions[i], 0x01U),
      ),
      "RegistrationRecord::from_bytes",
    )
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, (0x34 + i).to_byte()),
      ),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        bad_record,
        cred_id,
        ke1,
        Bytes::make(32, b'\x3a'),
        Bytes::make(32, b'\x3b'),
        Bytes::make(32, b'\x3c'),
      ),
      "generate_ke2",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state, None, None, ke2),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
  }
}

///|
test "security 06: tampered envelope auth_tag rejected (P256-SHA256)" {
  let suite = @moonopaque.CipherSuite::P256Sha256
  let config = @moonopaque.Config::p256_sha256(context=b"sec-06")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x31')),
    "from_seed",
  )
  let cred_id = b"env-tag-user-p256"
  let password = b"envelope-password"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    None,
    None,
    Bytes::make(32, b'\x32'),
    Bytes::make(32, b'\x33'),
  )
  let rec_bytes = record.to_bytes()
  // Flip 1 bit at first byte and last byte of auth_tag (offset 97..129) and nonce (offset 65)
  let positions = [97, rec_bytes.length() - 1, 65]
  for i = 0; i < positions.length(); i = i + 1 {
    let bad_record = sec_unwrap_ok(
      @moonopaque.RegistrationRecord::from_bytes(
        suite,
        sec_flip_bit(rec_bytes, positions[i], 0x01U),
      ),
      "RegistrationRecord::from_bytes",
    )
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, (0x34 + i).to_byte()),
      ),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        bad_record,
        cred_id,
        ke1,
        Bytes::make(32, b'\x3a'),
        Bytes::make(32, b'\x3b'),
        Bytes::make(32, b'\x3c'),
      ),
      "generate_ke2",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state, None, None, ke2),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
  }
}

///|
test "security 07: tampered CredentialResponse masked_response and masking_nonce rejected (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-07", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x41')),
      "from_seed",
    )
    let cred_id = b"mask-user"
    let password = b"mask-password"
    let (record, _) = sec_register_user(
      config,
      server_setup,
      password,
      cred_id,
      None,
      None,
      Bytes::make(32, b'\x42'),
      Bytes::make(32, b'\x43'),
    )
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\x44'),
      ),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        cred_id,
        ke1,
        Bytes::make(32, b'\x45'),
        Bytes::make(32, b'\x46'),
        Bytes::make(32, b'\x47'),
      ),
      "generate_ke2",
    )
    let (noe, npk, cr_len, _) = sec_suite_offsets(suite)
    let ke2_bytes = ke2.to_bytes()
    // Flip 1 bit in masking_nonce (first and last byte) and in masked_response
    // (server_pk portion, envelope nonce portion, envelope auth_tag portion)
    let flip_offsets = [noe, noe + 31, noe + 32, noe + 32 + npk, cr_len - 1]
    for off in flip_offsets {
      let tampered_ke2 = sec_unwrap_ok(
        @moonopaque.KE2::from_bytes(suite, sec_flip_bit(ke2_bytes, off, 0x01U)),
        "KE2::from_bytes",
      )
      assert_eq(
        @moonopaque.generate_ke3(config, client_state, None, None, tampered_ke2),
        Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
      )
    }
  }
}

///|
test "security 08: tampered KE2 server_mac rejected (Ristretto255-SHA512)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-08")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x51')),
    "from_seed",
  )
  let cred_id = b"mac-user-r255"
  let password = b"mac-password"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    None,
    None,
    Bytes::make(32, b'\x52'),
    Bytes::make(32, b'\x53'),
  )
  let (client_state, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x54'),
    ),
    "generate_ke1",
  )
  let (_, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      ke1,
      Bytes::make(32, b'\x55'),
      Bytes::make(32, b'\x56'),
      Bytes::make(32, b'\x57'),
    ),
    "generate_ke2",
  )
  let ke2_bytes = ke2.to_bytes()
  // server_mac starts at 192 + 32 + 32 = 256, ends at 320
  for off in [256, 287, 319] {
    let bad_ke2 = sec_unwrap_ok(
      @moonopaque.KE2::from_bytes(suite, sec_flip_bit(ke2_bytes, off, 0x01U)),
      "KE2::from_bytes",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state, None, None, bad_ke2),
      Err(@moonopaque.OpaqueError::InvalidServerMac),
    )
  }
}

///|
test "security 09: tampered KE2 server_mac rejected (P256-SHA256)" {
  let suite = @moonopaque.CipherSuite::P256Sha256
  let config = @moonopaque.Config::p256_sha256(context=b"sec-09")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x51')),
    "from_seed",
  )
  let cred_id = b"mac-user-p256"
  let password = b"mac-password"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    None,
    None,
    Bytes::make(32, b'\x52'),
    Bytes::make(32, b'\x53'),
  )
  let (client_state, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x54'),
    ),
    "generate_ke1",
  )
  let (_, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      ke1,
      Bytes::make(32, b'\x55'),
      Bytes::make(32, b'\x56'),
      Bytes::make(32, b'\x57'),
    ),
    "generate_ke2",
  )
  let ke2_bytes = ke2.to_bytes()
  // server_mac starts at 162 + 32 + 33 = 227, ends at 259
  for off in [227, 242, 258] {
    let bad_ke2 = sec_unwrap_ok(
      @moonopaque.KE2::from_bytes(suite, sec_flip_bit(ke2_bytes, off, 0x01U)),
      "KE2::from_bytes",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state, None, None, bad_ke2),
      Err(@moonopaque.OpaqueError::InvalidServerMac),
    )
  }
}

///|
test "security 10: tampered KE2 server_nonce rejected via transcript binding (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-10", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x61')),
      "from_seed",
    )
    let cred_id = b"nonce-user"
    let password = b"nonce-password"
    let (record, _) = sec_register_user(
      config,
      server_setup,
      password,
      cred_id,
      None,
      None,
      Bytes::make(32, b'\x62'),
      Bytes::make(32, b'\x63'),
    )
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\x64'),
      ),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        cred_id,
        ke1,
        Bytes::make(32, b'\x65'),
        Bytes::make(32, b'\x66'),
        Bytes::make(32, b'\x67'),
      ),
      "generate_ke2",
    )
    let (_, _, cr_len, _) = sec_suite_offsets(suite)
    let ke2_bytes = ke2.to_bytes()
    for off in [cr_len, cr_len + 31] {
      let bad_ke2 = sec_unwrap_ok(
        @moonopaque.KE2::from_bytes(suite, sec_flip_bit(ke2_bytes, off, 0x01U)),
        "KE2::from_bytes",
      )
      assert_eq(
        @moonopaque.generate_ke3(config, client_state, None, None, bad_ke2),
        Err(@moonopaque.OpaqueError::InvalidServerMac),
      )
    }
  }
}

///|
test "security 11: tampered KE2 server_public_keyshare rejected (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-11", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x71')),
      "from_seed",
    )
    let cred_id = b"keyshare-user"
    let password = b"keyshare-password"
    let (record, _) = sec_register_user(
      config,
      server_setup,
      password,
      cred_id,
      None,
      None,
      Bytes::make(32, b'\x72'),
      Bytes::make(32, b'\x73'),
    )
    let (client_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\x74'),
      ),
      "generate_ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        cred_id,
        ke1,
        Bytes::make(32, b'\x75'),
        Bytes::make(32, b'\x76'),
        Bytes::make(32, b'\x77'),
      ),
      "generate_ke2",
    )
    let (_, attacker_pk) = sec_unwrap_ok(
      @moonopaque.derive_dh_keypair(suite, Bytes::make(32, b'\xee')),
      "derive_dh_keypair(attacker)",
    )
    assert_true(attacker_pk != ke2.server_public_keyshare())
    let (_, _, cr_len, _) = sec_suite_offsets(suite)
    let tampered_bytes = sec_replace_slice(
      ke2.to_bytes(),
      cr_len + 32,
      attacker_pk,
    )
    let tampered_ke2 = sec_unwrap_ok(
      @moonopaque.KE2::from_bytes(suite, tampered_bytes),
      "KE2::from_bytes",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state, None, None, tampered_ke2),
      Err(@moonopaque.OpaqueError::InvalidServerMac),
    )
  }
}

///|
test "security 12: tampered KE3 client_mac rejected (Ristretto255-SHA512)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-12")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x81')),
    "from_seed",
  )
  let cred_id = b"ke3-user-r255"
  let password = b"ke3-password"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    None,
    None,
    Bytes::make(32, b'\x82'),
    Bytes::make(32, b'\x83'),
  )
  let (client_state, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x84'),
    ),
    "generate_ke1",
  )
  let (server_state, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      ke1,
      Bytes::make(32, b'\x85'),
      Bytes::make(32, b'\x86'),
      Bytes::make(32, b'\x87'),
    ),
    "generate_ke2",
  )
  let login_res = sec_unwrap_ok(
    @moonopaque.generate_ke3(config, client_state, None, None, ke2),
    "generate_ke3",
  )
  let ke3_bytes = login_res.ke3().to_bytes()
  assert_eq(ke3_bytes.length(), 64)
  for off in [0, 31, 63] {
    let bad_ke3 = sec_unwrap_ok(
      @moonopaque.KE3::from_bytes(suite, sec_flip_bit(ke3_bytes, off, 0x01U)),
      "KE3::from_bytes",
    )
    assert_eq(
      @moonopaque.server_finish(server_state, bad_ke3),
      Err(@moonopaque.OpaqueError::InvalidClientMac),
    )
  }
}

///|
test "security 13: tampered KE3 client_mac rejected (P256-SHA256)" {
  let suite = @moonopaque.CipherSuite::P256Sha256
  let config = @moonopaque.Config::p256_sha256(context=b"sec-13")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x81')),
    "from_seed",
  )
  let cred_id = b"ke3-user-p256"
  let password = b"ke3-password"
  let (record, _) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    None,
    None,
    Bytes::make(32, b'\x82'),
    Bytes::make(32, b'\x83'),
  )
  let (client_state, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x84'),
    ),
    "generate_ke1",
  )
  let (server_state, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      ke1,
      Bytes::make(32, b'\x85'),
      Bytes::make(32, b'\x86'),
      Bytes::make(32, b'\x87'),
    ),
    "generate_ke2",
  )
  let login_res = sec_unwrap_ok(
    @moonopaque.generate_ke3(config, client_state, None, None, ke2),
    "generate_ke3",
  )
  let ke3_bytes = login_res.ke3().to_bytes()
  assert_eq(ke3_bytes.length(), 32)
  for off in [0, 15, 31] {
    let bad_ke3 = sec_unwrap_ok(
      @moonopaque.KE3::from_bytes(suite, sec_flip_bit(ke3_bytes, off, 0x01U)),
      "KE3::from_bytes",
    )
    assert_eq(
      @moonopaque.server_finish(server_state, bad_ke3),
      Err(@moonopaque.OpaqueError::InvalidClientMac),
    )
  }
}

///|
test "security 14: cross-application context mismatch rejected (both suites)" {
  for suite in sec_both_suites() {
    let server_cfg = @moonopaque.Config::new(suite, b"app-prod-v1", Identity)
    let client_cfg = @moonopaque.Config::new(suite, b"app-staging-v1", Identity)
    let empty_cfg = @moonopaque.Config::new(suite, b"", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x91')),
      "from_seed",
    )
    let cred_id = b"ctx-user"
    let password = b"ctx-password"
    let (record, _) = sec_register_user(
      server_cfg,
      server_setup,
      password,
      cred_id,
      None,
      None,
      Bytes::make(32, b'\x92'),
      Bytes::make(32, b'\x93'),
    )
    for bad_cfg in [client_cfg, empty_cfg] {
      let (client_state, ke1) = sec_unwrap_ok(
        @moonopaque.generate_ke1_with_random(
          bad_cfg,
          password,
          Bytes::make(32, b'\x94'),
        ),
        "generate_ke1",
      )
      let (_, ke2) = sec_unwrap_ok(
        @moonopaque.generate_ke2(
          server_cfg,
          server_setup,
          None,
          None,
          record,
          cred_id,
          ke1,
          Bytes::make(32, b'\x95'),
          Bytes::make(32, b'\x96'),
          Bytes::make(32, b'\x97'),
        ),
        "generate_ke2",
      )
      assert_eq(
        @moonopaque.generate_ke3(bad_cfg, client_state, None, None, ke2),
        Err(@moonopaque.OpaqueError::InvalidServerMac),
      )
    }
  }
}

///|
test "security 15: cross-identity confusion attack rejected (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-15", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\xa1')),
      "from_seed",
    )
    let cred_id = b"id-user"
    let password = b"id-password"
    let alice = Some(b"alice@example.com")
    let mallory = Some(b"mallory@example.com")
    let srv_a = Some(b"auth-a.example.com")
    let srv_b = Some(b"auth-b.example.com")
    let (record, _) = sec_register_user(
      config,
      server_setup,
      password,
      cred_id,
      alice,
      srv_a,
      Bytes::make(32, b'\xa2'),
      Bytes::make(32, b'\xa3'),
    )
    // Case A: client uses wrong client_identity during login -> InvalidEnvelopeTag
    let (st_a, ke1_a) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\xa4'),
      ),
      "ke1_a",
    )
    let (_, ke2_a) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        srv_a,
        alice,
        record,
        cred_id,
        ke1_a,
        Bytes::make(32, b'\xa5'),
        Bytes::make(32, b'\xa6'),
        Bytes::make(32, b'\xa7'),
      ),
      "ke2_a",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, st_a, mallory, srv_a, ke2_a),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
    // Case B: client uses wrong server_identity during login -> InvalidEnvelopeTag
    assert_eq(
      @moonopaque.generate_ke3(config, st_a, alice, srv_b, ke2_a),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
    // Case C: client omits registered identity (None) -> InvalidEnvelopeTag
    assert_eq(
      @moonopaque.generate_ke3(config, st_a, None, srv_a, ke2_a),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
    // Case D: server passes mismatched client_identity to generate_ke2 -> envelope valid, Preamble differs -> InvalidServerMac
    let (_, ke2_srv_mismatch) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        srv_a,
        mallory,
        record,
        cred_id,
        ke1_a,
        Bytes::make(32, b'\xa8'),
        Bytes::make(32, b'\xa9'),
        Bytes::make(32, b'\xaa'),
      ),
      "ke2_srv_mismatch",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, st_a, alice, srv_a, ke2_srv_mismatch),
      Err(@moonopaque.OpaqueError::InvalidServerMac),
    )
  }
}

///|
test "security 16: cross-user credential substitution rejected (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-16", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\xb1')),
      "from_seed",
    )
    // Even when User A and User B share the exact same password, their per-user OPRF keys differ
    let shared_pw = b"same-password-different-users"
    let (_record_a, _) = sec_register_user(
      config,
      server_setup,
      shared_pw,
      b"user-a",
      None,
      None,
      Bytes::make(32, b'\xb2'),
      Bytes::make(32, b'\xb3'),
    )
    let (record_b, _) = sec_register_user(
      config,
      server_setup,
      shared_pw,
      b"user-b",
      None,
      None,
      Bytes::make(32, b'\xb4'),
      Bytes::make(32, b'\xb5'),
    )
    let (record_c, _) = sec_register_user(
      config,
      server_setup,
      b"different-password",
      b"user-c",
      None,
      None,
      Bytes::make(32, b'\xb6'),
      Bytes::make(32, b'\xb7'),
    )
    let (client_state_a, ke1_a) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        shared_pw,
        Bytes::make(32, b'\xb8'),
      ),
      "ke1_a",
    )
    // Server responds to User A's cred_id with User B's record
    let (_, sub_ke2_b) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record_b,
        b"user-a",
        ke1_a,
        Bytes::make(32, b'\xb9'),
        Bytes::make(32, b'\xba'),
        Bytes::make(32, b'\xbb'),
      ),
      "sub_ke2_b",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state_a, None, None, sub_ke2_b),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
    // Server responds to User A's login with User C's record and cred_id
    let (_, sub_ke2_c) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record_c,
        b"user-c",
        ke1_a,
        Bytes::make(32, b'\xbc'),
        Bytes::make(32, b'\xbd'),
        Bytes::make(32, b'\xbe'),
      ),
      "sub_ke2_c",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state_a, None, None, sub_ke2_c),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
  }
}

///|
test "security 17: replay attack defense and fresh session keys (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-17", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\xc1')),
      "from_seed",
    )
    let cred_id = b"replay-user"
    let password = b"replay-password"
    let (record, reg_export_key) = sec_register_user(
      config,
      server_setup,
      password,
      cred_id,
      None,
      None,
      Bytes::make(32, b'\xc2'),
      Bytes::make(32, b'\xc3'),
    )
    // Session 1
    let (c_state_1, ke1_1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\xc4'),
      ),
      "ke1_1",
    )
    let (s_state_1, ke2_1) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        cred_id,
        ke1_1,
        Bytes::make(32, b'\xc5'),
        Bytes::make(32, b'\xc6'),
        Bytes::make(32, b'\xc7'),
      ),
      "ke2_1",
    )
    let login_1 = sec_unwrap_ok(
      @moonopaque.generate_ke3(config, c_state_1, None, None, ke2_1),
      "ke3_1",
    )
    let sk_1 = sec_unwrap_ok(
      @moonopaque.server_finish(s_state_1, login_1.ke3()),
      "finish_1",
    )
    assert_eq(sk_1, login_1.session_key())
    assert_eq(login_1.export_key(), reg_export_key)

    // Session 2 (independent nonces, blind, keyshares)
    let (c_state_2, ke1_2) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\xd4'),
      ),
      "ke1_2",
    )
    let (s_state_2, ke2_2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        cred_id,
        ke1_2,
        Bytes::make(32, b'\xd5'),
        Bytes::make(32, b'\xd6'),
        Bytes::make(32, b'\xd7'),
      ),
      "ke2_2",
    )
    let login_2 = sec_unwrap_ok(
      @moonopaque.generate_ke3(config, c_state_2, None, None, ke2_2),
      "ke3_2",
    )
    let sk_2 = sec_unwrap_ok(
      @moonopaque.server_finish(s_state_2, login_2.ke3()),
      "finish_2",
    )
    assert_eq(sk_2, login_2.session_key())
    assert_eq(login_2.export_key(), reg_export_key)
    assert_true(sk_1 != sk_2)

    // Replay Session 1's KE2 into Session 2's ClientLoginState -> rejected
    assert_eq(
      @moonopaque.generate_ke3(config, c_state_2, None, None, ke2_1),
      Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
    )
    // Replay Session 1's KE3 into Session 2's ServerLoginState -> rejected
    assert_eq(
      @moonopaque.server_finish(s_state_2, login_1.ke3()),
      Err(@moonopaque.OpaqueError::InvalidClientMac),
    )
  }
}

///|
test "security 18: identity and non-canonical point rejection (Ristretto255-SHA512)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-18")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x1a')),
    "from_seed",
  )
  let (reg_state, reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      config,
      b"pw",
      Bytes::make(32, b'\x1b'),
    ),
    "reg_req",
  )
  let reg_resp = sec_unwrap_ok(
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, b"u",
    ),
    "reg_resp",
  )
  let (record, _) = sec_unwrap_ok(
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp,
      None,
      None,
      Bytes::make(32, b'\x1c'),
    ),
    "finalize",
  )
  let (_, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"pw",
      Bytes::make(32, b'\x1d'),
    ),
    "ke1",
  )
  let (_, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      b"u",
      ke1,
      Bytes::make(32, b'\x1e'),
      Bytes::make(32, b'\x1f'),
      Bytes::make(32, b'\x20'),
    ),
    "ke2",
  )
  let valid_reg_resp = reg_resp.to_bytes()
  let valid_record = record.to_bytes()
  let valid_ke1 = ke1.to_bytes()
  let valid_ke2 = ke2.to_bytes()

  // All-zero identity element + official RFC 9496 Appendix A.2 invalid encodings
  let bad_elements : Array[Bytes] = [
    Bytes::make(32, b'\x00'),
    // Non-canonical field encoding
    sec_hex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    sec_hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    // Negative field element
    sec_hex("0100000000000000000000000000000000000000000000000000000000000000"),
    // Non-square x^2
    sec_hex("26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"),
    // Negative x*y
    sec_hex("3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e"),
    // s = -1 (y = 0)
    sec_hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
  ]
  for bad in bad_elements {
    assert_eq(
      @moonopaque.RegistrationRequest::from_bytes(suite, bad),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.CredentialRequest::from_bytes(suite, bad),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationResponse::from_bytes(
        suite,
        sec_replace_slice(valid_reg_resp, 0, bad),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationResponse::from_bytes(
        suite,
        sec_replace_slice(valid_reg_resp, 32, bad),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationRecord::from_bytes(
        suite,
        sec_replace_slice(valid_record, 0, bad),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE1::from_bytes(suite, sec_replace_slice(valid_ke1, 0, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE1::from_bytes(suite, sec_replace_slice(valid_ke1, 64, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE2::from_bytes(suite, sec_replace_slice(valid_ke2, 0, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE2::from_bytes(suite, sec_replace_slice(valid_ke2, 224, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
  }
}

///|
test "security 19: off-curve, identity, uncompressed prefix, and x>=p point rejection (P256-SHA256)" {
  let suite = @moonopaque.CipherSuite::P256Sha256
  let config = @moonopaque.Config::p256_sha256(context=b"sec-19")
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x1a')),
    "from_seed",
  )
  let (reg_state, reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      config,
      b"pw",
      Bytes::make(32, b'\x1b'),
    ),
    "reg_req",
  )
  let reg_resp = sec_unwrap_ok(
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, b"u",
    ),
    "reg_resp",
  )
  let (record, _) = sec_unwrap_ok(
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp,
      None,
      None,
      Bytes::make(32, b'\x1c'),
    ),
    "finalize",
  )
  let (_, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"pw",
      Bytes::make(32, b'\x1d'),
    ),
    "ke1",
  )
  let (_, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      b"u",
      ke1,
      Bytes::make(32, b'\x1e'),
      Bytes::make(32, b'\x1f'),
      Bytes::make(32, b'\x20'),
    ),
    "ke2",
  )
  let valid_reg_resp = reg_resp.to_bytes()
  let valid_record = record.to_bytes()
  let valid_ke1 = ke1.to_bytes()
  let valid_ke2 = ke2.to_bytes()

  let gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  let p_hex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
  let p_plus_1_hex = "ffffffff00000001000000000000000000000001000000000000000000000000"
  let bad_points : Array[Bytes] = [
    // Point at infinity / all-zero 33 bytes
    Bytes::make(33, b'\x00'),
    // Invalid 0x00 prefix with valid Gx
    sec_hex("00" + gx),
    // Uncompressed prefix 0x04 with 32-byte coordinate
    sec_hex("04" + gx),
    // Invalid prefixes 0x01 and 0x05
    sec_hex("01" + gx),
    sec_hex("05" + gx),
    // Off-curve points: x = 1, 2, 3, 7 have non-square x^3 - 3x + b mod p
    sec_hex(
      "020000000000000000000000000000000000000000000000000000000000000001",
    ),
    sec_hex(
      "030000000000000000000000000000000000000000000000000000000000000002",
    ),
    sec_hex(
      "020000000000000000000000000000000000000000000000000000000000000003",
    ),
    sec_hex(
      "030000000000000000000000000000000000000000000000000000000000000007",
    ),
    // Non-canonical x >= p (x == p, x == p + 1, x == 2^256 - 1)
    sec_hex("02" + p_hex),
    sec_hex("03" + p_hex),
    sec_hex("02" + p_plus_1_hex),
    sec_hex(
      "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
  ]
  for bad in bad_points {
    assert_eq(
      @moonopaque.RegistrationRequest::from_bytes(suite, bad),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.CredentialRequest::from_bytes(suite, bad),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationResponse::from_bytes(
        suite,
        sec_replace_slice(valid_reg_resp, 0, bad),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationResponse::from_bytes(
        suite,
        sec_replace_slice(valid_reg_resp, 33, bad),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationRecord::from_bytes(
        suite,
        sec_replace_slice(valid_record, 0, bad),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE1::from_bytes(suite, sec_replace_slice(valid_ke1, 0, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE1::from_bytes(suite, sec_replace_slice(valid_ke1, 65, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE2::from_bytes(suite, sec_replace_slice(valid_ke2, 0, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE2::from_bytes(suite, sec_replace_slice(valid_ke2, 194, bad)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
  }
  // 1-byte SEC1 infinity 0x00 and 65-byte uncompressed point rejected by length check
  assert_eq(
    @moonopaque.RegistrationRequest::from_bytes(suite, b"\x00"),
    Err(@moonopaque.OpaqueError::InvalidMessageLength),
  )
  let gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  assert_eq(
    @moonopaque.RegistrationRequest::from_bytes(suite, sec_hex("04" + gx + gy)),
    Err(@moonopaque.OpaqueError::InvalidMessageLength),
  )
}

///|
test "security 20: zero blind scalar and non-canonical scalar rejection (both suites)" {
  let nonce = Bytes::make(32, b'\x01')
  let ks_seed = Bytes::make(32, b'\x02')
  // Ristretto255 scalars (little-endian order L)
  let r255_cfg = @moonopaque.Config::ristretto255_sha512(context=b"sec-20")
  let r255_bad_scalars : Array[Bytes] = [
    Bytes::make(32, b'\x00'),
    // L
    sec_hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
    // L + 1
    sec_hex("eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
    // 2^256 - 1
    Bytes::make(32, b'\xff'),
    // Wrong lengths
    Bytes::make(31, b'\x01'),
    Bytes::make(33, b'\x01'),
  ]
  for bad_s in r255_bad_scalars {
    assert_true(
      @moonopaque.create_registration_request(r255_cfg, b"pw", bad_s)
      is Err(@moonopaque.OpaqueError::InvalidKey),
    )
    assert_true(
      @moonopaque.generate_ke1(r255_cfg, b"pw", bad_s, nonce, ks_seed)
      is Err(@moonopaque.OpaqueError::InvalidKey),
    )
  }

  // P-256 scalars (big-endian order n)
  let p256_cfg = @moonopaque.Config::p256_sha256(context=b"sec-20")
  let p256_bad_scalars : Array[Bytes] = [
    Bytes::make(32, b'\x00'),
    // n
    sec_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    // n + 1
    sec_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552"),
    // 2^256 - 1
    Bytes::make(32, b'\xff'),
    // Wrong lengths
    Bytes::make(31, b'\x01'),
    Bytes::make(33, b'\x01'),
  ]
  for bad_s in p256_bad_scalars {
    assert_true(
      @moonopaque.create_registration_request(p256_cfg, b"pw", bad_s)
      is Err(@moonopaque.OpaqueError::InvalidKey),
    )
    assert_true(
      @moonopaque.generate_ke1(p256_cfg, b"pw", bad_s, nonce, ks_seed)
      is Err(@moonopaque.OpaqueError::InvalidKey),
    )
  }
}

///|
test "security 21: truncated, empty, and oversized wire messages rejected (both suites)" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-21", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x2a')),
      "from_seed",
    )
    let (reg_state, reg_req) = sec_unwrap_ok(
      @moonopaque.create_registration_request_with_random(
        config,
        b"pw",
        Bytes::make(32, b'\x2b'),
      ),
      "reg_req",
    )
    let reg_resp = sec_unwrap_ok(
      @moonopaque.create_registration_response(
        config, server_setup, reg_req, b"u",
      ),
      "reg_resp",
    )
    let (record, _) = sec_unwrap_ok(
      @moonopaque.finalize_registration_request(
        config,
        reg_state,
        reg_resp,
        None,
        None,
        Bytes::make(32, b'\x2c'),
      ),
      "finalize",
    )
    let (c_state, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        b"pw",
        Bytes::make(32, b'\x2d'),
      ),
      "ke1",
    )
    let (_, ke2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        b"u",
        ke1,
        Bytes::make(32, b'\x2e'),
        Bytes::make(32, b'\x2f'),
        Bytes::make(32, b'\x30'),
      ),
      "ke2",
    )
    let login_res = sec_unwrap_ok(
      @moonopaque.generate_ke3(config, c_state, None, None, ke2),
      "ke3",
    )

    let env_b = record.envelope().to_bytes()
    for
      bad in [
        b"",
        sec_slice(env_b, 0, env_b.length() - 1),
        sec_append_zero(env_b),
      ] {
      assert_eq(
        @moonopaque.Envelope::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let req_b = reg_req.to_bytes()
    for
      bad in [
        b"",
        sec_slice(req_b, 0, req_b.length() - 1),
        sec_append_zero(req_b),
      ] {
      assert_eq(
        @moonopaque.RegistrationRequest::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
      assert_eq(
        @moonopaque.CredentialRequest::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let resp_b = reg_resp.to_bytes()
    for
      bad in [
        b"",
        sec_slice(resp_b, 0, resp_b.length() - 1),
        sec_append_zero(resp_b),
      ] {
      assert_eq(
        @moonopaque.RegistrationResponse::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let rec_b = record.to_bytes()
    for
      bad in [
        b"",
        sec_slice(rec_b, 0, rec_b.length() - 1),
        sec_append_zero(rec_b),
      ] {
      assert_eq(
        @moonopaque.RegistrationRecord::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let cr_b = ke2.credential_response().to_bytes()
    for
      bad in [b"", sec_slice(cr_b, 0, cr_b.length() - 1), sec_append_zero(cr_b)] {
      assert_eq(
        @moonopaque.CredentialResponse::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let ke1_b = ke1.to_bytes()
    for
      bad in [
        b"",
        sec_slice(ke1_b, 0, ke1_b.length() - 1),
        sec_append_zero(ke1_b),
      ] {
      assert_eq(
        @moonopaque.KE1::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let ke2_b = ke2.to_bytes()
    for
      bad in [
        b"",
        sec_slice(ke2_b, 0, ke2_b.length() - 1),
        sec_append_zero(ke2_b),
      ] {
      assert_eq(
        @moonopaque.KE2::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }

    let ke3_b = login_res.ke3().to_bytes()
    for
      bad in [
        b"",
        sec_slice(ke3_b, 0, ke3_b.length() - 1),
        sec_append_zero(ke3_b),
      ] {
      assert_eq(
        @moonopaque.KE3::from_bytes(suite, bad),
        Err(@moonopaque.OpaqueError::InvalidMessageLength),
      )
    }
  }
}

///|
test "security 22: cross-ciphersuite confusion and KSF mismatch rejected" {
  let r255_cfg = @moonopaque.Config::ristretto255_sha512(context=b"sec-22")
  let p256_cfg = @moonopaque.Config::p256_sha256(context=b"sec-22")
  let r255_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(
      @moonopaque.CipherSuite::Ristretto255Sha512,
      Bytes::make(32, b'\x4a'),
    ),
    "r255 setup",
  )
  let p256_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(
      @moonopaque.CipherSuite::P256Sha256,
      Bytes::make(32, b'\x4b'),
    ),
    "p256 setup",
  )
  let (r255_reg_state, r255_reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      r255_cfg,
      b"pw",
      Bytes::make(32, b'\x4c'),
    ),
    "r255 reg_req",
  )
  let (_, p256_reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      p256_cfg,
      b"pw",
      Bytes::make(32, b'\x4d'),
    ),
    "p256 reg_req",
  )
  // Cross-suite ServerSetup vs Config rejected with InvalidInput
  assert_eq(
    @moonopaque.create_registration_response(
      p256_cfg, r255_setup, p256_reg_req, b"u",
    ),
    Err(@moonopaque.OpaqueError::InvalidInput),
  )
  assert_eq(
    @moonopaque.create_registration_response(
      r255_cfg, p256_setup, r255_reg_req, b"u",
    ),
    Err(@moonopaque.OpaqueError::InvalidInput),
  )
  let r255_reg_resp = sec_unwrap_ok(
    @moonopaque.create_registration_response(
      r255_cfg, r255_setup, r255_reg_req, b"u",
    ),
    "r255 reg_resp",
  )
  // Cross-suite ClientRegistrationState vs Config rejected with InvalidInput
  assert_eq(
    @moonopaque.finalize_registration_request(
      p256_cfg,
      r255_reg_state,
      r255_reg_resp,
      None,
      None,
      Bytes::make(32, b'\x4e'),
    ),
    Err(@moonopaque.OpaqueError::InvalidInput),
  )
  let (p256_record, _) = sec_register_user(
    p256_cfg,
    p256_setup,
    b"pw",
    b"u",
    None,
    None,
    Bytes::make(32, b'\x50'),
    Bytes::make(32, b'\x51'),
  )
  let (p256_c_state, p256_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      p256_cfg,
      b"pw",
      Bytes::make(32, b'\x52'),
    ),
    "p256 ke1",
  )
  assert_true(
    @moonopaque.generate_ke2(
      p256_cfg,
      r255_setup,
      None,
      None,
      p256_record,
      b"u",
      p256_ke1,
      Bytes::make(32, b'\x53'),
      Bytes::make(32, b'\x54'),
      Bytes::make(32, b'\x55'),
    )
    is Err(@moonopaque.OpaqueError::InvalidInput),
  )
  assert_true(
    @moonopaque.generate_ke2_for_unknown_user(
      p256_cfg,
      r255_setup,
      None,
      None,
      b"u",
      p256_ke1,
      Bytes::make(32, b'\x56'),
    )
    is Err(@moonopaque.OpaqueError::InvalidInput),
  )
  let (_, p256_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      p256_cfg,
      p256_setup,
      None,
      None,
      p256_record,
      b"u",
      p256_ke1,
      Bytes::make(32, b'\x57'),
      Bytes::make(32, b'\x58'),
      Bytes::make(32, b'\x59'),
    ),
    "p256 ke2",
  )
  assert_eq(
    @moonopaque.generate_ke3(r255_cfg, p256_c_state, None, None, p256_ke2),
    Err(@moonopaque.OpaqueError::InvalidInput),
  )

  // KSF mismatch: register with Pbkdf2Sha256(16), login with Identity (both suites)
  for suite in sec_both_suites() {
    let reg_cfg = @moonopaque.Config::new(
      suite,
      b"ksf-check",
      @moonopaque.Ksf::Pbkdf2Sha256(16),
    )
    let login_cfg_id = @moonopaque.Config::new(
      suite,
      b"ksf-check",
      @moonopaque.Ksf::Identity,
    )
    let login_cfg_diff_iter = @moonopaque.Config::new(
      suite,
      b"ksf-check",
      @moonopaque.Ksf::Pbkdf2Sha256(32),
    )
    let setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x6a')),
      "ksf setup",
    )
    let (rec, _) = sec_register_user(
      reg_cfg,
      setup,
      b"stretched-secret",
      b"ksf-user",
      None,
      None,
      Bytes::make(32, b'\x6b'),
      Bytes::make(32, b'\x6c'),
    )
    for bad_login_cfg in [login_cfg_id, login_cfg_diff_iter] {
      let (cs, ke1) = sec_unwrap_ok(
        @moonopaque.generate_ke1_with_random(
          bad_login_cfg,
          b"stretched-secret",
          Bytes::make(32, b'\x6d'),
        ),
        "ksf ke1",
      )
      let (_, ke2) = sec_unwrap_ok(
        @moonopaque.generate_ke2(
          bad_login_cfg,
          setup,
          None,
          None,
          rec,
          b"ksf-user",
          ke1,
          Bytes::make(32, b'\x6e'),
          Bytes::make(32, b'\x6f'),
          Bytes::make(32, b'\x70'),
        ),
        "ksf ke2",
      )
      assert_eq(
        @moonopaque.generate_ke3(bad_login_cfg, cs, None, None, ke2),
        Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
      )
    }
  }
}

///|
test "security 23: password blinding unlinkability, export_key stability, and forward secrecy" {
  for suite in sec_both_suites() {
    let config = @moonopaque.Config::new(suite, b"sec-23", Identity)
    let server_setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x7a')),
      "from_seed",
    )
    let password = b"ZeroPlaintextPassword-2026!"
    let cred_id = b"unlinkable-user"

    // Two blinded registration requests for the exact same password with different blinds are unlinkable
    let (_, req1) = sec_unwrap_ok(
      @moonopaque.create_registration_request_with_random(
        config,
        password,
        Bytes::make(32, b'\x7b'),
      ),
      "req1",
    )
    let (_, req2) = sec_unwrap_ok(
      @moonopaque.create_registration_request_with_random(
        config,
        password,
        Bytes::make(32, b'\x7c'),
      ),
      "req2",
    )
    assert_true(req1.blinded_message() != req2.blinded_message())
    assert_true(req1.to_bytes() != password)
    assert_true(req2.to_bytes() != password)

    // Register honestly and record reg_export_key
    let (record, reg_export_key) = sec_register_user(
      config,
      server_setup,
      password,
      cred_id,
      Some(b"client"),
      Some(b"server"),
      Bytes::make(32, b'\x7d'),
      Bytes::make(32, b'\x7e'),
    )

    // Two independent logins with distinct randomness
    let (cs1, ke1_1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\x81'),
      ),
      "ke1_1",
    )
    let (cs2, ke1_2) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(
        config,
        password,
        Bytes::make(32, b'\x82'),
      ),
      "ke1_2",
    )
    // Blinded OPRF messages across logins are completely unlinkable
    assert_true(
      ke1_1.credential_request().blinded_message() !=
      ke1_2.credential_request().blinded_message(),
    )
    assert_true(
      ke1_1.client_public_keyshare() != ke1_2.client_public_keyshare(),
    )

    let (ss1, ke2_1) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        Some(b"server"),
        Some(b"client"),
        record,
        cred_id,
        ke1_1,
        Bytes::make(32, b'\x83'),
        Bytes::make(32, b'\x84'),
        Bytes::make(32, b'\x85'),
      ),
      "ke2_1",
    )
    let (ss2, ke2_2) = sec_unwrap_ok(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        Some(b"server"),
        Some(b"client"),
        record,
        cred_id,
        ke1_2,
        Bytes::make(32, b'\x86'),
        Bytes::make(32, b'\x87'),
        Bytes::make(32, b'\x88'),
      ),
      "ke2_2",
    )
    let res1 = sec_unwrap_ok(
      @moonopaque.generate_ke3(
        config,
        cs1,
        Some(b"client"),
        Some(b"server"),
        ke2_1,
      ),
      "res1",
    )
    let res2 = sec_unwrap_ok(
      @moonopaque.generate_ke3(
        config,
        cs2,
        Some(b"client"),
        Some(b"server"),
        ke2_2,
      ),
      "res2",
    )
    let sk1 = sec_unwrap_ok(
      @moonopaque.server_finish(ss1, res1.ke3()),
      "finish1",
    )
    let sk2 = sec_unwrap_ok(
      @moonopaque.server_finish(ss2, res2.ke3()),
      "finish2",
    )

    // export_key is deterministic across registration and all logins
    assert_eq(res1.export_key(), reg_export_key)
    assert_eq(res2.export_key(), reg_export_key)
    // session_key matches peer on each session, differs across sessions (forward secrecy),
    // and is domain-separated from export_key
    assert_eq(res1.session_key(), sk1)
    assert_eq(res2.session_key(), sk2)
    assert_true(sk1 != sk2)
    assert_true(sk1 != reg_export_key)
    assert_true(sk2 != reg_export_key)
  }
}

///|
test "security 24: invalid KSF params, empty explicit identity, and short randomness rejected" {
  for suite in sec_both_suites() {
    let short_rand = Bytes::make(31, b'\xaa')
    assert_eq(
      @moonopaque.ServerSetup::from_seed(suite, short_rand),
      Err(@moonopaque.OpaqueError::InvalidInput),
    )
    let cfg = @moonopaque.Config::new(suite, b"sec-24", Identity)
    assert_true(
      @moonopaque.create_registration_request_with_random(
        cfg, b"pw", short_rand,
      )
      is Err(@moonopaque.OpaqueError::InvalidInput),
    )
    assert_true(
      @moonopaque.generate_ke1_with_random(cfg, b"pw", short_rand)
      is Err(@moonopaque.OpaqueError::InvalidInput),
    )
    let setup = sec_unwrap_ok(
      @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x9a')),
      "setup",
    )
    let (reg_state, reg_req) = sec_unwrap_ok(
      @moonopaque.create_registration_request_with_random(
        cfg,
        b"pw",
        Bytes::make(32, b'\x9b'),
      ),
      "reg_req",
    )
    let reg_resp = sec_unwrap_ok(
      @moonopaque.create_registration_response(cfg, setup, reg_req, b"u"),
      "reg_resp",
    )
    // Empty explicit identity Some(b"") rejected
    assert_eq(
      @moonopaque.finalize_registration_request(
        cfg,
        reg_state,
        reg_resp,
        Some(b""),
        None,
        Bytes::make(32, b'\x9c'),
      ),
      Err(@moonopaque.OpaqueError::InvalidInput),
    )
    assert_eq(
      @moonopaque.finalize_registration_request(
        cfg,
        reg_state,
        reg_resp,
        None,
        Some(b""),
        Bytes::make(32, b'\x9c'),
      ),
      Err(@moonopaque.OpaqueError::InvalidInput),
    )
    // Invalid KSF parameters rejected
    let bad_ksfs : Array[@moonopaque.Ksf] = [
      @moonopaque.Ksf::Pbkdf2Sha256(0),
      @moonopaque.Ksf::Pbkdf2Sha512(-1),
      @moonopaque.Ksf::Argon2id(0, 32, 1),
      @moonopaque.Ksf::Argon2id(1, 4, 1),
    ]
    for bad_ksf in bad_ksfs {
      let bad_cfg = @moonopaque.Config::new(suite, b"sec-24", bad_ksf)
      assert_eq(
        @moonopaque.finalize_registration_request(
          bad_cfg,
          reg_state,
          reg_resp,
          None,
          None,
          Bytes::make(32, b'\x9d'),
        ),
        Err(@moonopaque.OpaqueError::InvalidInput),
      )
    }
    let (_, ke1) = sec_unwrap_ok(
      @moonopaque.generate_ke1_with_random(cfg, b"pw", Bytes::make(32, b'\x9e')),
      "ke1",
    )
    assert_true(
      @moonopaque.generate_ke2_for_unknown_user(
        cfg,
        setup,
        None,
        None,
        b"ghost",
        ke1,
        short_rand,
      )
      is Err(@moonopaque.OpaqueError::InvalidInput),
    )
  }
}

///|
test "security 25: Curve25519 low-order point injection rejected (KE1, KE2, RegistrationRecord, OPRF)" {
  let suite = @moonopaque.CipherSuite::Ristretto255Curve25519Sha512
  let config = @moonopaque.Config::ristretto255_curve25519_sha512(
    context=b"sec-25",
  )
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x1a')),
    "from_seed",
  )
  let cred_id = b"c25519-low-order-user"
  let password = b"CorrectHorseBatteryStaple"
  let (reg_state, reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      config,
      password,
      Bytes::make(32, b'\x1b'),
    ),
    "reg_req",
  )
  let reg_resp = sec_unwrap_ok(
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, cred_id,
    ),
    "reg_resp",
  )
  let (record, _) = sec_unwrap_ok(
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp,
      None,
      None,
      Bytes::make(32, b'\x1c'),
    ),
    "finalize",
  )
  let (client_state, ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x1d'),
    ),
    "ke1",
  )
  let (_, ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      ke1,
      Bytes::make(32, b'\x1e'),
      Bytes::make(32, b'\x1f'),
      Bytes::make(32, b'\x20'),
    ),
    "ke2",
  )

  let valid_reg_resp = reg_resp.to_bytes()
  let valid_record = record.to_bytes()
  let valid_ke1 = ke1.to_bytes()
  let valid_ke2 = ke2.to_bytes()

  // 1. All-zero X25519 points (u = 0 and u = 2^255 -> masked u = 0) rejected at wire decoding
  let zero_points : Array[Bytes] = [
    Bytes::make(32, b'\x00'),
    sec_hex("0000000000000000000000000000000000000000000000000000000000000080"),
  ]
  for z in zero_points {
    assert_eq(
      @moonopaque.KE1::from_bytes(suite, sec_replace_slice(valid_ke1, 64, z)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.KE2::from_bytes(suite, sec_replace_slice(valid_ke2, 224, z)),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationRecord::from_bytes(
        suite,
        sec_replace_slice(valid_record, 0, z),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
    assert_eq(
      @moonopaque.RegistrationResponse::from_bytes(
        suite,
        sec_replace_slice(valid_reg_resp, 32, z),
      ),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )
  }

  // 2. Non-zero RFC 7748 small-order Curve25519 points rejected during 3DH via x25519_checked
  let small_order_points : Array[Bytes] = [
    // u = 1 (order 4)
    sec_hex("0100000000000000000000000000000000000000000000000000000000000000"),
    // Order-8 low-order point
    sec_hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    // Order-8 low-order point
    sec_hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    // p - 1 (order 2)
    sec_hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    // p (reduces to 0)
    sec_hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    // p + 1 (reduces to 1)
    sec_hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
  ]
  for low in small_order_points {
    // Inject into KE1.client_public_keyshare -> generate_ke2 rejects with InvalidElement
    let bad_ke1 = sec_unwrap_ok(
      @moonopaque.KE1::from_bytes(suite, sec_replace_slice(valid_ke1, 64, low)),
      "KE1::from_bytes(small-order)",
    )
    assert_true(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        record,
        cred_id,
        bad_ke1,
        Bytes::make(32, b'\x21'),
        Bytes::make(32, b'\x22'),
        Bytes::make(32, b'\x23'),
      )
      is Err(@moonopaque.OpaqueError::InvalidElement),
    )

    // Inject into KE2.server_public_keyshare -> generate_ke3 rejects with InvalidElement
    let bad_ke2 = sec_unwrap_ok(
      @moonopaque.KE2::from_bytes(suite, sec_replace_slice(valid_ke2, 224, low)),
      "KE2::from_bytes(small-order)",
    )
    assert_eq(
      @moonopaque.generate_ke3(config, client_state, None, None, bad_ke2),
      Err(@moonopaque.OpaqueError::InvalidElement),
    )

    // Inject into RegistrationRecord.client_public_key -> generate_ke2 rejects with InvalidElement
    let bad_record = sec_unwrap_ok(
      @moonopaque.RegistrationRecord::from_bytes(
        suite,
        sec_replace_slice(valid_record, 0, low),
      ),
      "RegistrationRecord::from_bytes(small-order)",
    )
    assert_true(
      @moonopaque.generate_ke2(
        config,
        server_setup,
        None,
        None,
        bad_record,
        cred_id,
        ke1,
        Bytes::make(32, b'\x24'),
        Bytes::make(32, b'\x25'),
        Bytes::make(32, b'\x26'),
      )
      is Err(@moonopaque.OpaqueError::InvalidElement),
    )
  }

  // 3. OPRF element fields still enforce strict Ristretto255 canonical decoding
  let invalid_ristretto = sec_hex(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(
    @moonopaque.RegistrationRequest::from_bytes(suite, invalid_ristretto),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
  assert_eq(
    @moonopaque.CredentialRequest::from_bytes(suite, invalid_ristretto),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
  assert_eq(
    @moonopaque.RegistrationResponse::from_bytes(
      suite,
      sec_replace_slice(valid_reg_resp, 0, invalid_ristretto),
    ),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
  assert_eq(
    @moonopaque.KE1::from_bytes(
      suite,
      sec_replace_slice(valid_ke1, 0, invalid_ristretto),
    ),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
  assert_eq(
    @moonopaque.KE2::from_bytes(
      suite,
      sec_replace_slice(valid_ke2, 0, invalid_ristretto),
    ),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
}

///|
test "security 26: Curve25519 wrong password, fake KE2 anti-enumeration, KE2/KE3 tampering, and invalid scrypt params" {
  let suite = @moonopaque.CipherSuite::Ristretto255Curve25519Sha512
  let config = @moonopaque.Config::ristretto255_curve25519_sha512(
    context=b"sec-26",
  )
  let server_setup = sec_unwrap_ok(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x31')),
    "from_seed",
  )
  let server_id = Some(b"auth.example.com")
  let cred_id = b"c25519-user@example.com"
  let password = b"CorrectHorseBatteryStaple"
  let (record, reg_export_key) = sec_register_user(
    config,
    server_setup,
    password,
    cred_id,
    Some(cred_id),
    server_id,
    Bytes::make(32, b'\x32'),
    Bytes::make(32, b'\x33'),
  )

  // 1. Wrong password -> InvalidEnvelopeTag
  let (bad_pw_state, bad_pw_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"WrongHorseBatteryStaple",
      Bytes::make(32, b'\x34'),
    ),
    "bad_pw_ke1",
  )
  let (_, bad_pw_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_id,
      Some(cred_id),
      record,
      cred_id,
      bad_pw_ke1,
      Bytes::make(32, b'\x35'),
      Bytes::make(32, b'\x36'),
      Bytes::make(32, b'\x37'),
    ),
    "bad_pw_ke2",
  )
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      bad_pw_state,
      Some(cred_id),
      server_id,
      bad_pw_ke2,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )

  // 2. Honest login + anti-enumeration Fake KE2 (length 320 B matches real KE2)
  let (client_state, real_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x38'),
    ),
    "real_ke1",
  )
  let (server_state, real_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_id,
      Some(cred_id),
      record,
      cred_id,
      real_ke1,
      Bytes::make(32, b'\x39'),
      Bytes::make(32, b'\x3a'),
      Bytes::make(32, b'\x3b'),
    ),
    "real_ke2",
  )
  let ghost_id = b"ghost-c25519@example.com"
  let (ghost_state, ghost_ke1) = sec_unwrap_ok(
    @moonopaque.generate_ke1_with_random(
      config,
      b"guessed-password",
      Bytes::make(32, b'\x3c'),
    ),
    "ghost_ke1",
  )
  let (_, fake_ke2) = sec_unwrap_ok(
    @moonopaque.generate_ke2_for_unknown_user(
      config,
      server_setup,
      server_id,
      Some(ghost_id),
      ghost_id,
      ghost_ke1,
      Bytes::make(32, b'\x3d'),
    ),
    "fake_ke2",
  )
  assert_eq(real_ke2.to_bytes().length(), 320)
  assert_eq(fake_ke2.to_bytes().length(), 320)
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      ghost_state,
      Some(ghost_id),
      server_id,
      fake_ke2,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )

  // 3. 1-bit tampering of KE2 (server_mac, server_nonce, masked_response)
  let ke2_bytes = real_ke2.to_bytes()
  for off in [256, 287, 319, 192, 223] {
    let tampered_ke2 = sec_unwrap_ok(
      @moonopaque.KE2::from_bytes(suite, sec_flip_bit(ke2_bytes, off, 0x01U)),
      "KE2::from_bytes(tampered)",
    )
    assert_eq(
      @moonopaque.generate_ke3(
        config,
        client_state,
        Some(cred_id),
        server_id,
        tampered_ke2,
      ),
      Err(@moonopaque.OpaqueError::InvalidServerMac),
    )
  }
  let tampered_mask_ke2 = sec_unwrap_ok(
    @moonopaque.KE2::from_bytes(suite, sec_flip_bit(ke2_bytes, 100, 0x01U)),
    "KE2::from_bytes(tampered mask)",
  )
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      client_state,
      Some(cred_id),
      server_id,
      tampered_mask_ke2,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )

  // 4. Honest KE3 succeeds; 1-bit tampering of KE3 rejected with InvalidClientMac
  let login_res = sec_unwrap_ok(
    @moonopaque.generate_ke3(
      config,
      client_state,
      Some(cred_id),
      server_id,
      real_ke2,
    ),
    "generate_ke3",
  )
  assert_eq(login_res.export_key(), reg_export_key)
  let ke3_bytes = login_res.ke3().to_bytes()
  assert_eq(ke3_bytes.length(), 64)
  for off in [0, 31, 63] {
    let bad_ke3 = sec_unwrap_ok(
      @moonopaque.KE3::from_bytes(suite, sec_flip_bit(ke3_bytes, off, 0x01U)),
      "KE3::from_bytes(tampered)",
    )
    assert_eq(
      @moonopaque.server_finish(server_state, bad_ke3),
      Err(@moonopaque.OpaqueError::InvalidClientMac),
    )
  }
  let server_sk = sec_unwrap_ok(
    @moonopaque.server_finish(server_state, login_res.ke3()),
    "server_finish",
  )
  assert_eq(server_sk, login_res.session_key())

  // 5. Invalid Ksf::Scrypt parameters rejected with InvalidInput
  let (reg_state, reg_req) = sec_unwrap_ok(
    @moonopaque.create_registration_request_with_random(
      config,
      password,
      Bytes::make(32, b'\x41'),
    ),
    "scrypt reg_req",
  )
  let reg_resp = sec_unwrap_ok(
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, b"scrypt-bad-user",
    ),
    "scrypt reg_resp",
  )
  let bad_scrypt_ksfs : Array[@moonopaque.Ksf] = [
    @moonopaque.Ksf::Scrypt(0, 1, 1),
    @moonopaque.Ksf::Scrypt(1, 1, 1),
    @moonopaque.Ksf::Scrypt(3, 1, 1),
    @moonopaque.Ksf::Scrypt(-16, 1, 1),
    @moonopaque.Ksf::Scrypt(16, 0, 1),
    @moonopaque.Ksf::Scrypt(16, -1, 1),
    @moonopaque.Ksf::Scrypt(16, 1, 0),
    @moonopaque.Ksf::Scrypt(16, 1, -2),
    @moonopaque.Ksf::Scrypt(1073741824, 8, 1),
  ]
  for bad_ksf in bad_scrypt_ksfs {
    let bad_cfg = @moonopaque.Config::new(suite, b"sec-26-scrypt", bad_ksf)
    assert_eq(
      @moonopaque.finalize_registration_request(
        bad_cfg,
        reg_state,
        reg_resp,
        None,
        None,
        Bytes::make(32, b'\x42'),
      ),
      Err(@moonopaque.OpaqueError::InvalidInput),
    )
  }
}
