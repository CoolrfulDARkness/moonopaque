///|
/// Pure-MoonBit RFC 9807 OPAQUE-3DH Interactive Security Showcase CLI.
///
/// Demonstrates all three RFC 9807 standard ciphersuites
/// (`OPAQUE-Ristretto255-SHA512`, `OPAQUE-Ristretto255-Curve25519-SHA512`, and
/// `OPAQUE-P256-SHA256`) across six end-to-end security scenarios — including
/// pluggable PBKDF2, Argon2id (RFC 9106), and scrypt (RFC 7914) key stretching
/// — with zero external dependencies, zero FFI, and identical behavior on
/// wasm-gc, js, and native targets.
///
/// NOTE: Demo entropy is derived deterministically via SHA-256 labels so the
/// CLI runs reproducibly without OS RNG hooks. Production deployments MUST
/// pass fresh CSPRNG bytes for every registration, login, and server setup.

///|
fn demo_entropy(label : Bytes) -> Bytes {
  @hash.sha256(label)
}

///|
fn slice_bytes(data : Bytes, start : Int32, len : Int32) -> Bytes {
  Bytes::makei(len, i => data[start + i])
}

///|
fn hex_preview(data : Bytes) -> String {
  let n = data.length()
  if n <= 16 {
    @hash.hex_encode(data) + " (" + n.to_string() + " B)"
  } else {
    let head = @hash.hex_encode(slice_bytes(data, 0, 8))
    let tail = @hash.hex_encode(slice_bytes(data, n - 4, 4))
    head + "..." + tail + " (" + n.to_string() + " B)"
  }
}

///|
fn flip_last_bit(data : Bytes) -> Bytes {
  let n = data.length()
  Bytes::makei(n, i => {
    if i == n - 1 {
      (data[i].to_uint() ^ 0x01U).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn[T] must_ok(res : Result[T, @opaque.OpaqueError], step : String) -> T {
  match res {
    Ok(v) => v
    Err(e) => abort("[FAIL] " + step + " failed: " + Show::to_string(e))
  }
}

///|
fn expect_err(
  res : Result[Unit, @opaque.OpaqueError],
  expected : @opaque.OpaqueError,
  step : String,
) -> Unit {
  match res {
    Err(actual) =>
      if actual != expected {
        abort(
          "[FAIL] " +
          step +
          ": expected " +
          Show::to_string(expected) +
          ", got " +
          Show::to_string(actual),
        )
      }
    Ok(_) =>
      abort(
        "[FAIL] " +
        step +
        ": expected " +
        Show::to_string(expected) +
        ", but succeeded",
      )
  }
}

///|
fn run_suite_showcase(
  suite : @opaque.CipherSuite,
  suite_name : String,
  tag : Bytes,
) -> Unit {
  let config = @opaque.Config::new(
    suite,
    b"moonopaque-cli-demo-v1",
    @opaque.Ksf::Identity,
  )
  let server_setup = must_ok(
    @opaque.ServerSetup::from_seed(
      suite,
      demo_entropy(@hash.concat_bytes([tag, b":server-setup"])),
    ),
    "ServerSetup::from_seed",
  )

  let server_id : Bytes? = Some(b"auth.moonopaque.dev")
  let client_id : Bytes? = Some(b"alice@example.com")
  let cred_id = b"alice@example.com"
  let password = b"correct-horse-battery-staple"
  let wrong_password = b"wrong-password-12345"

  println("")
  println(
    "====================================================================",
  )
  println("  CIPHERSUITE: " + suite_name)
  println(
    "====================================================================",
  )
  println(
    "  Server Public Key : " + hex_preview(server_setup.server_public_key()),
  )
  println("  Protocol Context  : \"moonopaque-cli-demo-v1\"")

  // ------------------------------------------------------------------
  // Scenario 1: Zero-Knowledge Registration (RFC 9807 Section 5)
  // ------------------------------------------------------------------
  println("")
  println("  [1/5] Zero-Knowledge Registration (RFC 9807 Section 5)")
  let (reg_state, reg_req) = must_ok(
    @opaque.create_registration_request_with_random(
      config,
      password,
      demo_entropy(@hash.concat_bytes([tag, b":reg-blind"])),
    ),
    "create_registration_request_with_random",
  )
  let reg_req_wire = reg_req.to_bytes()
  let reg_req_rx = must_ok(
    @opaque.RegistrationRequest::from_bytes(suite, reg_req_wire),
    "RegistrationRequest::from_bytes",
  )
  let reg_resp = must_ok(
    @opaque.create_registration_response(
      config, server_setup, reg_req_rx, cred_id,
    ),
    "create_registration_response",
  )
  let reg_resp_wire = reg_resp.to_bytes()
  let reg_resp_rx = must_ok(
    @opaque.RegistrationResponse::from_bytes(suite, reg_resp_wire),
    "RegistrationResponse::from_bytes",
  )
  let (record, reg_export_key) = must_ok(
    @opaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp_rx,
      client_id,
      server_id,
      demo_entropy(@hash.concat_bytes([tag, b":envelope-nonce"])),
    ),
    "finalize_registration_request",
  )
  let record_wire = record.to_bytes()
  let stored_record = must_ok(
    @opaque.RegistrationRecord::from_bytes(suite, record_wire),
    "RegistrationRecord::from_bytes",
  )

  println(
    "        Plaintext password NEVER leaves client (blinded OPRF element only).",
  )
  println("        C -> S RegistrationRequest : " + hex_preview(reg_req_wire))
  println("        S -> C RegistrationResponse: " + hex_preview(reg_resp_wire))
  println(
    "        C -> S RegistrationRecord  : " +
    hex_preview(record_wire) +
    " [sealed envelope]",
  )
  println("        Client Export Key (reg)    : " + hex_preview(reg_export_key))
  println("        Result: PASS (server stores zero password material)")

  // ------------------------------------------------------------------
  // Scenario 2: Mutual-Auth 3DH Login (RFC 9807 Section 6)
  // ------------------------------------------------------------------
  println("")
  println("  [2/5] Mutual-Auth 3DH Login (KE1 -> KE2 -> KE3 -> ServerFinish)")
  let (login_client_state, ke1) = must_ok(
    @opaque.generate_ke1_with_random(
      config,
      password,
      demo_entropy(@hash.concat_bytes([tag, b":ke1-rand"])),
    ),
    "generate_ke1_with_random",
  )
  let ke1_wire = ke1.to_bytes()
  let ke1_rx = must_ok(
    @opaque.KE1::from_bytes(suite, ke1_wire),
    "KE1::from_bytes",
  )

  let (login_server_state, ke2) = must_ok(
    @opaque.generate_ke2(
      config,
      server_setup,
      server_id,
      client_id,
      stored_record,
      cred_id,
      ke1_rx,
      demo_entropy(@hash.concat_bytes([tag, b":masking-nonce"])),
      demo_entropy(@hash.concat_bytes([tag, b":server-nonce"])),
      demo_entropy(@hash.concat_bytes([tag, b":server-keyshare"])),
    ),
    "generate_ke2",
  )
  let ke2_wire = ke2.to_bytes()
  let ke2_rx = must_ok(
    @opaque.KE2::from_bytes(suite, ke2_wire),
    "KE2::from_bytes",
  )

  let login_result = must_ok(
    @opaque.generate_ke3(
      config, login_client_state, client_id, server_id, ke2_rx,
    ),
    "generate_ke3",
  )
  let ke3_wire = login_result.ke3().to_bytes()
  let ke3_rx = must_ok(
    @opaque.KE3::from_bytes(suite, ke3_wire),
    "KE3::from_bytes",
  )

  let server_session_key = must_ok(
    @opaque.server_finish(login_server_state, ke3_rx),
    "server_finish",
  )

  if !@hash.ct_equal(login_result.session_key(), server_session_key) {
    abort("[FAIL] client and server session keys do not match")
  }
  if !@hash.ct_equal(login_result.export_key(), reg_export_key) {
    abort("[FAIL] login export_key does not match registration export_key")
  }

  println("        C -> S KE1                 : " + hex_preview(ke1_wire))
  println("        S -> C KE2                 : " + hex_preview(ke2_wire))
  println("        C -> S KE3                 : " + hex_preview(ke3_wire))
  println(
    "        Client Session Key         : " +
    hex_preview(login_result.session_key()),
  )
  println(
    "        Server Session Key         : " + hex_preview(server_session_key),
  )
  println(
    "        Recovered Export Key       : " +
    hex_preview(login_result.export_key()),
  )
  println("        Result: PASS (session_key & export_key match byte-for-byte)")

  // ------------------------------------------------------------------
  // Scenario 3: Anti-Enumeration Fake KE2 for Unknown User
  // ------------------------------------------------------------------
  println("")
  println("  [3/5] Anti-Enumeration Fake KE2 (Unknown User: ghost@example.com)")
  let ghost_id : Bytes? = Some(b"ghost@example.com")
  let (ghost_state, ghost_ke1) = must_ok(
    @opaque.generate_ke1_with_random(
      config,
      b"any-guess-password",
      demo_entropy(@hash.concat_bytes([tag, b":ghost-ke1"])),
    ),
    "generate_ke1_with_random(ghost)",
  )
  let (_, fake_ke2) = must_ok(
    @opaque.generate_ke2_for_unknown_user(
      config,
      server_setup,
      server_id,
      ghost_id,
      b"ghost@example.com",
      ghost_ke1,
      demo_entropy(@hash.concat_bytes([tag, b":ghost-fake-ke2"])),
    ),
    "generate_ke2_for_unknown_user",
  )
  let fake_ke2_wire = fake_ke2.to_bytes()
  if fake_ke2_wire.length() != ke2_wire.length() {
    abort("[FAIL] fake KE2 length differs from real KE2 length")
  }
  let ghost_res = match
    @opaque.generate_ke3(config, ghost_state, ghost_id, server_id, fake_ke2) {
    Ok(_) => Ok(())
    Err(e) => Err(e)
  }
  expect_err(
    ghost_res,
    @opaque.OpaqueError::InvalidEnvelopeTag,
    "unknown user fake KE2",
  )

  println(
    "        Real KE2 wire length       : " +
    ke2_wire.length().to_string() +
    " bytes",
  )
  println(
    "        Fake KE2 wire length       : " +
    fake_ke2_wire.length().to_string() +
    " bytes (IDENTICAL)",
  )
  println("        Fake KE2 preview           : " + hex_preview(fake_ke2_wire))
  println(
    "        Client verification        : Rejected with InvalidEnvelopeTag",
  )
  println(
    "        Result: PASS (attacker cannot enumerate registered accounts)",
  )

  // ------------------------------------------------------------------
  // Scenario 4: Wrong Password Rejection (Constant-Time Envelope MAC)
  // ------------------------------------------------------------------
  println("")
  println("  [4/5] Wrong Password Rejection (Constant-Time Envelope Auth Tag)")
  let (bad_state, bad_ke1) = must_ok(
    @opaque.generate_ke1_with_random(
      config,
      wrong_password,
      demo_entropy(@hash.concat_bytes([tag, b":bad-pw-ke1"])),
    ),
    "generate_ke1_with_random(wrong password)",
  )
  let (_, bad_ke2) = must_ok(
    @opaque.generate_ke2(
      config,
      server_setup,
      server_id,
      client_id,
      stored_record,
      cred_id,
      bad_ke1,
      demo_entropy(@hash.concat_bytes([tag, b":bad-pw-mask"])),
      demo_entropy(@hash.concat_bytes([tag, b":bad-pw-snonce"])),
      demo_entropy(@hash.concat_bytes([tag, b":bad-pw-sks"])),
    ),
    "generate_ke2(wrong password)",
  )
  let bad_pw_res = match
    @opaque.generate_ke3(config, bad_state, client_id, server_id, bad_ke2) {
    Ok(_) => Ok(())
    Err(e) => Err(e)
  }
  expect_err(
    bad_pw_res,
    @opaque.OpaqueError::InvalidEnvelopeTag,
    "wrong password",
  )
  println(
    "        Attempted password         : \"wrong-password-12345\" (for alice@example.com)",
  )
  println(
    "        Envelope verification      : Rejected with InvalidEnvelopeTag",
  )
  println(
    "        Result: PASS (constant-time tag check blocks invalid password)",
  )

  // ------------------------------------------------------------------
  // Scenario 5: Active MITM / MAC Tampering Rejection (1-bit Flip)
  // ------------------------------------------------------------------
  println("")
  println("  [5/5] Active MITM / MAC Tampering Rejection (1-Bit Flip)")
  let (mitm_c_state, mitm_ke1) = must_ok(
    @opaque.generate_ke1_with_random(
      config,
      password,
      demo_entropy(@hash.concat_bytes([tag, b":mitm-ke1"])),
    ),
    "generate_ke1_with_random(mitm)",
  )
  let (mitm_s_state, mitm_ke2) = must_ok(
    @opaque.generate_ke2(
      config,
      server_setup,
      server_id,
      client_id,
      stored_record,
      cred_id,
      mitm_ke1,
      demo_entropy(@hash.concat_bytes([tag, b":mitm-mask"])),
      demo_entropy(@hash.concat_bytes([tag, b":mitm-snonce"])),
      demo_entropy(@hash.concat_bytes([tag, b":mitm-sks"])),
    ),
    "generate_ke2(mitm)",
  )

  // 5a. Flip 1 bit in KE2 server_mac -> client rejects with InvalidServerMac
  let tampered_ke2 = must_ok(
    @opaque.KE2::from_bytes(suite, flip_last_bit(mitm_ke2.to_bytes())),
    "KE2::from_bytes(tampered)",
  )
  let mitm_ke2_res = match
    @opaque.generate_ke3(
      config, mitm_c_state, client_id, server_id, tampered_ke2,
    ) {
    Ok(_) => Ok(())
    Err(e) => Err(e)
  }
  expect_err(
    mitm_ke2_res,
    @opaque.OpaqueError::InvalidServerMac,
    "tampered KE2 server_mac",
  )

  // 5b. Client produces valid KE3, attacker flips 1 bit -> server rejects with InvalidClientMac
  let honest_login = must_ok(
    @opaque.generate_ke3(config, mitm_c_state, client_id, server_id, mitm_ke2),
    "generate_ke3(honest before KE3 tamper)",
  )
  let tampered_ke3 = must_ok(
    @opaque.KE3::from_bytes(suite, flip_last_bit(honest_login.ke3().to_bytes())),
    "KE3::from_bytes(tampered)",
  )
  let mitm_ke3_res = match @opaque.server_finish(mitm_s_state, tampered_ke3) {
    Ok(_) => Ok(())
    Err(e) => Err(e)
  }
  expect_err(
    mitm_ke3_res,
    @opaque.OpaqueError::InvalidClientMac,
    "tampered KE3 client_mac",
  )

  println(
    "        KE2 1-bit flip (server_mac): Rejected by client with InvalidServerMac",
  )
  println(
    "        KE3 1-bit flip (client_mac): Rejected by server with InvalidClientMac",
  )
  println("        Result: PASS (mutual transcript authentication stops MITM)")
}

///|
fn run_ksf_case(label : String, config : @opaque.Config, tag : Bytes) -> Unit {
  let suite = config.suite()
  let setup = must_ok(
    @opaque.ServerSetup::from_seed(
      suite,
      demo_entropy(@hash.concat_bytes([tag, b":setup"])),
    ),
    "ServerSetup::from_seed(" + label + ")",
  )
  let password = b"hardened-passphrase-2026"
  let cred_id = b"bob@example.com"
  let server_id : Bytes? = Some(b"vault.moonopaque.dev")
  let client_id : Bytes? = Some(b"bob@example.com")

  // Registration
  let (r_state, r_req) = must_ok(
    @opaque.create_registration_request_with_random(
      config,
      password,
      demo_entropy(@hash.concat_bytes([tag, b":reg"])),
    ),
    "ksf reg_req",
  )
  let r_resp = must_ok(
    @opaque.create_registration_response(config, setup, r_req, cred_id),
    "ksf reg_resp",
  )
  let (record, reg_ek) = must_ok(
    @opaque.finalize_registration_request(
      config,
      r_state,
      r_resp,
      client_id,
      server_id,
      demo_entropy(@hash.concat_bytes([tag, b":env"])),
    ),
    "ksf finalize_reg",
  )

  // Login
  let (c_state, ke1) = must_ok(
    @opaque.generate_ke1_with_random(
      config,
      password,
      demo_entropy(@hash.concat_bytes([tag, b":ke1"])),
    ),
    "ksf ke1",
  )
  let (s_state, ke2) = must_ok(
    @opaque.generate_ke2(
      config,
      setup,
      server_id,
      client_id,
      record,
      cred_id,
      ke1,
      demo_entropy(@hash.concat_bytes([tag, b":mask"])),
      demo_entropy(@hash.concat_bytes([tag, b":snonce"])),
      demo_entropy(@hash.concat_bytes([tag, b":sks"])),
    ),
    "ksf ke2",
  )
  let login = must_ok(
    @opaque.generate_ke3(config, c_state, client_id, server_id, ke2),
    "ksf ke3",
  )
  let server_sk = must_ok(
    @opaque.server_finish(s_state, login.ke3()),
    "ksf finish",
  )

  if !@hash.ct_equal(login.session_key(), server_sk) {
    abort("[FAIL] KSF session_key mismatch for " + label)
  }
  if !@hash.ct_equal(login.export_key(), reg_ek) {
    abort("[FAIL] KSF export_key mismatch for " + label)
  }

  println("  -> " + label)
  println("     Session Key (matched) : " + hex_preview(server_sk))
  println("     Export Key  (matched) : " + hex_preview(login.export_key()))
  println("     Result: PASS")
}

///|
fn main {
  println(
    "+------------------------------------------------------------------+",
  )
  println(
    "|  moonopaque :: Pure MoonBit RFC 9807 OPAQUE-3DH Security Demo    |",
  )
  println(
    "|  Zero-FFI | Sans-I/O | Constant-Time MACs | Wasm / JS / Native   |",
  )
  println(
    "+------------------------------------------------------------------+",
  )

  run_suite_showcase(
    @opaque.CipherSuite::Ristretto255Sha512,
    "OPAQUE-Ristretto255-SHA512 (RFC 9807 + RFC 9496)",
    b"suite-ristretto255",
  )

  run_suite_showcase(
    @opaque.CipherSuite::Ristretto255Curve25519Sha512,
    "OPAQUE-Ristretto255-Curve25519-SHA512 (RFC 9807 + RFC 7748 X25519)",
    b"suite-curve25519",
  )

  run_suite_showcase(
    @opaque.CipherSuite::P256Sha256,
    "OPAQUE-P256-SHA256 (RFC 9807 + NIST P-256)",
    b"suite-p256",
  )

  println("")
  println(
    "====================================================================",
  )
  println("  [6/6] Pluggable Key Stretching (KSF: PBKDF2, Argon2id & scrypt)")
  println(
    "====================================================================",
  )
  run_ksf_case(
    "OPAQUE-Ristretto255-Curve25519-SHA512 + PBKDF2-HMAC-SHA256 (iterations=1000)",
    @opaque.Config::ristretto255_curve25519_sha512(
      context=b"moonopaque-ksf-demo",
      ksf=@opaque.Ksf::Pbkdf2Sha256(1000),
    ),
    b"ksf-pbkdf2",
  )
  run_ksf_case(
    "OPAQUE-Ristretto255-SHA512 + Argon2id (RFC 9106, t=2, m=64 KiB, p=1)",
    @opaque.Config::ristretto255_sha512(
      context=b"moonopaque-ksf-demo",
      ksf=@opaque.Ksf::Argon2id(2, 64, 1),
    ),
    b"ksf-argon2id",
  )
  run_ksf_case(
    "OPAQUE-P256-SHA256 + scrypt (RFC 7914, N=1024, r=8, p=1)",
    @opaque.Config::p256_sha256(
      context=b"moonopaque-ksf-demo",
      ksf=@opaque.Ksf::Scrypt(1024, 8, 1),
    ),
    b"ksf-scrypt",
  )

  println("")
  println(
    "====================================================================",
  )
  println("  ALL 6 SECURITY SCENARIOS PASSED ACROSS ALL 3 RFC 9807 SUITES!")
  println(
    "====================================================================",
  )
}
