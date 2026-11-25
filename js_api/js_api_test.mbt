///|
fn split_ok(resp : String) -> Array[String] {
  match resp.strip_prefix("OK:") {
    Some(body) => body.split("|").map(fn(v) { v.to_owned() }).collect()
    None => abort("expected OK: response, got: " + resp)
  }
}

///|
fn seed_hex(label : Bytes) -> String {
  @hash.hex_encode(@hash.sha256(label))
}

///|
fn flip_last_hex_bit(hex : String) -> String {
  let bytes = @hash.hex_decode(hex).unwrap()
  let n = bytes.length()
  let mutated = Bytes::makei(n, fn(i) {
    if i == n - 1 {
      (bytes[i].to_uint() ^ 0x01U).to_byte()
    } else {
      bytes[i]
    }
  })
  @hash.hex_encode(mutated)
}

///|
fn run_full_suite_flow(suite : String, tag : Bytes) -> Unit raise {
  let context = "moonopaque-js-api-test-v1"
  let cred_id = "alice@example.com"
  let client_id = "alice@example.com"
  let server_id = "auth.moonopaque.dev"
  let password = "correct-horse-battery-staple"

  // 1. Server setup
  let setup_parts = split_ok(
    @js_api.server_setup_from_seed(
      suite,
      seed_hex(@hash.concat_bytes([tag, b":setup"])),
    ),
  )
  assert_eq(setup_parts.length(), 3)
  let oprf_seed = setup_parts[0]
  let sk = setup_parts[1]
  let pk = setup_parts[2]

  // 2. Registration
  let reg_start = split_ok(
    @js_api.client_register_start(
      suite,
      password,
      seed_hex(@hash.concat_bytes([tag, b":reg-rand"])),
    ),
  )
  assert_eq(reg_start.length(), 2)
  let reg_handle = reg_start[0]
  let reg_req = reg_start[1]

  let reg_resp_parts = split_ok(
    @js_api.server_register_response(suite, oprf_seed, sk, pk, reg_req, cred_id),
  )
  assert_eq(reg_resp_parts.length(), 1)
  let reg_resp = reg_resp_parts[0]

  let reg_fin = split_ok(
    @js_api.client_register_finish(
      suite,
      reg_handle,
      reg_resp,
      client_id,
      server_id,
      seed_hex(@hash.concat_bytes([tag, b":env-nonce"])),
    ),
  )
  assert_eq(reg_fin.length(), 2)
  let record_hex = reg_fin[0]
  let reg_export_key = reg_fin[1]

  // Consumed registration handle cannot be reused
  assert_eq(
    @js_api.client_register_finish(
      suite,
      reg_handle,
      reg_resp,
      client_id,
      server_id,
      seed_hex(@hash.concat_bytes([tag, b":env-nonce"])),
    ),
    "ERR:InvalidHandle",
  )

  // 3. Honest 3DH Login
  let login_c = split_ok(
    @js_api.client_login_start(
      suite,
      context,
      password,
      seed_hex(@hash.concat_bytes([tag, b":ke1-rand"])),
    ),
  )
  assert_eq(login_c.length(), 2)
  let c_handle = login_c[0]
  let ke1_hex = login_c[1]

  let login_s = split_ok(
    @js_api.server_login_start(
      suite,
      context,
      oprf_seed,
      sk,
      pk,
      record_hex,
      cred_id,
      client_id,
      server_id,
      ke1_hex,
      seed_hex(@hash.concat_bytes([tag, b":mask-nonce"])),
      seed_hex(@hash.concat_bytes([tag, b":srv-nonce"])),
      seed_hex(@hash.concat_bytes([tag, b":srv-ks"])),
    ),
  )
  assert_eq(login_s.length(), 2)
  let s_handle = login_s[0]
  let ke2_hex = login_s[1]

  let ke3_res = split_ok(
    @js_api.client_login_finish(
      suite, context, c_handle, client_id, server_id, ke2_hex,
    ),
  )
  assert_eq(ke3_res.length(), 3)
  let ke3_hex = ke3_res[0]
  let client_session_key = ke3_res[1]
  let login_export_key = ke3_res[2]

  let srv_fin = split_ok(@js_api.server_login_finish(s_handle, ke3_hex))
  assert_eq(srv_fin.length(), 1)
  let server_session_key = srv_fin[0]

  assert_eq(client_session_key, server_session_key)
  assert_eq(login_export_key, reg_export_key)

  // Consumed login handles cannot be reused
  assert_eq(
    @js_api.client_login_finish(
      suite, context, c_handle, client_id, server_id, ke2_hex,
    ),
    "ERR:InvalidHandle",
  )
  assert_eq(@js_api.server_login_finish(s_handle, ke3_hex), "ERR:InvalidHandle")

  // 4. Unknown user Anti-Enumeration Fake KE2
  let ghost_c = split_ok(
    @js_api.client_login_start(
      suite,
      context,
      "any-password",
      seed_hex(@hash.concat_bytes([tag, b":ghost-ke1"])),
    ),
  )
  let ghost_s = split_ok(
    @js_api.server_login_fake(
      suite,
      context,
      oprf_seed,
      sk,
      pk,
      "ghost@example.com",
      "ghost@example.com",
      server_id,
      ghost_c[1],
      seed_hex(@hash.concat_bytes([tag, b":ghost-fake"])),
    ),
  )
  assert_eq(ghost_s[1].length(), ke2_hex.length())
  assert_eq(
    @js_api.client_login_finish(
      suite,
      context,
      ghost_c[0],
      "ghost@example.com",
      server_id,
      ghost_s[1],
    ),
    "ERR:InvalidEnvelopeTag",
  )
  assert_eq(
    @js_api.server_login_finish(ghost_s[0], ke3_hex),
    "ERR:InvalidClientMac",
  )

  // 5. Wrong password rejection
  let bad_c = split_ok(
    @js_api.client_login_start(
      suite,
      context,
      "wrong-password-123",
      seed_hex(@hash.concat_bytes([tag, b":bad-pw-ke1"])),
    ),
  )
  let bad_s = split_ok(
    @js_api.server_login_start(
      suite,
      context,
      oprf_seed,
      sk,
      pk,
      record_hex,
      cred_id,
      client_id,
      server_id,
      bad_c[1],
      seed_hex(@hash.concat_bytes([tag, b":bad-mask"])),
      seed_hex(@hash.concat_bytes([tag, b":bad-snonce"])),
      seed_hex(@hash.concat_bytes([tag, b":bad-sks"])),
    ),
  )
  assert_eq(
    @js_api.client_login_finish(
      suite,
      context,
      bad_c[0],
      client_id,
      server_id,
      bad_s[1],
    ),
    "ERR:InvalidEnvelopeTag",
  )
  assert_eq(
    @js_api.server_login_finish(bad_s[0], ke3_hex),
    "ERR:InvalidClientMac",
  )

  // 6. MITM tampered KE2 server_mac rejection
  let mitm2_c = split_ok(
    @js_api.client_login_start(
      suite,
      context,
      password,
      seed_hex(@hash.concat_bytes([tag, b":mitm2-ke1"])),
    ),
  )
  let mitm2_s = split_ok(
    @js_api.server_login_start(
      suite,
      context,
      oprf_seed,
      sk,
      pk,
      record_hex,
      cred_id,
      client_id,
      server_id,
      mitm2_c[1],
      seed_hex(@hash.concat_bytes([tag, b":mitm2-mask"])),
      seed_hex(@hash.concat_bytes([tag, b":mitm2-snonce"])),
      seed_hex(@hash.concat_bytes([tag, b":mitm2-sks"])),
    ),
  )
  assert_eq(
    @js_api.client_login_finish(
      suite,
      context,
      mitm2_c[0],
      client_id,
      server_id,
      flip_last_hex_bit(mitm2_s[1]),
    ),
    "ERR:InvalidServerMac",
  )
  assert_eq(
    @js_api.server_login_finish(mitm2_s[0], ke3_hex),
    "ERR:InvalidClientMac",
  )

  // 7. MITM tampered KE3 client_mac rejection
  let mitm3_c = split_ok(
    @js_api.client_login_start(
      suite,
      context,
      password,
      seed_hex(@hash.concat_bytes([tag, b":mitm3-ke1"])),
    ),
  )
  let mitm3_s = split_ok(
    @js_api.server_login_start(
      suite,
      context,
      oprf_seed,
      sk,
      pk,
      record_hex,
      cred_id,
      client_id,
      server_id,
      mitm3_c[1],
      seed_hex(@hash.concat_bytes([tag, b":mitm3-mask"])),
      seed_hex(@hash.concat_bytes([tag, b":mitm3-snonce"])),
      seed_hex(@hash.concat_bytes([tag, b":mitm3-sks"])),
    ),
  )
  let mitm3_ke3 = split_ok(
    @js_api.client_login_finish(
      suite,
      context,
      mitm3_c[0],
      client_id,
      server_id,
      mitm3_s[1],
    ),
  )
  assert_eq(
    @js_api.server_login_finish(mitm3_s[0], flip_last_hex_bit(mitm3_ke3[0])),
    "ERR:InvalidClientMac",
  )
}

///|
test "js_api: ristretto255 full protocol & security scenarios" {
  run_full_suite_flow("ristretto255", b"js-api-ristretto255")
}

///|
test "js_api: curve25519 full protocol & security scenarios" {
  run_full_suite_flow("curve25519", b"js-api-curve25519")
}

///|
test "js_api: p256 full protocol & security scenarios" {
  run_full_suite_flow("p256", b"js-api-p256")
}

///|
test "js_api: invalid inputs and unknown suite error handling" {
  assert_eq(
    @js_api.server_setup_from_seed("unknown-suite", seed_hex(b"seed")),
    "ERR:UnknownSuite",
  )
  assert_eq(
    @js_api.server_setup_from_seed("p256", "not-valid-hex"),
    "ERR:InvalidHex:seed",
  )
  assert_eq(@js_api.server_login_finish("999999", "00"), "ERR:InvalidHandle")
  assert_eq(@js_api.server_login_finish("abc", "00"), "ERR:InvalidHandle")
}
