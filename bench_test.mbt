///|
fn[T] bench_unwrap(
  res : Result[T, @moonopaque.OpaqueError],
  label : String,
) -> T {
  match res {
    Ok(v) => v
    Err(e) => abort(label + " failed: " + Show::to_string(e))
  }
}

///|
fn bench_fixture(
  suite : @moonopaque.CipherSuite,
) -> (
  @moonopaque.Config,
  @moonopaque.ServerSetup,
  @moonopaque.RegistrationRecord,
  @moonopaque.KE1,
) {
  let config = @moonopaque.Config::new(suite, b"moonopaque-bench", Identity)
  let server_setup = bench_unwrap(
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x11')),
    "ServerSetup::from_seed",
  )
  let (reg_state, reg_req) = bench_unwrap(
    @moonopaque.create_registration_request_with_random(
      config,
      b"CorrectHorseBatteryStaple",
      Bytes::make(32, b'\x22'),
    ),
    "create_registration_request_with_random",
  )
  let reg_resp = bench_unwrap(
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, b"alice@example.com",
    ),
    "create_registration_response",
  )
  let (record, _) = bench_unwrap(
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp,
      Some(b"alice@example.com"),
      Some(b"auth.example.com"),
      Bytes::make(32, b'\x33'),
    ),
    "finalize_registration_request",
  )
  let (_, ke1) = bench_unwrap(
    @moonopaque.generate_ke1_with_random(
      config,
      b"CorrectHorseBatteryStaple",
      Bytes::make(32, b'\x44'),
    ),
    "generate_ke1_with_random",
  )
  (config, server_setup, record, ke1)
}

///|
test "opaque_ristretto255_oprf_roundtrip" (b : @bench.T) {
  let (config, server_setup, _, _) = bench_fixture(
    @moonopaque.CipherSuite::Ristretto255Sha512,
  )
  let password = b"CorrectHorseBatteryStaple"
  let cred_id = b"alice@example.com"
  let rand = Bytes::make(32, b'\x22')
  b.bench(() => {
    let (_, req) = bench_unwrap(
      @moonopaque.create_registration_request_with_random(
        config, password, rand,
      ),
      "oprf blind",
    )
    let resp = bench_unwrap(
      @moonopaque.create_registration_response(
        config, server_setup, req, cred_id,
      ),
      "oprf evaluate",
    )
    b.keep(resp)
  })
}

///|
test "opaque_p256_oprf_roundtrip" (b : @bench.T) {
  let (config, server_setup, _, _) = bench_fixture(
    @moonopaque.CipherSuite::P256Sha256,
  )
  let password = b"CorrectHorseBatteryStaple"
  let cred_id = b"alice@example.com"
  let rand = Bytes::make(32, b'\x22')
  b.bench(() => {
    let (_, req) = bench_unwrap(
      @moonopaque.create_registration_request_with_random(
        config, password, rand,
      ),
      "oprf blind",
    )
    let resp = bench_unwrap(
      @moonopaque.create_registration_response(
        config, server_setup, req, cred_id,
      ),
      "oprf evaluate",
    )
    b.keep(resp)
  })
}

///|
test "opaque_ristretto255_registration" (b : @bench.T) {
  let (config, server_setup, _, _) = bench_fixture(
    @moonopaque.CipherSuite::Ristretto255Sha512,
  )
  let password = b"CorrectHorseBatteryStaple"
  let cred_id = b"alice@example.com"
  let client_id = Some(cred_id)
  let server_id = Some(b"auth.example.com")
  let reg_rand = Bytes::make(32, b'\x22')
  let env_nonce = Bytes::make(32, b'\x33')
  b.bench(() => {
    let (reg_state, reg_req) = bench_unwrap(
      @moonopaque.create_registration_request_with_random(
        config, password, reg_rand,
      ),
      "reg_req",
    )
    let reg_resp = bench_unwrap(
      @moonopaque.create_registration_response(
        config, server_setup, reg_req, cred_id,
      ),
      "reg_resp",
    )
    let (record, export_key) = bench_unwrap(
      @moonopaque.finalize_registration_request(
        config, reg_state, reg_resp, client_id, server_id, env_nonce,
      ),
      "reg_finalize",
    )
    b.keep((record, export_key))
  })
}

///|
test "opaque_ristretto255_login" (b : @bench.T) {
  let (config, server_setup, record, _) = bench_fixture(
    @moonopaque.CipherSuite::Ristretto255Sha512,
  )
  let password = b"CorrectHorseBatteryStaple"
  let cred_id = b"alice@example.com"
  let client_id = Some(cred_id)
  let server_id = Some(b"auth.example.com")
  let ke1_rand = Bytes::make(32, b'\x44')
  let mask_nonce = Bytes::make(32, b'\x55')
  let srv_nonce = Bytes::make(32, b'\x66')
  let srv_ks_seed = Bytes::make(32, b'\x77')
  b.bench(() => {
    let (client_state, ke1) = bench_unwrap(
      @moonopaque.generate_ke1_with_random(config, password, ke1_rand),
      "ke1",
    )
    let (server_state, ke2) = bench_unwrap(
      @moonopaque.generate_ke2(
        config, server_setup, server_id, client_id, record, cred_id, ke1, mask_nonce,
        srv_nonce, srv_ks_seed,
      ),
      "ke2",
    )
    let login_res = bench_unwrap(
      @moonopaque.generate_ke3(config, client_state, client_id, server_id, ke2),
      "ke3",
    )
    let server_sk = bench_unwrap(
      @moonopaque.server_finish(server_state, login_res.ke3()),
      "server_finish",
    )
    b.keep((login_res, server_sk))
  })
}

///|
test "opaque_p256_registration" (b : @bench.T) {
  let (config, server_setup, _, _) = bench_fixture(
    @moonopaque.CipherSuite::P256Sha256,
  )
  let password = b"CorrectHorseBatteryStaple"
  let cred_id = b"alice@example.com"
  let client_id = Some(cred_id)
  let server_id = Some(b"auth.example.com")
  let reg_rand = Bytes::make(32, b'\x22')
  let env_nonce = Bytes::make(32, b'\x33')
  b.bench(() => {
    let (reg_state, reg_req) = bench_unwrap(
      @moonopaque.create_registration_request_with_random(
        config, password, reg_rand,
      ),
      "reg_req",
    )
    let reg_resp = bench_unwrap(
      @moonopaque.create_registration_response(
        config, server_setup, reg_req, cred_id,
      ),
      "reg_resp",
    )
    let (record, export_key) = bench_unwrap(
      @moonopaque.finalize_registration_request(
        config, reg_state, reg_resp, client_id, server_id, env_nonce,
      ),
      "reg_finalize",
    )
    b.keep((record, export_key))
  })
}

///|
test "opaque_p256_login" (b : @bench.T) {
  let (config, server_setup, record, _) = bench_fixture(
    @moonopaque.CipherSuite::P256Sha256,
  )
  let password = b"CorrectHorseBatteryStaple"
  let cred_id = b"alice@example.com"
  let client_id = Some(cred_id)
  let server_id = Some(b"auth.example.com")
  let ke1_rand = Bytes::make(32, b'\x44')
  let mask_nonce = Bytes::make(32, b'\x55')
  let srv_nonce = Bytes::make(32, b'\x66')
  let srv_ks_seed = Bytes::make(32, b'\x77')
  b.bench(() => {
    let (client_state, ke1) = bench_unwrap(
      @moonopaque.generate_ke1_with_random(config, password, ke1_rand),
      "ke1",
    )
    let (server_state, ke2) = bench_unwrap(
      @moonopaque.generate_ke2(
        config, server_setup, server_id, client_id, record, cred_id, ke1, mask_nonce,
        srv_nonce, srv_ks_seed,
      ),
      "ke2",
    )
    let login_res = bench_unwrap(
      @moonopaque.generate_ke3(config, client_state, client_id, server_id, ke2),
      "ke3",
    )
    let server_sk = bench_unwrap(
      @moonopaque.server_finish(server_state, login_res.ke3()),
      "server_finish",
    )
    b.keep((login_res, server_sk))
  })
}

///|
test "opaque_ristretto255_ke2_fake" (b : @bench.T) {
  let (config, server_setup, _, ke1) = bench_fixture(
    @moonopaque.CipherSuite::Ristretto255Sha512,
  )
  let server_id = Some(b"auth.example.com")
  let ghost_id = b"ghost@example.com"
  let rand = Bytes::make(32, b'\x99')
  b.bench(() => {
    let (_, ke2) = bench_unwrap(
      @moonopaque.generate_ke2_for_unknown_user(
        config,
        server_setup,
        server_id,
        Some(ghost_id),
        ghost_id,
        ke1,
        rand,
      ),
      "ke2_fake",
    )
    b.keep(ke2)
  })
}

///|
test "opaque_p256_ke2_fake" (b : @bench.T) {
  let (config, server_setup, _, ke1) = bench_fixture(
    @moonopaque.CipherSuite::P256Sha256,
  )
  let server_id = Some(b"auth.example.com")
  let ghost_id = b"ghost@example.com"
  let rand = Bytes::make(32, b'\x99')
  b.bench(() => {
    let (_, ke2) = bench_unwrap(
      @moonopaque.generate_ke2_for_unknown_user(
        config,
        server_setup,
        server_id,
        Some(ghost_id),
        ghost_id,
        ke1,
        rand,
      ),
      "ke2_fake",
    )
    b.keep(ke2)
  })
}
