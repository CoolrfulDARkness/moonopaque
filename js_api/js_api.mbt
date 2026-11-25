///|
/// JavaScript / ESM bridge for `CoolrfulDARkness/moonopaque`.
///
/// Every exported function takes and returns plain `String` values so browser
/// and Node.js callers need zero JS glue or memory-marshaling boilerplate:
/// - Success: `"OK:<field1>|<field2>|..."` (all binary fields are lowercase hex)
/// - Failure: `"ERR:<error_code>"`
///
/// Ephemeral protocol states (`ClientRegistrationState`, `ClientLoginState`,
/// `ServerLoginState`) remain encapsulated inside MoonBit via single-use
/// integer session handles that are removed immediately upon completion.

///|
let next_handle : Ref[Int32] = Ref(1)

///|
let reg_sessions : Map[
  Int32,
  (@opaque.CipherSuite, @opaque.ClientRegistrationState),
] = Map([])

///|
let client_login_sessions : Map[
  Int32,
  (@opaque.CipherSuite, String, @opaque.ClientLoginState),
] = Map([])

///|
let server_login_sessions : Map[
  Int32,
  (@opaque.CipherSuite, @opaque.ServerLoginState),
] = Map([])

///|
fn alloc_handle() -> Int32 {
  let id = next_handle.val
  next_handle.val = id + 1
  id
}

///|
fn ok(payload : String) -> String {
  "OK:" + payload
}

///|
fn err(msg : String) -> String {
  "ERR:" + msg
}

///|
fn utf8_bytes(s : String) -> Bytes {
  @utf8.encode(s)
}

///|
fn optional_identity(id : String) -> Bytes? {
  if id.length() == 0 {
    None
  } else {
    Some(utf8_bytes(id))
  }
}

///|
fn parse_suite(suite : String) -> Result[@opaque.CipherSuite, String] {
  match suite {
    "ristretto255" | "OPAQUE-Ristretto255-SHA512" | "Ristretto255Sha512" =>
      Ok(@opaque.CipherSuite::Ristretto255Sha512)
    "curve25519"
    | "ristretto255-curve25519"
    | "OPAQUE-Ristretto255-Curve25519-SHA512"
    | "Ristretto255Curve25519Sha512" =>
      Ok(@opaque.CipherSuite::Ristretto255Curve25519Sha512)
    "p256" | "P256" | "OPAQUE-P256-SHA256" | "P256Sha256" =>
      Ok(@opaque.CipherSuite::P256Sha256)
    _ => Err("UnknownSuite")
  }
}

///|
fn decode_hex(hex : String, field : String) -> Result[Bytes, String] {
  match @hash.hex_decode(hex) {
    Some(bytes) => Ok(bytes)
    None => Err("InvalidHex:" + field)
  }
}

///|
fn parse_handle(handle : String) -> Int32? {
  let len = handle.length()
  if len == 0 || len > 9 {
    return None
  }
  let mut acc = 0
  for i = 0; i < len; i = i + 1 {
    let ch = handle.code_unit_at(i).to_int()
    if ch < 48 || ch > 57 {
      return None
    }
    acc = acc * 10 + (ch - 48)
  }
  if acc <= 0 {
    None
  } else {
    Some(acc)
  }
}

///|
fn build_server_setup(
  suite : @opaque.CipherSuite,
  oprf_seed_hex : String,
  sk_hex : String,
  pk_hex : String,
) -> Result[@opaque.ServerSetup, String] {
  let oprf_seed = match decode_hex(oprf_seed_hex, "oprf_seed") {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let sk = match decode_hex(sk_hex, "server_sk") {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  let pk = match decode_hex(pk_hex, "server_pk") {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  match @opaque.ServerSetup::from_keys(suite, oprf_seed, sk, pk) {
    Ok(setup) => Ok(setup)
    Err(e) => Err(Show::to_string(e))
  }
}

///|
/// Derives a deterministic `ServerSetup` from a caller-supplied hex seed (`>= 32` bytes).
/// Returns `"OK:<oprf_seed_hex>|<server_sk_hex>|<server_pk_hex>"`.
pub fn server_setup_from_seed(suite : String, seed_hex : String) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let seed = match decode_hex(seed_hex, "seed") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  match @opaque.ServerSetup::from_seed(s, seed) {
    Ok(setup) =>
      ok(
        @hash.hex_encode(setup.oprf_seed()) +
        "|" +
        @hash.hex_encode(setup.server_private_key()) +
        "|" +
        @hash.hex_encode(setup.server_public_key()),
      )
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Starts RFC 9807 §5.2.1 client registration using caller-supplied random hex (`>= 32` bytes).
/// Returns `"OK:<handle>|<registration_request_hex>"`.
pub fn client_register_start(
  suite : String,
  password : String,
  random_hex : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let random_bytes = match decode_hex(random_hex, "random") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let config = @opaque.Config::new(s, b"", @opaque.Ksf::Identity)
  match
    @opaque.create_registration_request_with_random(
      config,
      utf8_bytes(password),
      random_bytes,
    ) {
    Ok((state, req)) => {
      let handle = alloc_handle()
      reg_sessions.set(handle, (s, state))
      ok(handle.to_string() + "|" + @hash.hex_encode(req.to_bytes()))
    }
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Executes RFC 9807 §5.2.2 server registration response.
/// Returns `"OK:<registration_response_hex>"`.
pub fn server_register_response(
  suite : String,
  oprf_seed_hex : String,
  sk_hex : String,
  pk_hex : String,
  req_hex : String,
  cred_id : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let setup = match build_server_setup(s, oprf_seed_hex, sk_hex, pk_hex) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let req_bytes = match decode_hex(req_hex, "req") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let req = match @opaque.RegistrationRequest::from_bytes(s, req_bytes) {
    Ok(r) => r
    Err(e) => return err(Show::to_string(e))
  }
  let config = @opaque.Config::new(s, b"", @opaque.Ksf::Identity)
  match
    @opaque.create_registration_response(
      config,
      setup,
      req,
      utf8_bytes(cred_id),
    ) {
    Ok(resp) => ok(@hash.hex_encode(resp.to_bytes()))
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Finalizes RFC 9807 §5.2.3 client registration and consumes the single-use `handle`.
/// Empty `client_id` / `server_id` uses the RFC 9807 default public-key identity (`None`).
/// Returns `"OK:<registration_record_hex>|<export_key_hex>"`.
pub fn client_register_finish(
  suite : String,
  handle : String,
  resp_hex : String,
  client_id : String,
  server_id : String,
  env_nonce_hex : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let id = match parse_handle(handle) {
    Some(v) => v
    None => return err("InvalidHandle")
  }
  let (stored_suite, state) = match reg_sessions.get(id) {
    Some(entry) => {
      reg_sessions.remove(id)
      entry
    }
    None => return err("InvalidHandle")
  }
  if stored_suite != s {
    return err("SessionMismatch")
  }
  let resp_bytes = match decode_hex(resp_hex, "resp") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let resp = match @opaque.RegistrationResponse::from_bytes(s, resp_bytes) {
    Ok(r) => r
    Err(e) => return err(Show::to_string(e))
  }
  let env_nonce = match decode_hex(env_nonce_hex, "env_nonce") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let config = @opaque.Config::new(s, b"", @opaque.Ksf::Identity)
  match
    @opaque.finalize_registration_request(
      config,
      state,
      resp,
      optional_identity(client_id),
      optional_identity(server_id),
      env_nonce,
    ) {
    Ok((record, export_key)) =>
      ok(
        @hash.hex_encode(record.to_bytes()) + "|" + @hash.hex_encode(export_key),
      )
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Starts RFC 9807 §6.2.1 client 3DH login (`KE1`) using caller-supplied random hex (`>= 32` bytes).
/// Returns `"OK:<handle>|<ke1_hex>"`.
pub fn client_login_start(
  suite : String,
  context : String,
  password : String,
  random_hex : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let random_bytes = match decode_hex(random_hex, "random") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let config = @opaque.Config::new(
    s,
    utf8_bytes(context),
    @opaque.Ksf::Identity,
  )
  match
    @opaque.generate_ke1_with_random(config, utf8_bytes(password), random_bytes) {
    Ok((state, ke1)) => {
      let handle = alloc_handle()
      client_login_sessions.set(handle, (s, context, state))
      ok(handle.to_string() + "|" + @hash.hex_encode(ke1.to_bytes()))
    }
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Executes RFC 9807 §6.2.2 server 3DH login response (`KE2`) for a registered user.
/// Returns `"OK:<handle>|<ke2_hex>"`.
pub fn server_login_start(
  suite : String,
  context : String,
  oprf_seed_hex : String,
  sk_hex : String,
  pk_hex : String,
  record_hex : String,
  cred_id : String,
  client_id : String,
  server_id : String,
  ke1_hex : String,
  masking_nonce_hex : String,
  server_nonce_hex : String,
  server_keyshare_seed_hex : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let setup = match build_server_setup(s, oprf_seed_hex, sk_hex, pk_hex) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let record_bytes = match decode_hex(record_hex, "record") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let record = match @opaque.RegistrationRecord::from_bytes(s, record_bytes) {
    Ok(r) => r
    Err(e) => return err(Show::to_string(e))
  }
  let ke1_bytes = match decode_hex(ke1_hex, "ke1") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let ke1 = match @opaque.KE1::from_bytes(s, ke1_bytes) {
    Ok(k) => k
    Err(e) => return err(Show::to_string(e))
  }
  let masking_nonce = match decode_hex(masking_nonce_hex, "masking_nonce") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let server_nonce = match decode_hex(server_nonce_hex, "server_nonce") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let server_keyshare_seed = match
    decode_hex(server_keyshare_seed_hex, "server_keyshare_seed") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let config = @opaque.Config::new(
    s,
    utf8_bytes(context),
    @opaque.Ksf::Identity,
  )
  match
    @opaque.generate_ke2(
      config,
      setup,
      optional_identity(server_id),
      optional_identity(client_id),
      record,
      utf8_bytes(cred_id),
      ke1,
      masking_nonce,
      server_nonce,
      server_keyshare_seed,
    ) {
    Ok((state, ke2)) => {
      let handle = alloc_handle()
      server_login_sessions.set(handle, (s, state))
      ok(handle.to_string() + "|" + @hash.hex_encode(ke2.to_bytes()))
    }
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Executes RFC 9807 §6.3.2.2 & §10.9 anti-enumeration Fake `KE2` for an unknown user.
/// Returns `"OK:<handle>|<ke2_hex>"`.
pub fn server_login_fake(
  suite : String,
  context : String,
  oprf_seed_hex : String,
  sk_hex : String,
  pk_hex : String,
  cred_id : String,
  client_id : String,
  server_id : String,
  ke1_hex : String,
  random_hex : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let setup = match build_server_setup(s, oprf_seed_hex, sk_hex, pk_hex) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let ke1_bytes = match decode_hex(ke1_hex, "ke1") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let ke1 = match @opaque.KE1::from_bytes(s, ke1_bytes) {
    Ok(k) => k
    Err(e) => return err(Show::to_string(e))
  }
  let random_bytes = match decode_hex(random_hex, "random") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let config = @opaque.Config::new(
    s,
    utf8_bytes(context),
    @opaque.Ksf::Identity,
  )
  match
    @opaque.generate_ke2_for_unknown_user(
      config,
      setup,
      optional_identity(server_id),
      optional_identity(client_id),
      utf8_bytes(cred_id),
      ke1,
      random_bytes,
    ) {
    Ok((state, ke2)) => {
      let handle = alloc_handle()
      server_login_sessions.set(handle, (s, state))
      ok(handle.to_string() + "|" + @hash.hex_encode(ke2.to_bytes()))
    }
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Finalizes RFC 9807 §6.2.3 client 3DH login (`KE3`) and consumes the single-use `handle`.
/// Returns `"OK:<ke3_hex>|<session_key_hex>|<export_key_hex>"`.
pub fn client_login_finish(
  suite : String,
  context : String,
  handle : String,
  client_id : String,
  server_id : String,
  ke2_hex : String,
) -> String {
  let s = match parse_suite(suite) {
    Ok(v) => v
    Err(e) => return err(e)
  }
  let id = match parse_handle(handle) {
    Some(v) => v
    None => return err("InvalidHandle")
  }
  let (stored_suite, stored_context, state) = match
    client_login_sessions.get(id) {
    Some(entry) => {
      client_login_sessions.remove(id)
      entry
    }
    None => return err("InvalidHandle")
  }
  if stored_suite != s || stored_context != context {
    return err("SessionMismatch")
  }
  let ke2_bytes = match decode_hex(ke2_hex, "ke2") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let ke2 = match @opaque.KE2::from_bytes(s, ke2_bytes) {
    Ok(k) => k
    Err(e) => return err(Show::to_string(e))
  }
  let config = @opaque.Config::new(
    s,
    utf8_bytes(context),
    @opaque.Ksf::Identity,
  )
  match
    @opaque.generate_ke3(
      config,
      state,
      optional_identity(client_id),
      optional_identity(server_id),
      ke2,
    ) {
    Ok(res) =>
      ok(
        @hash.hex_encode(res.ke3().to_bytes()) +
        "|" +
        @hash.hex_encode(res.session_key()) +
        "|" +
        @hash.hex_encode(res.export_key()),
      )
    Err(e) => err(Show::to_string(e))
  }
}

///|
/// Executes RFC 9807 §6.2.4 server 3DH finalization (`ServerFinish`) and consumes the single-use `handle`.
/// Returns `"OK:<session_key_hex>"`.
pub fn server_login_finish(handle : String, ke3_hex : String) -> String {
  let id = match parse_handle(handle) {
    Some(v) => v
    None => return err("InvalidHandle")
  }
  let (s, state) = match server_login_sessions.get(id) {
    Some(entry) => {
      server_login_sessions.remove(id)
      entry
    }
    None => return err("InvalidHandle")
  }
  let ke3_bytes = match decode_hex(ke3_hex, "ke3") {
    Ok(b) => b
    Err(e) => return err(e)
  }
  let ke3 = match @opaque.KE3::from_bytes(s, ke3_bytes) {
    Ok(k) => k
    Err(e) => return err(Show::to_string(e))
  }
  match @opaque.server_finish(state, ke3) {
    Ok(session_key) => ok(@hash.hex_encode(session_key))
    Err(e) => err(Show::to_string(e))
  }
}
