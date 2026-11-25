///|
/// Supported RFC 9807 OPAQUE-3DH ciphersuites.
#derive(Eq, Debug)
pub(all) enum CipherSuite {
  Ristretto255Sha512
  P256Sha256
}

///|
pub impl Show for CipherSuite with fn output(self, logger) {
  match self {
    Ristretto255Sha512 => logger.write_string("Ristretto255Sha512")
    P256Sha256 => logger.write_string("P256Sha256")
  }
}

///|
/// Key Stretching Function (KSF) configuration for RFC 9807 §2.3 & §7.
///
/// - `Identity`: returns the OPRF output unchanged (used in RFC 9807 Appendix C test vectors).
/// - `Pbkdf2Sha256(iterations)`: PBKDF2-HMAC-SHA256 with 16 zero-byte salt and `dk_len = Nh`.
/// - `Pbkdf2Sha512(iterations)`: PBKDF2-HMAC-SHA512 with 16 zero-byte salt and `dk_len = Nh`.
/// - `Argon2id(t_cost, m_cost_kib, parallelism)`: RFC 9106 Argon2id with 16 zero-byte salt and `T = Nh`.
/// - `Custom(f)`: caller-provided collision-resistant stretching function.
pub(all) enum Ksf {
  Identity
  Pbkdf2Sha256(Int32)
  Pbkdf2Sha512(Int32)
  Argon2id(Int32, Int32, Int32)
  Custom((Bytes) -> Bytes)
}

///|
/// Errors produced by OPAQUE-3DH protocol operations and wire decoding.
#derive(Eq, Debug)
pub(all) enum OpaqueError {
  InvalidInput
  InvalidKey
  InvalidElement
  InvalidMessageLength
  InvalidEnvelopeTag
  InvalidServerMac
  InvalidClientMac
  OprfError(String)
  KeyDerivationFailed
}

///|
pub impl Show for OpaqueError with fn output(self, logger) {
  match self {
    InvalidInput => logger.write_string("InvalidInput")
    InvalidKey => logger.write_string("InvalidKey")
    InvalidElement => logger.write_string("InvalidElement")
    InvalidMessageLength => logger.write_string("InvalidMessageLength")
    InvalidEnvelopeTag => logger.write_string("InvalidEnvelopeTag")
    InvalidServerMac => logger.write_string("InvalidServerMac")
    InvalidClientMac => logger.write_string("InvalidClientMac")
    OprfError(msg) => {
      logger.write_string("OprfError(")
      logger.write_string(msg)
      logger.write_string(")")
    }
    KeyDerivationFailed => logger.write_string("KeyDerivationFailed")
  }
}

///|
/// OPAQUE-3DH protocol configuration (RFC 9807 §7).
pub struct Config {
  priv suite : CipherSuite
  priv context : Bytes
  priv ksf : Ksf
}

///|
/// Creates a new OPAQUE configuration.
pub fn Config::new(suite : CipherSuite, context : Bytes, ksf : Ksf) -> Config {
  { suite, context, ksf, }
}

///|
/// Creates an `OPAQUE-Ristretto255-SHA512` configuration.
pub fn Config::ristretto255_sha512(
  context~ : Bytes = b"",
  ksf~ : Ksf = Identity,
) -> Config {
  { suite: Ristretto255Sha512, context, ksf, }
}

///|
/// Creates an `OPAQUE-P256-SHA256` configuration.
pub fn Config::p256_sha256(
  context~ : Bytes = b"",
  ksf~ : Ksf = Identity,
) -> Config {
  { suite: P256Sha256, context, ksf, }
}

///|
pub fn Config::suite(self : Config) -> CipherSuite {
  self.suite
}

///|
pub fn Config::context(self : Config) -> Bytes {
  self.context
}

///|
pub fn Config::ksf(self : Config) -> Ksf {
  self.ksf
}

///|
/// Server long-term setup material (RFC 9807 §3.1): `oprf_seed` and AKE key pair.
#derive(Eq, Debug)
pub struct ServerSetup {
  priv suite : CipherSuite
  priv oprf_seed : Bytes
  priv server_private_key : Bytes
  priv server_public_key : Bytes
}

///|
/// Constructs and strictly validates `ServerSetup` from explicit keys and `oprf_seed`.
pub fn ServerSetup::from_keys(
  suite : CipherSuite,
  oprf_seed : Bytes,
  server_private_key : Bytes,
  server_public_key : Bytes,
) -> Result[ServerSetup, OpaqueError] {
  if oprf_seed.length() != suite_nh(suite) {
    return Err(InvalidKey)
  }
  if server_private_key.length() != suite_nsk(suite) {
    return Err(InvalidKey)
  }
  if server_public_key.length() != suite_npk(suite) {
    return Err(InvalidKey)
  }
  match validate_group_element(suite, server_public_key) {
    Err(_) => return Err(InvalidKey)
    Ok(_) => ()
  }
  let derived_pk = match base_mul_public_key(suite, server_private_key) {
    Ok(pk) => pk
    Err(e) => return Err(e)
  }
  if !@hash.ct_equal(derived_pk, server_public_key) {
    return Err(InvalidKey)
  }
  Ok({ suite, oprf_seed, server_private_key, server_public_key, })
}

///|
/// Deterministically derives `ServerSetup` (`oprf_seed` and AKE key pair) from a secret seed.
pub fn ServerSetup::from_seed(
  suite : CipherSuite,
  seed : Bytes,
) -> Result[ServerSetup, OpaqueError] {
  if seed.length() < nseed_len {
    return Err(InvalidInput)
  }
  let prk = suite_hkdf_extract(suite, b"", seed)
  let oprf_seed = match
    suite_hkdf_expand(
      suite,
      prk,
      b"OPAQUE-ServerSetup-OprfSeed",
      suite_nh(suite),
    ) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let kp_seed = match
    suite_hkdf_expand(suite, prk, b"OPAQUE-ServerSetup-KeyPair", nseed_len) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let (server_private_key, server_public_key) = match
    derive_dh_keypair(suite, kp_seed) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  Ok({ suite, oprf_seed, server_private_key, server_public_key, })
}

///|
pub fn ServerSetup::suite(self : ServerSetup) -> CipherSuite {
  self.suite
}

///|
pub fn ServerSetup::oprf_seed(self : ServerSetup) -> Bytes {
  self.oprf_seed
}

///|
pub fn ServerSetup::server_private_key(self : ServerSetup) -> Bytes {
  self.server_private_key
}

///|
pub fn ServerSetup::server_public_key(self : ServerSetup) -> Bytes {
  self.server_public_key
}

///|
/// RFC 9807 §4.1.1 `Envelope` structure (`nonce[Nn] || auth_tag[Nm]`).
#derive(Eq, Debug)
pub struct Envelope {
  priv nonce : Bytes
  priv auth_tag : Bytes
}

///|
pub fn Envelope::nonce(self : Envelope) -> Bytes {
  self.nonce
}

///|
pub fn Envelope::auth_tag(self : Envelope) -> Bytes {
  self.auth_tag
}

///|
pub fn Envelope::to_bytes(self : Envelope) -> Bytes {
  @hash.concat_bytes([self.nonce, self.auth_tag])
}

///|
pub fn Envelope::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[Envelope, OpaqueError] {
  let expected = suite_envelope_len(suite)
  if bytes.length() != expected {
    return Err(InvalidMessageLength)
  }
  let nonce = slice_bytes(bytes, 0, nn_len)
  let auth_tag = slice_bytes(bytes, nn_len, suite_nm(suite))
  Ok({ nonce, auth_tag, })
}

///|
/// RFC 9807 §5.1 `RegistrationRequest` message (`blinded_message[Noe]`).
#derive(Eq, Debug)
pub struct RegistrationRequest {
  priv blinded_message : Bytes
}

///|
pub fn RegistrationRequest::blinded_message(
  self : RegistrationRequest,
) -> Bytes {
  self.blinded_message
}

///|
pub fn RegistrationRequest::to_bytes(self : RegistrationRequest) -> Bytes {
  self.blinded_message
}

///|
pub fn RegistrationRequest::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[RegistrationRequest, OpaqueError] {
  if bytes.length() != suite_noe(suite) {
    return Err(InvalidMessageLength)
  }
  match validate_group_element(suite, bytes) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  Ok({ blinded_message: bytes, })
}

///|
/// RFC 9807 §5.1 `RegistrationResponse` message (`evaluated_message[Noe] || server_public_key[Npk]`).
#derive(Eq, Debug)
pub struct RegistrationResponse {
  priv evaluated_message : Bytes
  priv server_public_key : Bytes
}

///|
pub fn RegistrationResponse::evaluated_message(
  self : RegistrationResponse,
) -> Bytes {
  self.evaluated_message
}

///|
pub fn RegistrationResponse::server_public_key(
  self : RegistrationResponse,
) -> Bytes {
  self.server_public_key
}

///|
pub fn RegistrationResponse::to_bytes(self : RegistrationResponse) -> Bytes {
  @hash.concat_bytes([self.evaluated_message, self.server_public_key])
}

///|
pub fn RegistrationResponse::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[RegistrationResponse, OpaqueError] {
  let noe = suite_noe(suite)
  let npk = suite_npk(suite)
  if bytes.length() != noe + npk {
    return Err(InvalidMessageLength)
  }
  let evaluated_message = slice_bytes(bytes, 0, noe)
  let server_public_key = slice_bytes(bytes, noe, npk)
  match validate_group_element(suite, evaluated_message) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match validate_group_element(suite, server_public_key) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  Ok({ evaluated_message, server_public_key, })
}

///|
/// RFC 9807 §5.1 `RegistrationRecord` message
/// (`client_public_key[Npk] || masking_key[Nh] || envelope[Nn + Nm]`).
#derive(Eq, Debug)
pub struct RegistrationRecord {
  priv client_public_key : Bytes
  priv masking_key : Bytes
  priv envelope : Envelope
}

///|
pub fn RegistrationRecord::client_public_key(
  self : RegistrationRecord,
) -> Bytes {
  self.client_public_key
}

///|
pub fn RegistrationRecord::masking_key(self : RegistrationRecord) -> Bytes {
  self.masking_key
}

///|
pub fn RegistrationRecord::envelope(self : RegistrationRecord) -> Envelope {
  self.envelope
}

///|
pub fn RegistrationRecord::to_bytes(self : RegistrationRecord) -> Bytes {
  @hash.concat_bytes([
    self.client_public_key,
    self.masking_key,
    self.envelope.to_bytes(),
  ])
}

///|
pub fn RegistrationRecord::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[RegistrationRecord, OpaqueError] {
  let npk = suite_npk(suite)
  let nh = suite_nh(suite)
  let env_len = suite_envelope_len(suite)
  if bytes.length() != npk + nh + env_len {
    return Err(InvalidMessageLength)
  }
  let client_public_key = slice_bytes(bytes, 0, npk)
  match validate_group_element(suite, client_public_key) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let masking_key = slice_bytes(bytes, npk, nh)
  let env_bytes = slice_bytes(bytes, npk + nh, env_len)
  let envelope = match Envelope::from_bytes(suite, env_bytes) {
    Ok(e) => e
    Err(e) => return Err(e)
  }
  Ok({ client_public_key, masking_key, envelope, })
}

///|
/// Constructs a fake `RegistrationRecord` per RFC 9807 §6.3.2.2 & Appendix C.2:
/// `client_public_key`, `masking_key`, and an all-zero `Envelope` of length `Nn + Nm`.
pub fn RegistrationRecord::new_fake(
  suite : CipherSuite,
  client_public_key : Bytes,
  masking_key : Bytes,
) -> Result[RegistrationRecord, OpaqueError] {
  if client_public_key.length() != suite_npk(suite) {
    return Err(InvalidMessageLength)
  }
  if masking_key.length() != suite_nh(suite) {
    return Err(InvalidMessageLength)
  }
  match validate_group_element(suite, client_public_key) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let envelope : Envelope = {
    nonce: Bytes::make(nn_len, b'\x00'),
    auth_tag: Bytes::make(suite_nm(suite), b'\x00'),
  }
  Ok({ client_public_key, masking_key, envelope, })
}

///|
/// RFC 9807 §6.3.1 `CredentialRequest` message (`blinded_message[Noe]`).
#derive(Eq, Debug)
pub struct CredentialRequest {
  priv blinded_message : Bytes
}

///|
pub fn CredentialRequest::blinded_message(self : CredentialRequest) -> Bytes {
  self.blinded_message
}

///|
pub fn CredentialRequest::to_bytes(self : CredentialRequest) -> Bytes {
  self.blinded_message
}

///|
pub fn CredentialRequest::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[CredentialRequest, OpaqueError] {
  if bytes.length() != suite_noe(suite) {
    return Err(InvalidMessageLength)
  }
  match validate_group_element(suite, bytes) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  Ok({ blinded_message: bytes, })
}

///|
/// RFC 9807 §6.3.1 `CredentialResponse` message
/// (`evaluated_message[Noe] || masking_nonce[Nn] || masked_response[Npk + Nn + Nm]`).
#derive(Eq, Debug)
pub struct CredentialResponse {
  priv evaluated_message : Bytes
  priv masking_nonce : Bytes
  priv masked_response : Bytes
}

///|
pub fn CredentialResponse::evaluated_message(
  self : CredentialResponse,
) -> Bytes {
  self.evaluated_message
}

///|
pub fn CredentialResponse::masking_nonce(self : CredentialResponse) -> Bytes {
  self.masking_nonce
}

///|
pub fn CredentialResponse::masked_response(self : CredentialResponse) -> Bytes {
  self.masked_response
}

///|
pub fn CredentialResponse::to_bytes(self : CredentialResponse) -> Bytes {
  @hash.concat_bytes([
    self.evaluated_message,
    self.masking_nonce,
    self.masked_response,
  ])
}

///|
pub fn CredentialResponse::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[CredentialResponse, OpaqueError] {
  let noe = suite_noe(suite)
  let masked_len = suite_masked_response_len(suite)
  if bytes.length() != noe + nn_len + masked_len {
    return Err(InvalidMessageLength)
  }
  let evaluated_message = slice_bytes(bytes, 0, noe)
  match validate_group_element(suite, evaluated_message) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let masking_nonce = slice_bytes(bytes, noe, nn_len)
  let masked_response = slice_bytes(bytes, noe + nn_len, masked_len)
  Ok({ evaluated_message, masking_nonce, masked_response, })
}

///|
/// RFC 9807 §6.1 `KE1` message
/// (`credential_request[Noe] || client_nonce[Nn] || client_public_keyshare[Npk]`).
#derive(Eq, Debug)
pub struct KE1 {
  priv credential_request : CredentialRequest
  priv client_nonce : Bytes
  priv client_public_keyshare : Bytes
}

///|
pub fn KE1::credential_request(self : KE1) -> CredentialRequest {
  self.credential_request
}

///|
pub fn KE1::client_nonce(self : KE1) -> Bytes {
  self.client_nonce
}

///|
pub fn KE1::client_public_keyshare(self : KE1) -> Bytes {
  self.client_public_keyshare
}

///|
pub fn KE1::to_bytes(self : KE1) -> Bytes {
  @hash.concat_bytes([
    self.credential_request.to_bytes(),
    self.client_nonce,
    self.client_public_keyshare,
  ])
}

///|
pub fn KE1::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[KE1, OpaqueError] {
  let noe = suite_noe(suite)
  let npk = suite_npk(suite)
  if bytes.length() != noe + nn_len + npk {
    return Err(InvalidMessageLength)
  }
  let cred_bytes = slice_bytes(bytes, 0, noe)
  let credential_request = match
    CredentialRequest::from_bytes(suite, cred_bytes) {
    Ok(cr) => cr
    Err(e) => return Err(e)
  }
  let client_nonce = slice_bytes(bytes, noe, nn_len)
  let client_public_keyshare = slice_bytes(bytes, noe + nn_len, npk)
  match validate_group_element(suite, client_public_keyshare) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  Ok({ credential_request, client_nonce, client_public_keyshare, })
}

///|
/// RFC 9807 §6.1 `KE2` message
/// (`credential_response || server_nonce[Nn] || server_public_keyshare[Npk] || server_mac[Nm]`).
#derive(Eq, Debug)
pub struct KE2 {
  priv credential_response : CredentialResponse
  priv server_nonce : Bytes
  priv server_public_keyshare : Bytes
  priv server_mac : Bytes
}

///|
pub fn KE2::credential_response(self : KE2) -> CredentialResponse {
  self.credential_response
}

///|
pub fn KE2::server_nonce(self : KE2) -> Bytes {
  self.server_nonce
}

///|
pub fn KE2::server_public_keyshare(self : KE2) -> Bytes {
  self.server_public_keyshare
}

///|
pub fn KE2::server_mac(self : KE2) -> Bytes {
  self.server_mac
}

///|
pub fn KE2::to_bytes(self : KE2) -> Bytes {
  @hash.concat_bytes([
    self.credential_response.to_bytes(),
    self.server_nonce,
    self.server_public_keyshare,
    self.server_mac,
  ])
}

///|
pub fn KE2::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[KE2, OpaqueError] {
  let cr_len = suite_noe(suite) + nn_len + suite_masked_response_len(suite)
  let npk = suite_npk(suite)
  let nm = suite_nm(suite)
  if bytes.length() != cr_len + nn_len + npk + nm {
    return Err(InvalidMessageLength)
  }
  let cr_bytes = slice_bytes(bytes, 0, cr_len)
  let credential_response = match
    CredentialResponse::from_bytes(suite, cr_bytes) {
    Ok(cr) => cr
    Err(e) => return Err(e)
  }
  let server_nonce = slice_bytes(bytes, cr_len, nn_len)
  let server_public_keyshare = slice_bytes(bytes, cr_len + nn_len, npk)
  match validate_group_element(suite, server_public_keyshare) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let server_mac = slice_bytes(bytes, cr_len + nn_len + npk, nm)
  Ok({ credential_response, server_nonce, server_public_keyshare, server_mac, })
}

///|
/// RFC 9807 §6.1 `KE3` message (`client_mac[Nm]`).
#derive(Eq, Debug)
pub struct KE3 {
  priv client_mac : Bytes
}

///|
pub fn KE3::client_mac(self : KE3) -> Bytes {
  self.client_mac
}

///|
pub fn KE3::to_bytes(self : KE3) -> Bytes {
  self.client_mac
}

///|
pub fn KE3::from_bytes(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[KE3, OpaqueError] {
  if bytes.length() != suite_nm(suite) {
    return Err(InvalidMessageLength)
  }
  Ok({ client_mac: bytes, })
}

///|
/// Ephemeral client state retained between `create_registration_request`
/// and `finalize_registration_request`.
pub struct ClientRegistrationState {
  priv suite : CipherSuite
  priv password : Bytes
  priv blind_state : @oprf.BlindState
}

///|
/// Ephemeral client state retained between `generate_ke1` and `generate_ke3`.
pub struct ClientLoginState {
  priv suite : CipherSuite
  priv password : Bytes
  priv blind_state : @oprf.BlindState
  priv client_secret : Bytes
  priv ke1 : KE1
}

///|
/// Ephemeral server state retained between `generate_ke2` and `server_finish`.
pub struct ServerLoginState {
  priv suite : CipherSuite
  priv expected_client_mac : Bytes
  priv session_key : Bytes
}

///|
/// Client output of `generate_ke3` containing `KE3`, `session_key`, and `export_key`.
#derive(Eq, Debug)
pub struct LoginResult {
  priv ke3 : KE3
  priv session_key : Bytes
  priv export_key : Bytes
}

///|
pub fn LoginResult::ke3(self : LoginResult) -> KE3 {
  self.ke3
}

///|
pub fn LoginResult::session_key(self : LoginResult) -> Bytes {
  self.session_key
}

///|
pub fn LoginResult::export_key(self : LoginResult) -> Bytes {
  self.export_key
}
