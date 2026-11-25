///|
/// RFC 9807 §6.4.1 `DeriveDiffieHellmanKeyPair(seed)`.
/// Derives `(private_key, public_key)` deterministically from a 32-byte `seed`.
pub fn derive_dh_keypair(
  suite : CipherSuite,
  seed : Bytes,
) -> Result[(Bytes, Bytes), OpaqueError] {
  if seed.length() != nseed_len {
    return Err(InvalidInput)
  }
  match
    @oprf.derive_key_pair(
      suite_oprf(suite),
      seed,
      b"OPAQUE-DeriveDiffieHellmanKeyPair",
    ) {
    Ok(pair) => Ok(pair)
    Err(e) => Err(map_oprf_error(e))
  }
}

///|
/// RFC 9807 §6.4.1 & §10.7 `DiffieHellman(k, B)` with strict public-key and shared-secret validation.
fn diffie_hellman(
  suite : CipherSuite,
  sk_bytes : Bytes,
  pk_bytes : Bytes,
) -> Result[Bytes, OpaqueError] {
  match suite {
    Ristretto255Sha512 => {
      let sk = match @ristretto255.Scalar::from_bytes_canonical(sk_bytes) {
        None => return Err(InvalidKey)
        Some(s) => if s.is_zero() { return Err(InvalidKey) } else { s }
      }
      let pk = match @ristretto255.Element::from_bytes(pk_bytes) {
        None => return Err(InvalidElement)
        Some(p) => if p.is_identity() { return Err(InvalidElement) } else { p }
      }
      let shared = pk.scalar_mul(sk)
      if shared.is_identity() {
        return Err(InvalidElement)
      }
      Ok(shared.to_bytes())
    }
    P256Sha256 => {
      let sk = match @p256.Scalar::from_bytes_canonical(sk_bytes) {
        None => return Err(InvalidKey)
        Some(s) => if s.is_zero() { return Err(InvalidKey) } else { s }
      }
      let pk = match @p256.Point::from_bytes_compressed(pk_bytes) {
        None => return Err(InvalidElement)
        Some(p) => if p.is_identity() { return Err(InvalidElement) } else { p }
      }
      let shared = pk.scalar_mul(sk)
      if shared.is_identity() {
        return Err(InvalidElement)
      }
      Ok(shared.to_bytes_compressed())
    }
  }
}

///|
/// RFC 9807 §6.4.2.1 `Expand-Label(Secret, Label, Context, Length)`.
fn expand_label(
  suite : CipherSuite,
  secret : Bytes,
  label : Bytes,
  context : Bytes,
  length : Int32,
) -> Result[Bytes, OpaqueError] {
  let full_label = @hash.concat_bytes([b"OPAQUE-", label])
  if full_label.length() > 255 || context.length() > 255 {
    return Err(InvalidInput)
  }
  let custom_label = @hash.concat_bytes([
    @hash.i2osp(length, 2),
    @hash.i2osp(full_label.length(), 1),
    full_label,
    @hash.i2osp(context.length(), 1),
    context,
  ])
  suite_hkdf_expand(suite, secret, custom_label, length)
}

///|
/// RFC 9807 §6.4.2.1 `Derive-Secret(Secret, Label, Transcript-Hash)`.
fn derive_secret(
  suite : CipherSuite,
  secret : Bytes,
  label : Bytes,
  transcript_hash : Bytes,
) -> Result[Bytes, OpaqueError] {
  expand_label(suite, secret, label, transcript_hash, suite_nx(suite))
}

///|
/// RFC 9807 §6.4.2.1 `Preamble` transcript construction.
fn build_preamble(
  context : Bytes,
  client_identity : Bytes,
  ke1 : KE1,
  server_identity : Bytes,
  credential_response : CredentialResponse,
  server_nonce : Bytes,
  server_public_keyshare : Bytes,
) -> Result[Bytes, OpaqueError] {
  if context.length() > max_u16_len ||
    client_identity.length() > max_u16_len ||
    server_identity.length() > max_u16_len {
    return Err(InvalidInput)
  }
  Ok(
    @hash.concat_bytes([
      b"OPAQUEv1-",
      @hash.i2osp(context.length(), 2),
      context,
      @hash.i2osp(client_identity.length(), 2),
      client_identity,
      ke1.to_bytes(),
      @hash.i2osp(server_identity.length(), 2),
      server_identity,
      credential_response.to_bytes(),
      server_nonce,
      server_public_keyshare,
    ]),
  )
}

///|
/// RFC 9807 §6.4.2.2 `DeriveKeys(ikm, preamble)`.
/// Returns `(Km2, Km3, session_key)`.
fn derive_keys(
  suite : CipherSuite,
  ikm : Bytes,
  preamble : Bytes,
) -> Result[(Bytes, Bytes, Bytes), OpaqueError] {
  let prk = suite_hkdf_extract(suite, b"", ikm)
  let preamble_hash = suite_hash(suite, preamble)
  let handshake_secret = match
    derive_secret(suite, prk, b"HandshakeSecret", preamble_hash) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let session_key = match
    derive_secret(suite, prk, b"SessionKey", preamble_hash) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let km2 = match derive_secret(suite, handshake_secret, b"ServerMAC", b"") {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let km3 = match derive_secret(suite, handshake_secret, b"ClientMAC", b"") {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  Ok((km2, km3, session_key))
}

///|
/// RFC 9807 §6.2.1 `GenerateKE1` with explicit deterministic randomness inputs.
pub fn generate_ke1(
  config : Config,
  password : Bytes,
  blind_scalar : Bytes,
  client_nonce : Bytes,
  client_keyshare_seed : Bytes,
) -> Result[(ClientLoginState, KE1), OpaqueError] {
  if client_nonce.length() != nn_len ||
    client_keyshare_seed.length() != nseed_len {
    return Err(InvalidInput)
  }
  let (blind_state, blinded_message) = match
    @oprf.blind_with_scalar(suite_oprf(config.suite), password, blind_scalar) {
    Ok(res) => res
    Err(e) => return Err(map_oprf_error(e))
  }
  let (client_secret, client_public_keyshare) = match
    derive_dh_keypair(config.suite, client_keyshare_seed) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let credential_request : CredentialRequest = { blinded_message, }
  let ke1 : KE1 = { credential_request, client_nonce, client_public_keyshare, }
  let state : ClientLoginState = {
    suite: config.suite,
    password,
    blind_state,
    client_secret,
    ke1,
  }
  Ok((state, ke1))
}

///|
/// RFC 9807 §6.2.1 `GenerateKE1` deriving blind scalar, `client_nonce`, and
/// `client_keyshare_seed` from caller-supplied `random_bytes` (at least 32 bytes).
pub fn generate_ke1_with_random(
  config : Config,
  password : Bytes,
  random_bytes : Bytes,
) -> Result[(ClientLoginState, KE1), OpaqueError] {
  if random_bytes.length() < nseed_len {
    return Err(InvalidInput)
  }
  let prk = suite_hkdf_extract(config.suite, b"", random_bytes)
  let blind_seed = match
    suite_hkdf_expand(config.suite, prk, b"OPAQUE-KE1-Blind", nseed_len) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let client_nonce = match
    suite_hkdf_expand(config.suite, prk, b"OPAQUE-KE1-Nonce", nn_len) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let client_keyshare_seed = match
    suite_hkdf_expand(config.suite, prk, b"OPAQUE-KE1-KeyshareSeed", nseed_len) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let (blind_state, blinded_message) = match
    @oprf.blind_from_random_bytes(
      suite_oprf(config.suite),
      password,
      blind_seed,
    ) {
    Ok(res) => res
    Err(e) => return Err(map_oprf_error(e))
  }
  let (client_secret, client_public_keyshare) = match
    derive_dh_keypair(config.suite, client_keyshare_seed) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let credential_request : CredentialRequest = { blinded_message, }
  let ke1 : KE1 = { credential_request, client_nonce, client_public_keyshare, }
  let state : ClientLoginState = {
    suite: config.suite,
    password,
    blind_state,
    client_secret,
    ke1,
  }
  Ok((state, ke1))
}

///|
/// RFC 9807 §6.2.2 `GenerateKE2`.
pub fn generate_ke2(
  config : Config,
  server_setup : ServerSetup,
  server_identity : Bytes?,
  client_identity : Bytes?,
  record : RegistrationRecord,
  credential_identifier : Bytes,
  ke1 : KE1,
  masking_nonce : Bytes,
  server_nonce : Bytes,
  server_keyshare_seed : Bytes,
) -> Result[(ServerLoginState, KE2), OpaqueError] {
  let suite = config.suite
  if suite != server_setup.suite {
    return Err(InvalidInput)
  }
  if masking_nonce.length() != nn_len ||
    server_nonce.length() != nn_len ||
    server_keyshare_seed.length() != nseed_len {
    return Err(InvalidInput)
  }
  if record.client_public_key.length() != suite_npk(suite) ||
    record.masking_key.length() != suite_nh(suite) ||
    record.envelope.nonce.length() != nn_len ||
    record.envelope.auth_tag.length() != suite_nm(suite) ||
    ke1.credential_request.blinded_message.length() != suite_noe(suite) ||
    ke1.client_nonce.length() != nn_len ||
    ke1.client_public_keyshare.length() != suite_npk(suite) {
    return Err(InvalidMessageLength)
  }
  // CreateCredentialResponse (RFC 9807 §6.3.2.2)
  let oprf_key = match
    derive_oprf_key(suite, server_setup.oprf_seed, credential_identifier) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let evaluated_message = match
    @oprf.blind_evaluate(
      suite_oprf(suite),
      oprf_key,
      ke1.credential_request.blinded_message,
    ) {
    Ok(m) => m
    Err(e) => return Err(map_oprf_error(e))
  }
  let pad = match
    suite_hkdf_expand(
      suite,
      record.masking_key,
      @hash.concat_bytes([masking_nonce, b"CredentialResponsePad"]),
      suite_masked_response_len(suite),
    ) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let masked_response = @hash.xor_bytes(
    pad,
    @hash.concat_bytes([
      server_setup.server_public_key,
      record.envelope.to_bytes(),
    ]),
  )
  let credential_response : CredentialResponse = {
    evaluated_message,
    masking_nonce,
    masked_response,
  }
  // CreateCleartextCredentials (RFC 9807 §4)
  let cleartext_credentials = match
    create_cleartext_credentials(
      server_setup.server_public_key,
      record.client_public_key,
      server_identity,
      client_identity,
    ) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  // AuthServerRespond (RFC 9807 §6.4.4)
  let (server_private_keyshare, server_public_keyshare) = match
    derive_dh_keypair(suite, server_keyshare_seed) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let preamble = match
    build_preamble(
      config.context,
      cleartext_credentials.client_identity,
      ke1,
      cleartext_credentials.server_identity,
      credential_response,
      server_nonce,
      server_public_keyshare,
    ) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let dh1 = match
    diffie_hellman(suite, server_private_keyshare, ke1.client_public_keyshare) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  let dh2 = match
    diffie_hellman(
      suite,
      server_setup.server_private_key,
      ke1.client_public_keyshare,
    ) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  let dh3 = match
    diffie_hellman(suite, server_private_keyshare, record.client_public_key) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  let ikm = @hash.concat_bytes([dh1, dh2, dh3])
  let (km2, km3, session_key) = match derive_keys(suite, ikm, preamble) {
    Ok(res) => res
    Err(e) => return Err(e)
  }
  let server_mac = suite_hmac(suite, km2, suite_hash(suite, preamble))
  let expected_client_mac = suite_hmac(
    suite,
    km3,
    suite_hash(suite, @hash.concat_bytes([preamble, server_mac])),
  )
  let state : ServerLoginState = { suite, expected_client_mac, session_key, }
  let ke2 : KE2 = {
    credential_response,
    server_nonce,
    server_public_keyshare,
    server_mac,
  }
  Ok((state, ke2))
}

///|
/// RFC 9807 §6.2.2 / §6.3.2.2 / §10.9 fake `KE2` response generator for mitigating
/// client enumeration attacks with explicit deterministic fake-record parameters.
pub fn generate_ke2_fake(
  config : Config,
  server_setup : ServerSetup,
  server_identity : Bytes?,
  client_identity : Bytes?,
  credential_identifier : Bytes,
  ke1 : KE1,
  masking_nonce : Bytes,
  server_nonce : Bytes,
  server_keyshare_seed : Bytes,
  fake_client_keypair_seed : Bytes,
  fake_masking_key : Bytes,
  fake_envelope_nonce : Bytes,
  fake_auth_tag : Bytes,
) -> Result[(ServerLoginState, KE2), OpaqueError] {
  let suite = config.suite
  if fake_masking_key.length() != suite_nh(suite) ||
    fake_envelope_nonce.length() != nn_len ||
    fake_auth_tag.length() != suite_nm(suite) {
    return Err(InvalidInput)
  }
  let (_, fake_client_public_key) = match
    derive_dh_keypair(suite, fake_client_keypair_seed) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let fake_record : RegistrationRecord = {
    client_public_key: fake_client_public_key,
    masking_key: fake_masking_key,
    envelope: { nonce: fake_envelope_nonce, auth_tag: fake_auth_tag, },
  }
  generate_ke2(
    config, server_setup, server_identity, client_identity, fake_record, credential_identifier,
    ke1, masking_nonce, server_nonce, server_keyshare_seed,
  )
}

///|
/// Convenience anti-enumeration entry point for unknown users (RFC 9807 §6.3.2.2 & §10.9).
/// Derives fake record parameters (with all-zero envelope per RFC 9807 §6.3.2.2) and
/// server nonces from `random_bytes` (at least 32 bytes) to emit an indistinguishable `KE2`.
pub fn generate_ke2_for_unknown_user(
  config : Config,
  server_setup : ServerSetup,
  server_identity : Bytes?,
  client_identity : Bytes?,
  credential_identifier : Bytes,
  ke1 : KE1,
  random_bytes : Bytes,
) -> Result[(ServerLoginState, KE2), OpaqueError] {
  if random_bytes.length() < nseed_len {
    return Err(InvalidInput)
  }
  let suite = config.suite
  let prk = suite_hkdf_extract(suite, b"", random_bytes)
  let masking_nonce = match
    suite_hkdf_expand(suite, prk, b"OPAQUE-Fake-MaskingNonce", nn_len) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let server_nonce = match
    suite_hkdf_expand(suite, prk, b"OPAQUE-Fake-ServerNonce", nn_len) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let server_keyshare_seed = match
    suite_hkdf_expand(suite, prk, b"OPAQUE-Fake-ServerKeyshareSeed", nseed_len) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let fake_client_keypair_seed = match
    suite_hkdf_expand(suite, prk, b"OPAQUE-Fake-ClientKeypairSeed", nseed_len) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let fake_masking_key = match
    suite_hkdf_expand(suite, prk, b"OPAQUE-Fake-MaskingKey", suite_nh(suite)) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let fake_envelope_nonce = Bytes::make(nn_len, b'\x00')
  let fake_auth_tag = Bytes::make(suite_nm(suite), b'\x00')
  generate_ke2_fake(
    config, server_setup, server_identity, client_identity, credential_identifier,
    ke1, masking_nonce, server_nonce, server_keyshare_seed, fake_client_keypair_seed,
    fake_masking_key, fake_envelope_nonce, fake_auth_tag,
  )
}

///|
/// RFC 9807 §6.2.3 `GenerateKE3`.
/// Recovers client credentials, verifies `Envelope.auth_tag` and `KE2.server_mac`
/// in constant time, and returns `LoginResult` (`ke3`, `session_key`, `export_key`).
pub fn generate_ke3(
  config : Config,
  state : ClientLoginState,
  client_identity : Bytes?,
  server_identity : Bytes?,
  ke2 : KE2,
) -> Result[LoginResult, OpaqueError] {
  let suite = config.suite
  if suite != state.suite {
    return Err(InvalidInput)
  }
  let noe = suite_noe(suite)
  let npk = suite_npk(suite)
  let nm = suite_nm(suite)
  let masked_len = suite_masked_response_len(suite)
  if ke2.credential_response.evaluated_message.length() != noe ||
    ke2.credential_response.masking_nonce.length() != nn_len ||
    ke2.credential_response.masked_response.length() != masked_len ||
    ke2.server_nonce.length() != nn_len ||
    ke2.server_public_keyshare.length() != npk ||
    ke2.server_mac.length() != nm {
    return Err(InvalidMessageLength)
  }
  // RecoverCredentials (RFC 9807 §6.3.2.3)
  let oprf_output = match
    @oprf.finalize(
      state.blind_state,
      state.password,
      ke2.credential_response.evaluated_message,
    ) {
    Ok(out) => out
    Err(e) => return Err(map_oprf_error(e))
  }
  let randomized_password = match
    derive_randomized_password(config, oprf_output) {
    Ok(rp) => rp
    Err(e) => return Err(e)
  }
  let masking_key = match
    suite_hkdf_expand(
      suite,
      randomized_password,
      b"MaskingKey",
      suite_nh(suite),
    ) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let pad = match
    suite_hkdf_expand(
      suite,
      masking_key,
      @hash.concat_bytes([
        ke2.credential_response.masking_nonce,
        b"CredentialResponsePad",
      ]),
      masked_len,
    ) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let unmasked = @hash.xor_bytes(pad, ke2.credential_response.masked_response)
  let server_public_key = slice_bytes(unmasked, 0, npk)
  let envelope : Envelope = {
    nonce: slice_bytes(unmasked, npk, nn_len),
    auth_tag: slice_bytes(unmasked, npk + nn_len, nm),
  }
  let (client_private_key, cleartext_credentials, export_key) = match
    envelope_recover(
      suite, randomized_password, server_public_key, envelope, server_identity, client_identity,
    ) {
    Ok(res) => res
    Err(e) => return Err(e)
  }
  // AuthClientFinalize (RFC 9807 §6.4.3)
  let dh1 = match
    diffie_hellman(suite, state.client_secret, ke2.server_public_keyshare) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  let dh2 = match
    diffie_hellman(
      suite,
      state.client_secret,
      cleartext_credentials.server_public_key,
    ) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  let dh3 = match
    diffie_hellman(suite, client_private_key, ke2.server_public_keyshare) {
    Ok(d) => d
    Err(e) => return Err(e)
  }
  let ikm = @hash.concat_bytes([dh1, dh2, dh3])
  let preamble = match
    build_preamble(
      config.context,
      cleartext_credentials.client_identity,
      state.ke1,
      cleartext_credentials.server_identity,
      ke2.credential_response,
      ke2.server_nonce,
      ke2.server_public_keyshare,
    ) {
    Ok(p) => p
    Err(e) => return Err(e)
  }
  let (km2, km3, session_key) = match derive_keys(suite, ikm, preamble) {
    Ok(res) => res
    Err(e) => return Err(e)
  }
  let expected_server_mac = suite_hmac(suite, km2, suite_hash(suite, preamble))
  if !@hash.ct_equal(ke2.server_mac, expected_server_mac) {
    return Err(InvalidServerMac)
  }
  let client_mac = suite_hmac(
    suite,
    km3,
    suite_hash(suite, @hash.concat_bytes([preamble, expected_server_mac])),
  )
  let ke3 : KE3 = { client_mac, }
  Ok({ ke3, session_key, export_key, })
}

///|
/// RFC 9807 §6.2.4 `ServerFinish`.
/// Verifies `KE3.client_mac` in constant time using `@hash.ct_equal` and returns `session_key`.
pub fn server_finish(
  state : ServerLoginState,
  ke3 : KE3,
) -> Result[Bytes, OpaqueError] {
  if ke3.client_mac.length() != suite_nm(state.suite) {
    return Err(InvalidMessageLength)
  }
  if !@hash.ct_equal(ke3.client_mac, state.expected_client_mac) {
    return Err(InvalidClientMac)
  }
  Ok(state.session_key)
}
