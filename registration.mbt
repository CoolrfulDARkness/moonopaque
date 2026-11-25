///|
/// RFC 9807 §5.2.1 `CreateRegistrationRequest` with an explicit canonical non-zero blind scalar.
pub fn create_registration_request(
  config : Config,
  password : Bytes,
  blind_scalar : Bytes,
) -> Result[(ClientRegistrationState, RegistrationRequest), OpaqueError] {
  let (blind_state, blinded_message) = match
    @oprf.blind_with_scalar(suite_oprf(config.suite), password, blind_scalar) {
    Ok(res) => res
    Err(e) => return Err(map_oprf_error(e))
  }
  let state : ClientRegistrationState = {
    suite: config.suite,
    password,
    blind_state,
  }
  let request : RegistrationRequest = { blinded_message, }
  Ok((state, request))
}

///|
/// RFC 9807 §5.2.1 `CreateRegistrationRequest` deriving a non-zero blind scalar
/// from caller-supplied `random_bytes` (at least 32 bytes).
pub fn create_registration_request_with_random(
  config : Config,
  password : Bytes,
  random_bytes : Bytes,
) -> Result[(ClientRegistrationState, RegistrationRequest), OpaqueError] {
  if random_bytes.length() < nseed_len {
    return Err(InvalidInput)
  }
  let (blind_state, blinded_message) = match
    @oprf.blind_from_random_bytes(
      suite_oprf(config.suite),
      password,
      random_bytes,
    ) {
    Ok(res) => res
    Err(e) => return Err(map_oprf_error(e))
  }
  let state : ClientRegistrationState = {
    suite: config.suite,
    password,
    blind_state,
  }
  let request : RegistrationRequest = { blinded_message, }
  Ok((state, request))
}

///|
/// RFC 9807 §5.2.2 `CreateRegistrationResponse`.
pub fn create_registration_response(
  config : Config,
  server_setup : ServerSetup,
  request : RegistrationRequest,
  credential_identifier : Bytes,
) -> Result[RegistrationResponse, OpaqueError] {
  if config.suite != server_setup.suite {
    return Err(InvalidInput)
  }
  if request.blinded_message.length() != suite_noe(config.suite) {
    return Err(InvalidMessageLength)
  }
  let oprf_key = match
    derive_oprf_key(config.suite, server_setup.oprf_seed, credential_identifier) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let evaluated_message = match
    @oprf.blind_evaluate(
      suite_oprf(config.suite),
      oprf_key,
      request.blinded_message,
    ) {
    Ok(m) => m
    Err(e) => return Err(map_oprf_error(e))
  }
  Ok({ evaluated_message, server_public_key: server_setup.server_public_key, })
}

///|
/// RFC 9807 §5.2.3 `FinalizeRegistrationRequest`.
/// Returns `(record, export_key)`.
pub fn finalize_registration_request(
  config : Config,
  state : ClientRegistrationState,
  response : RegistrationResponse,
  client_identity : Bytes?,
  server_identity : Bytes?,
  envelope_nonce : Bytes,
) -> Result[(RegistrationRecord, Bytes), OpaqueError] {
  if config.suite != state.suite {
    return Err(InvalidInput)
  }
  if response.evaluated_message.length() != suite_noe(config.suite) ||
    response.server_public_key.length() != suite_npk(config.suite) {
    return Err(InvalidMessageLength)
  }
  // RFC 9807 §5 & §10.7: client MUST validate the server public key before use.
  match validate_group_element(config.suite, response.server_public_key) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let oprf_output = match
    @oprf.finalize(
      state.blind_state,
      state.password,
      response.evaluated_message,
    ) {
    Ok(out) => out
    Err(e) => return Err(map_oprf_error(e))
  }
  let randomized_password = match
    derive_randomized_password(config, oprf_output) {
    Ok(rp) => rp
    Err(e) => return Err(e)
  }
  let (envelope, client_public_key, masking_key, export_key) = match
    envelope_store(
      config.suite,
      randomized_password,
      response.server_public_key,
      server_identity,
      client_identity,
      envelope_nonce,
    ) {
    Ok(res) => res
    Err(e) => return Err(e)
  }
  let record : RegistrationRecord = {
    client_public_key,
    masking_key,
    envelope,
  }
  Ok((record, export_key))
}
