///|
/// Internal RFC 9807 §4 `CleartextCredentials` structure.
priv struct CleartextCredentials {
  server_public_key : Bytes
  server_identity : Bytes
  client_identity : Bytes
}

///|
/// RFC 9807 §4 `CreateCleartextCredentials`.
/// Defaults missing identities (`None`) to the corresponding public key.
fn create_cleartext_credentials(
  server_public_key : Bytes,
  client_public_key : Bytes,
  server_identity : Bytes?,
  client_identity : Bytes?,
) -> Result[CleartextCredentials, OpaqueError] {
  let resolved_server_id = match server_identity {
    None => server_public_key
    Some(id) =>
      if id.length() == 0 || id.length() > max_u16_len {
        return Err(InvalidInput)
      } else {
        id
      }
  }
  let resolved_client_id = match client_identity {
    None => client_public_key
    Some(id) =>
      if id.length() == 0 || id.length() > max_u16_len {
        return Err(InvalidInput)
      } else {
        id
      }
  }
  Ok({
    server_public_key,
    server_identity: resolved_server_id,
    client_identity: resolved_client_id,
  })
}

///|
/// Wire encoding of `CleartextCredentials` used as MAC input in RFC 9807 §4.1.2 & §4.1.3.
fn serialize_cleartext_credentials(creds : CleartextCredentials) -> Bytes {
  @hash.concat_bytes([
    creds.server_public_key,
    @hash.i2osp(creds.server_identity.length(), 2),
    creds.server_identity,
    @hash.i2osp(creds.client_identity.length(), 2),
    creds.client_identity,
  ])
}

///|
/// Computes `randomized_password = Extract("", concat(oprf_output, Stretch(oprf_output)))`
/// per RFC 9807 §5.2.3 & §6.3.2.3.
fn derive_randomized_password(
  config : Config,
  oprf_output : Bytes,
) -> Result[Bytes, OpaqueError] {
  let stretched = match suite_stretch(config, oprf_output) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  Ok(
    suite_hkdf_extract(
      config.suite,
      b"",
      @hash.concat_bytes([oprf_output, stretched]),
    ),
  )
}

///|
/// Derives the client's AKE keypair from `randomized_password` and `envelope_nonce`
/// per RFC 9807 §4.1.2 & §4.1.3.
fn derive_client_keypair(
  suite : CipherSuite,
  randomized_password : Bytes,
  envelope_nonce : Bytes,
) -> Result[(Bytes, Bytes), OpaqueError] {
  let seed = match
    suite_hkdf_expand(
      suite,
      randomized_password,
      @hash.concat_bytes([envelope_nonce, b"PrivateKey"]),
      nseed_len,
    ) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  derive_dh_keypair(suite, seed)
}

///|
/// RFC 9807 §4.1.2 `Store` (deterministic given `envelope_nonce`).
/// Returns `(envelope, client_public_key, masking_key, export_key)`.
fn envelope_store(
  suite : CipherSuite,
  randomized_password : Bytes,
  server_public_key : Bytes,
  server_identity : Bytes?,
  client_identity : Bytes?,
  envelope_nonce : Bytes,
) -> Result[(Envelope, Bytes, Bytes, Bytes), OpaqueError] {
  if envelope_nonce.length() != nn_len {
    return Err(InvalidInput)
  }
  let nh = suite_nh(suite)
  let masking_key = match
    suite_hkdf_expand(suite, randomized_password, b"MaskingKey", nh) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let auth_key = match
    suite_hkdf_expand(
      suite,
      randomized_password,
      @hash.concat_bytes([envelope_nonce, b"AuthKey"]),
      nh,
    ) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let export_key = match
    suite_hkdf_expand(
      suite,
      randomized_password,
      @hash.concat_bytes([envelope_nonce, b"ExportKey"]),
      nh,
    ) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let (_, client_public_key) = match
    derive_client_keypair(suite, randomized_password, envelope_nonce) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let cleartext_credentials = match
    create_cleartext_credentials(
      server_public_key, client_public_key, server_identity, client_identity,
    ) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let auth_tag = suite_hmac(
    suite,
    auth_key,
    @hash.concat_bytes([
      envelope_nonce,
      serialize_cleartext_credentials(cleartext_credentials),
    ]),
  )
  let envelope : Envelope = { nonce: envelope_nonce, auth_tag, }
  Ok((envelope, client_public_key, masking_key, export_key))
}

///|
/// RFC 9807 §4.1.3 `Recover`.
/// Verifies `envelope.auth_tag` in constant time using `@hash.ct_equal` before returning
/// `(client_private_key, cleartext_credentials, export_key)`.
fn envelope_recover(
  suite : CipherSuite,
  randomized_password : Bytes,
  server_public_key : Bytes,
  envelope : Envelope,
  server_identity : Bytes?,
  client_identity : Bytes?,
) -> Result[(Bytes, CleartextCredentials, Bytes), OpaqueError] {
  if envelope.nonce.length() != nn_len ||
    envelope.auth_tag.length() != suite_nm(suite) {
    return Err(InvalidMessageLength)
  }
  let nh = suite_nh(suite)
  let auth_key = match
    suite_hkdf_expand(
      suite,
      randomized_password,
      @hash.concat_bytes([envelope.nonce, b"AuthKey"]),
      nh,
    ) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let export_key = match
    suite_hkdf_expand(
      suite,
      randomized_password,
      @hash.concat_bytes([envelope.nonce, b"ExportKey"]),
      nh,
    ) {
    Ok(k) => k
    Err(e) => return Err(e)
  }
  let (client_private_key, client_public_key) = match
    derive_client_keypair(suite, randomized_password, envelope.nonce) {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let cleartext_credentials = match
    create_cleartext_credentials(
      server_public_key, client_public_key, server_identity, client_identity,
    ) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let expected_tag = suite_hmac(
    suite,
    auth_key,
    @hash.concat_bytes([
      envelope.nonce,
      serialize_cleartext_credentials(cleartext_credentials),
    ]),
  )
  if !@hash.ct_equal(envelope.auth_tag, expected_tag) {
    return Err(InvalidEnvelopeTag)
  }
  Ok((client_private_key, cleartext_credentials, export_key))
}
