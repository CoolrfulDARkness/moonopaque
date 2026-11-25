///|
/// Pure-MoonBit, zero-FFI, Sans-I/O implementation of the IETF RFC 9807 OPAQUE
/// (OPAQUE-3DH) Augmented Password-Authenticated Key Exchange protocol.
///
/// Supported ciphersuites:
/// - `OPAQUE-Ristretto255-SHA512` (ristretto255, SHA-512, HKDF-SHA512, HMAC-SHA512)
/// - `OPAQUE-P256-SHA256` (NIST P-256, SHA-256, HKDF-SHA256, HMAC-SHA256)

///|
/// Nonce length `Nn` in bytes (RFC 9807 §2).
let nn_len : Int32 = 32

///|
/// Seed length `Nseed` in bytes (RFC 9807 §2).
let nseed_len : Int32 = 32

///|
/// Maximum length of 2-byte length-prefixed fields (`<..2^16-1>`).
let max_u16_len : Int32 = 65535

///|
fn slice_bytes(data : Bytes, start : Int32, len : Int32) -> Bytes {
  Bytes::makei(len, i => data[start + i])
}

///|
fn map_oprf_error(err : @oprf.OprfError) -> OpaqueError {
  match err {
    @oprf.OprfError::InvalidInput => InvalidInput
    @oprf.OprfError::InvalidElement => InvalidElement
    @oprf.OprfError::InvalidScalar => InvalidKey
    @oprf.OprfError::ZeroScalar => InvalidKey
    @oprf.OprfError::DeriveKeyPairFailed => KeyDerivationFailed
  }
}

///|
fn suite_oprf(suite : CipherSuite) -> @oprf.OprfSuite {
  match suite {
    Ristretto255Sha512 => @oprf.OprfSuite::Ristretto255Sha512
    P256Sha256 => @oprf.OprfSuite::P256Sha256
  }
}

///|
fn suite_nh(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 64
    P256Sha256 => 32
  }
}

///|
fn suite_nx(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 64
    P256Sha256 => 32
  }
}

///|
fn suite_nm(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 64
    P256Sha256 => 32
  }
}

///|
fn suite_noe(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 32
    P256Sha256 => 33
  }
}

///|
fn suite_nok(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 32
    P256Sha256 => 32
  }
}

///|
fn suite_npk(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 32
    P256Sha256 => 33
  }
}

///|
fn suite_nsk(suite : CipherSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 32
    P256Sha256 => 32
  }
}

///|
fn suite_envelope_len(suite : CipherSuite) -> Int32 {
  nn_len + suite_nm(suite)
}

///|
fn suite_masked_response_len(suite : CipherSuite) -> Int32 {
  suite_npk(suite) + nn_len + suite_nm(suite)
}

///|
fn suite_hash(suite : CipherSuite, msg : Bytes) -> Bytes {
  match suite {
    Ristretto255Sha512 => @hash.sha512(msg)
    P256Sha256 => @hash.sha256(msg)
  }
}

///|
fn suite_hmac(suite : CipherSuite, key : Bytes, msg : Bytes) -> Bytes {
  match suite {
    Ristretto255Sha512 => @hash.hmac_sha512(key, msg)
    P256Sha256 => @hash.hmac_sha256(key, msg)
  }
}

///|
fn suite_hkdf_extract(suite : CipherSuite, salt : Bytes, ikm : Bytes) -> Bytes {
  match suite {
    Ristretto255Sha512 => @hash.hkdf_extract_sha512(salt, ikm)
    P256Sha256 => @hash.hkdf_extract_sha256(salt, ikm)
  }
}

///|
fn suite_hkdf_expand(
  suite : CipherSuite,
  prk : Bytes,
  info : Bytes,
  length : Int32,
) -> Result[Bytes, OpaqueError] {
  let max_len = 255 * suite_nx(suite)
  if length < 0 || length > max_len {
    return Err(KeyDerivationFailed)
  }
  let out = match suite {
    Ristretto255Sha512 => @hash.hkdf_expand_sha512(prk, info, length)
    P256Sha256 => @hash.hkdf_expand_sha256(prk, info, length)
  }
  Ok(out)
}

///|
fn suite_stretch(
  config : Config,
  oprf_output : Bytes,
) -> Result[Bytes, OpaqueError] {
  let nh = suite_nh(config.suite)
  let zero_salt = Bytes::make(16, b'\x00')
  match config.ksf {
    Identity => Ok(oprf_output)
    Pbkdf2Sha256(iterations) =>
      if iterations <= 0 {
        Err(InvalidInput)
      } else {
        Ok(@hash.pbkdf2_hmac_sha256(oprf_output, zero_salt, iterations, nh))
      }
    Pbkdf2Sha512(iterations) =>
      if iterations <= 0 {
        Err(InvalidInput)
      } else {
        Ok(@hash.pbkdf2_hmac_sha512(oprf_output, zero_salt, iterations, nh))
      }
    Argon2id(t_cost, m_cost_kib, parallelism) =>
      if t_cost < 1 || parallelism < 1 || m_cost_kib < 8 * parallelism {
        Err(InvalidInput)
      } else {
        Ok(
          @hash.argon2id(
            oprf_output, zero_salt, t_cost, m_cost_kib, parallelism, nh,
          ),
        )
      }
    Custom(stretch_fn) => Ok(stretch_fn(oprf_output))
  }
}

///|
fn validate_group_element(
  suite : CipherSuite,
  bytes : Bytes,
) -> Result[Unit, OpaqueError] {
  match suite {
    Ristretto255Sha512 =>
      match @ristretto255.Element::from_bytes(bytes) {
        None => Err(InvalidElement)
        Some(elem) =>
          if elem.is_identity() {
            Err(InvalidElement)
          } else {
            Ok(())
          }
      }
    P256Sha256 =>
      match @p256.Point::from_bytes_compressed(bytes) {
        None => Err(InvalidElement)
        Some(pt) => if pt.is_identity() { Err(InvalidElement) } else { Ok(()) }
      }
  }
}

///|
fn base_mul_public_key(
  suite : CipherSuite,
  sk_bytes : Bytes,
) -> Result[Bytes, OpaqueError] {
  match suite {
    Ristretto255Sha512 =>
      match @ristretto255.Scalar::from_bytes_canonical(sk_bytes) {
        None => Err(InvalidKey)
        Some(sk) =>
          if sk.is_zero() {
            Err(InvalidKey)
          } else {
            let pk = @ristretto255.Element::base_mul(sk)
            if pk.is_identity() {
              Err(InvalidKey)
            } else {
              Ok(pk.to_bytes())
            }
          }
      }
    P256Sha256 =>
      match @p256.Scalar::from_bytes_canonical(sk_bytes) {
        None => Err(InvalidKey)
        Some(sk) =>
          if sk.is_zero() {
            Err(InvalidKey)
          } else {
            let pk = @p256.Point::base_mul(sk)
            if pk.is_identity() {
              Err(InvalidKey)
            } else {
              Ok(pk.to_bytes_compressed())
            }
          }
      }
  }
}

///|
fn derive_oprf_key(
  suite : CipherSuite,
  oprf_seed : Bytes,
  credential_identifier : Bytes,
) -> Result[Bytes, OpaqueError] {
  let seed = match
    suite_hkdf_expand(
      suite,
      oprf_seed,
      @hash.concat_bytes([credential_identifier, b"OprfKey"]),
      suite_nok(suite),
    ) {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  match
    @oprf.derive_key_pair(suite_oprf(suite), seed, b"OPAQUE-DeriveKeyPair") {
    Ok((oprf_key, _)) => Ok(oprf_key)
    Err(e) => Err(map_oprf_error(e))
  }
}
