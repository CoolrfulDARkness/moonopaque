///|
/// Supported IETF RFC 9497 Base OPRF (mode 0x00) ciphersuites.
#derive(Eq, Debug)
pub(all) enum OprfSuite {
  Ristretto255Sha512
  P256Sha256
}

///|
pub impl Show for OprfSuite with fn output(self, logger) {
  match self {
    Ristretto255Sha512 => logger.write_string("Ristretto255Sha512")
    P256Sha256 => logger.write_string("P256Sha256")
  }
}

///|
/// Error cases produced by RFC 9497 OPRF operations.
#derive(Eq, Debug)
pub(all) enum OprfError {
  InvalidInput
  InvalidElement
  InvalidScalar
  ZeroScalar
  DeriveKeyPairFailed
}

///|
pub impl Show for OprfError with fn output(self, logger) {
  match self {
    InvalidInput => logger.write_string("InvalidInput")
    InvalidElement => logger.write_string("InvalidElement")
    InvalidScalar => logger.write_string("InvalidScalar")
    ZeroScalar => logger.write_string("ZeroScalar")
    DeriveKeyPairFailed => logger.write_string("DeriveKeyPairFailed")
  }
}

///|
/// Client blinding state holding the ciphersuite and serialized non-zero blind scalar.
pub struct BlindState {
  priv suite : OprfSuite
  priv blind : Bytes
}

///|
/// Returns the ciphersuite associated with this blinding state.
pub fn BlindState::suite(self : BlindState) -> OprfSuite {
  self.suite
}

///|
/// Returns the serialized blind scalar bytes.
pub fn BlindState::blind_bytes(self : BlindState) -> Bytes {
  self.blind
}

///|
/// Maximum byte length of `PrivateInput` and `PublicInput` (RFC 9497 §5.1).
let max_input_len : Int32 = 65535

///|
/// Serialized group element length `Ne` in bytes (RFC 9497 §4).
pub fn element_len(suite : OprfSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 32
    P256Sha256 => 33
  }
}

///|
/// Serialized scalar length `Ns` in bytes (RFC 9497 §4).
pub fn scalar_len(suite : OprfSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 32
    P256Sha256 => 32
  }
}

///|
/// Hash / OPRF output length `Nh` in bytes (RFC 9497 §4).
pub fn output_len(suite : OprfSuite) -> Int32 {
  match suite {
    Ristretto255Sha512 => 64
    P256Sha256 => 32
  }
}

///|
/// Base OPRF (mode 0x00) context string `CreateContextString(0x00, identifier)` (RFC 9497 §3.1).
pub fn context_string(suite : OprfSuite) -> Bytes {
  match suite {
    Ristretto255Sha512 => b"OPRFV1-\x00-ristretto255-SHA512"
    P256Sha256 => b"OPRFV1-\x00-P256-SHA256"
  }
}

///|
fn suite_hash(suite : OprfSuite, msg : Bytes) -> Bytes {
  match suite {
    Ristretto255Sha512 => @hash.sha512(msg)
    P256Sha256 => @hash.sha256(msg)
  }
}

///|
fn finalize_hash(
  suite : OprfSuite,
  input : Bytes,
  serialized_element : Bytes,
) -> Bytes {
  let hash_input = @hash.concat_bytes([
    @hash.i2osp(input.length(), 2),
    input,
    @hash.i2osp(serialized_element.length(), 2),
    serialized_element,
    b"Finalize",
  ])
  suite_hash(suite, hash_input)
}

///|
fn hash_to_group_dst(suite : OprfSuite) -> Bytes {
  @hash.concat_bytes([b"HashToGroup-", context_string(suite)])
}

///|
fn hash_to_ristretto_element(
  msg : Bytes,
  dst : Bytes,
) -> Result[@ristretto255.Element, OprfError] {
  let uniform = @hash.expand_message_xmd_sha512(msg, dst, 64)
  match @ristretto255.Element::from_uniform_bytes(uniform) {
    Some(elem) => Ok(elem)
    None => Err(InvalidElement)
  }
}

///|
fn hash_to_p256_point(
  msg : Bytes,
  dst : Bytes,
) -> Result[@p256.Point, OprfError] {
  let uniform = @hash.expand_message_xmd_sha256(msg, dst, 96)
  match @p256.Point::hash_to_curve_from_uniform(uniform) {
    Some(pt) => Ok(pt)
    None => Err(InvalidElement)
  }
}

///|
fn hash_to_ristretto_scalar(
  msg : Bytes,
  dst : Bytes,
) -> Result[@ristretto255.Scalar, OprfError] {
  let uniform = @hash.expand_message_xmd_sha512(msg, dst, 64)
  match @ristretto255.Scalar::from_bytes_wide(uniform) {
    Some(s) => Ok(s)
    None => Err(InvalidScalar)
  }
}

///|
fn hash_to_p256_scalar(
  msg : Bytes,
  dst : Bytes,
) -> Result[@p256.Scalar, OprfError] {
  let uniform = @hash.expand_message_xmd_sha256(msg, dst, 48)
  match @p256.Scalar::from_bytes_be_mod_n(uniform) {
    Some(s) => Ok(s)
    None => Err(InvalidScalar)
  }
}

///|
fn parse_nonzero_ristretto_scalar(
  bytes : Bytes,
) -> Result[@ristretto255.Scalar, OprfError] {
  match @ristretto255.Scalar::from_bytes_canonical(bytes) {
    None => Err(InvalidScalar)
    Some(s) => if s.is_zero() { Err(ZeroScalar) } else { Ok(s) }
  }
}

///|
fn parse_nonzero_p256_scalar(bytes : Bytes) -> Result[@p256.Scalar, OprfError] {
  match @p256.Scalar::from_bytes_canonical(bytes) {
    None => Err(InvalidScalar)
    Some(s) => if s.is_zero() { Err(ZeroScalar) } else { Ok(s) }
  }
}

///|
fn parse_nonidentity_ristretto_element(
  bytes : Bytes,
) -> Result[@ristretto255.Element, OprfError] {
  match @ristretto255.Element::from_bytes(bytes) {
    None => Err(InvalidElement)
    Some(e) => if e.is_identity() { Err(InvalidElement) } else { Ok(e) }
  }
}

///|
fn parse_nonidentity_p256_point(
  bytes : Bytes,
) -> Result[@p256.Point, OprfError] {
  match @p256.Point::from_bytes_compressed(bytes) {
    None => Err(InvalidElement)
    Some(p) => if p.is_identity() { Err(InvalidElement) } else { Ok(p) }
  }
}

///|
/// RFC 9497 §4 `HashToGroup(msg, dst)` returning the serialized group element.
pub fn hash_to_group(
  suite : OprfSuite,
  msg : Bytes,
  dst : Bytes,
) -> Result[Bytes, OprfError] {
  match suite {
    Ristretto255Sha512 =>
      match hash_to_ristretto_element(msg, dst) {
        Ok(elem) => Ok(elem.to_bytes())
        Err(e) => Err(e)
      }
    P256Sha256 =>
      match hash_to_p256_point(msg, dst) {
        Ok(pt) => Ok(pt.to_bytes_compressed())
        Err(e) => Err(e)
      }
  }
}

///|
/// RFC 9497 §4 `HashToScalar(msg, dst)` returning the canonical serialized scalar.
pub fn hash_to_scalar(
  suite : OprfSuite,
  msg : Bytes,
  dst : Bytes,
) -> Result[Bytes, OprfError] {
  match suite {
    Ristretto255Sha512 =>
      match hash_to_ristretto_scalar(msg, dst) {
        Ok(s) => Ok(s.to_bytes())
        Err(e) => Err(e)
      }
    P256Sha256 =>
      match hash_to_p256_scalar(msg, dst) {
        Ok(s) => Ok(s.to_bytes())
        Err(e) => Err(e)
      }
  }
}

///|
/// RFC 9497 §3.2.1 deterministic server key-pair derivation `DeriveKeyPair(seed, info)`.
/// Returns `(skS, pkS)` serialized according to the ciphersuite.
pub fn derive_key_pair(
  suite : OprfSuite,
  seed : Bytes,
  info : Bytes,
) -> Result[(Bytes, Bytes), OprfError] {
  if info.length() > max_input_len {
    return Err(InvalidInput)
  }
  let derive_input = @hash.concat_bytes([
    seed,
    @hash.i2osp(info.length(), 2),
    info,
  ])
  let dst = @hash.concat_bytes([b"DeriveKeyPair", context_string(suite)])
  match suite {
    Ristretto255Sha512 => {
      for counter in 0..<=255 {
        let msg = @hash.concat_bytes([derive_input, @hash.i2osp(counter, 1)])
        let sk = match hash_to_ristretto_scalar(msg, dst) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        if !sk.is_zero() {
          let pk = @ristretto255.Element::base_mul(sk)
          return Ok((sk.to_bytes(), pk.to_bytes()))
        }
      }
      Err(DeriveKeyPairFailed)
    }
    P256Sha256 => {
      for counter in 0..<=255 {
        let msg = @hash.concat_bytes([derive_input, @hash.i2osp(counter, 1)])
        let sk = match hash_to_p256_scalar(msg, dst) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        if !sk.is_zero() {
          let pk = @p256.Point::base_mul(sk)
          return Ok((sk.to_bytes(), pk.to_bytes_compressed()))
        }
      }
      Err(DeriveKeyPairFailed)
    }
  }
}

///|
/// RFC 9497 §3.3.1 `Blind(input)` with a caller-supplied canonical non-zero blind scalar.
pub fn blind_with_scalar(
  suite : OprfSuite,
  input : Bytes,
  blind_scalar : Bytes,
) -> Result[(BlindState, Bytes), OprfError] {
  if input.length() > max_input_len {
    return Err(InvalidInput)
  }
  let dst = hash_to_group_dst(suite)
  match suite {
    Ristretto255Sha512 => {
      let blind = match parse_nonzero_ristretto_scalar(blind_scalar) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let input_elem = match hash_to_ristretto_element(input, dst) {
        Ok(elem) => elem
        Err(_) => return Err(InvalidInput)
      }
      if input_elem.is_identity() {
        return Err(InvalidInput)
      }
      let blinded = input_elem.scalar_mul(blind)
      let state : BlindState = { suite, blind: blind.to_bytes(), }
      Ok((state, blinded.to_bytes()))
    }
    P256Sha256 => {
      let blind = match parse_nonzero_p256_scalar(blind_scalar) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let input_pt = match hash_to_p256_point(input, dst) {
        Ok(pt) => pt
        Err(_) => return Err(InvalidInput)
      }
      if input_pt.is_identity() {
        return Err(InvalidInput)
      }
      let blinded = input_pt.scalar_mul(blind)
      let state : BlindState = { suite, blind: blind.to_bytes(), }
      Ok((state, blinded.to_bytes_compressed()))
    }
  }
}

///|
/// RFC 9497 §3.3.1 `Blind(input)` deriving a non-zero blind scalar from `random_bytes`
/// via `HashToScalar(random_bytes, "RandomScalar-" || contextString)`, retrying with an
/// appended counter byte if the derived scalar is zero.
pub fn blind_from_random_bytes(
  suite : OprfSuite,
  input : Bytes,
  random_bytes : Bytes,
) -> Result[(BlindState, Bytes), OprfError] {
  if input.length() > max_input_len {
    return Err(InvalidInput)
  }
  let dst = @hash.concat_bytes([b"RandomScalar-", context_string(suite)])
  match suite {
    Ristretto255Sha512 => {
      let first = match hash_to_ristretto_scalar(random_bytes, dst) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      if !first.is_zero() {
        return blind_with_scalar(suite, input, first.to_bytes())
      }
      for counter in 0..<=255 {
        let msg = @hash.concat_bytes([random_bytes, @hash.i2osp(counter, 1)])
        let cand = match hash_to_ristretto_scalar(msg, dst) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        if !cand.is_zero() {
          return blind_with_scalar(suite, input, cand.to_bytes())
        }
      }
      Err(ZeroScalar)
    }
    P256Sha256 => {
      let first = match hash_to_p256_scalar(random_bytes, dst) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      if !first.is_zero() {
        return blind_with_scalar(suite, input, first.to_bytes())
      }
      for counter in 0..<=255 {
        let msg = @hash.concat_bytes([random_bytes, @hash.i2osp(counter, 1)])
        let cand = match hash_to_p256_scalar(msg, dst) {
          Ok(s) => s
          Err(e) => return Err(e)
        }
        if !cand.is_zero() {
          return blind_with_scalar(suite, input, cand.to_bytes())
        }
      }
      Err(ZeroScalar)
    }
  }
}

///|
/// RFC 9497 §3.3.1 server `BlindEvaluate(skS, blindedElement)`.
/// Strictly validates that `sk_s` is canonical and non-zero and that `blinded_element`
/// decodes to a valid non-identity group element.
pub fn blind_evaluate(
  suite : OprfSuite,
  sk_s : Bytes,
  blinded_element : Bytes,
) -> Result[Bytes, OprfError] {
  match suite {
    Ristretto255Sha512 => {
      let sk = match parse_nonzero_ristretto_scalar(sk_s) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let elem = match parse_nonidentity_ristretto_element(blinded_element) {
        Ok(e) => e
        Err(e) => return Err(e)
      }
      let evaluated = elem.scalar_mul(sk)
      if evaluated.is_identity() {
        return Err(InvalidElement)
      }
      Ok(evaluated.to_bytes())
    }
    P256Sha256 => {
      let sk = match parse_nonzero_p256_scalar(sk_s) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let pt = match parse_nonidentity_p256_point(blinded_element) {
        Ok(p) => p
        Err(e) => return Err(e)
      }
      let evaluated = pt.scalar_mul(sk)
      if evaluated.is_identity() {
        return Err(InvalidElement)
      }
      Ok(evaluated.to_bytes_compressed())
    }
  }
}

///|
/// RFC 9497 §3.3.1 client `Finalize(input, blind, evaluatedElement)`.
/// Strictly validates that `evaluated_element` decodes to a valid non-identity element.
pub fn finalize(
  state : BlindState,
  input : Bytes,
  evaluated_element : Bytes,
) -> Result[Bytes, OprfError] {
  if input.length() > max_input_len {
    return Err(InvalidInput)
  }
  match state.suite {
    Ristretto255Sha512 => {
      let blind = match parse_nonzero_ristretto_scalar(state.blind) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let blind_inv = match blind.invert() {
        Some(inv) => inv
        None => return Err(ZeroScalar)
      }
      let eval_elem = match
        parse_nonidentity_ristretto_element(evaluated_element) {
        Ok(e) => e
        Err(e) => return Err(e)
      }
      let unblinded = eval_elem.scalar_mul(blind_inv)
      if unblinded.is_identity() {
        return Err(InvalidElement)
      }
      Ok(finalize_hash(state.suite, input, unblinded.to_bytes()))
    }
    P256Sha256 => {
      let blind = match parse_nonzero_p256_scalar(state.blind) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let blind_inv = match blind.invert() {
        Some(inv) => inv
        None => return Err(ZeroScalar)
      }
      let eval_pt = match parse_nonidentity_p256_point(evaluated_element) {
        Ok(p) => p
        Err(e) => return Err(e)
      }
      let unblinded = eval_pt.scalar_mul(blind_inv)
      if unblinded.is_identity() {
        return Err(InvalidElement)
      }
      Ok(finalize_hash(state.suite, input, unblinded.to_bytes_compressed()))
    }
  }
}

///|
/// RFC 9497 §3.3.1 server direct `Evaluate(skS, input)`.
pub fn evaluate(
  suite : OprfSuite,
  sk_s : Bytes,
  input : Bytes,
) -> Result[Bytes, OprfError] {
  if input.length() > max_input_len {
    return Err(InvalidInput)
  }
  let dst = hash_to_group_dst(suite)
  match suite {
    Ristretto255Sha512 => {
      let sk = match parse_nonzero_ristretto_scalar(sk_s) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let input_elem = match hash_to_ristretto_element(input, dst) {
        Ok(elem) => elem
        Err(_) => return Err(InvalidInput)
      }
      if input_elem.is_identity() {
        return Err(InvalidInput)
      }
      let evaluated = input_elem.scalar_mul(sk)
      if evaluated.is_identity() {
        return Err(InvalidElement)
      }
      Ok(finalize_hash(suite, input, evaluated.to_bytes()))
    }
    P256Sha256 => {
      let sk = match parse_nonzero_p256_scalar(sk_s) {
        Ok(s) => s
        Err(e) => return Err(e)
      }
      let input_pt = match hash_to_p256_point(input, dst) {
        Ok(pt) => pt
        Err(_) => return Err(InvalidInput)
      }
      if input_pt.is_identity() {
        return Err(InvalidInput)
      }
      let evaluated = input_pt.scalar_mul(sk)
      if evaluated.is_identity() {
        return Err(InvalidElement)
      }
      Ok(finalize_hash(suite, input, evaluated.to_bytes_compressed()))
    }
  }
}
