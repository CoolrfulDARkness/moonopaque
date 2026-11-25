///|
fn must_hex(hex : String) -> Bytes {
  match @hash.hex_decode(hex) {
    Some(b) => b
    None => abort("invalid hex literal in test vector")
  }
}

///|
fn flip_last_byte(b : Bytes) -> Bytes {
  let len = b.length()
  Bytes::makei(len, i => {
    if i == len - 1 {
      (b[i].to_uint() ^ 0x01U).to_byte()
    } else {
      b[i]
    }
  })
}

///|
fn run_real_vector(
  suite : @moonopaque.CipherSuite,
  context_hex : String,
  client_identity_hex : String?,
  server_identity_hex : String?,
  oprf_seed_hex : String,
  credential_identifier_hex : String,
  password_hex : String,
  envelope_nonce_hex : String,
  masking_nonce_hex : String,
  server_private_key_hex : String,
  server_public_key_hex : String,
  server_nonce_hex : String,
  client_nonce_hex : String,
  client_keyshare_seed_hex : String,
  server_keyshare_seed_hex : String,
  blind_registration_hex : String,
  blind_login_hex : String,
  expected_client_public_key_hex : String,
  expected_envelope_hex : String,
  expected_reg_req_hex : String,
  expected_reg_resp_hex : String,
  expected_reg_upload_hex : String,
  expected_ke1_hex : String,
  expected_ke2_hex : String,
  expected_ke3_hex : String,
  expected_export_key_hex : String,
  expected_session_key_hex : String,
) -> Unit raise {
  let config = @moonopaque.Config::new(suite, must_hex(context_hex), Identity)
  let client_identity = match client_identity_hex {
    None => None
    Some(h) => Some(must_hex(h))
  }
  let server_identity = match server_identity_hex {
    None => None
    Some(h) => Some(must_hex(h))
  }
  let server_setup = match
    @moonopaque.ServerSetup::from_keys(
      suite,
      must_hex(oprf_seed_hex),
      must_hex(server_private_key_hex),
      must_hex(server_public_key_hex),
    ) {
    Ok(s) => s
    Err(e) => fail("ServerSetup::from_keys failed: " + Show::to_string(e))
  }
  let password = must_hex(password_hex)
  let cred_id = must_hex(credential_identifier_hex)

  // --- Stage 1: Registration ---
  let (reg_state, reg_req) = match
    @moonopaque.create_registration_request(
      config,
      password,
      must_hex(blind_registration_hex),
    ) {
    Ok(v) => v
    Err(e) => fail("create_registration_request failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(reg_req.to_bytes()), expected_reg_req_hex)
  let reg_req_rt = match
    @moonopaque.RegistrationRequest::from_bytes(suite, reg_req.to_bytes()) {
    Ok(r) => r
    Err(e) =>
      fail("RegistrationRequest::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(reg_req_rt, reg_req)

  let reg_resp = match
    @moonopaque.create_registration_response(
      config, server_setup, reg_req_rt, cred_id,
    ) {
    Ok(v) => v
    Err(e) => fail("create_registration_response failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(reg_resp.to_bytes()), expected_reg_resp_hex)
  let reg_resp_rt = match
    @moonopaque.RegistrationResponse::from_bytes(suite, reg_resp.to_bytes()) {
    Ok(r) => r
    Err(e) =>
      fail("RegistrationResponse::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(reg_resp_rt, reg_resp)

  let (record, reg_export_key) = match
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp_rt,
      client_identity,
      server_identity,
      must_hex(envelope_nonce_hex),
    ) {
    Ok(v) => v
    Err(e) =>
      fail("finalize_registration_request failed: " + Show::to_string(e))
  }
  assert_eq(
    @hash.hex_encode(record.client_public_key()),
    expected_client_public_key_hex,
  )
  assert_eq(
    @hash.hex_encode(record.envelope().to_bytes()),
    expected_envelope_hex,
  )
  assert_eq(@hash.hex_encode(record.to_bytes()), expected_reg_upload_hex)
  assert_eq(@hash.hex_encode(reg_export_key), expected_export_key_hex)
  let record_rt = match
    @moonopaque.RegistrationRecord::from_bytes(suite, record.to_bytes()) {
    Ok(r) => r
    Err(e) =>
      fail("RegistrationRecord::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(record_rt, record)

  // --- Stage 2: Online AKE (3DH) ---
  let (client_login_state, ke1) = match
    @moonopaque.generate_ke1(
      config,
      password,
      must_hex(blind_login_hex),
      must_hex(client_nonce_hex),
      must_hex(client_keyshare_seed_hex),
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke1 failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(ke1.to_bytes()), expected_ke1_hex)
  let ke1_rt = match @moonopaque.KE1::from_bytes(suite, ke1.to_bytes()) {
    Ok(v) => v
    Err(e) => fail("KE1::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(ke1_rt, ke1)

  let (server_login_state, ke2) = match
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_identity,
      client_identity,
      record_rt,
      cred_id,
      ke1_rt,
      must_hex(masking_nonce_hex),
      must_hex(server_nonce_hex),
      must_hex(server_keyshare_seed_hex),
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke2 failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(ke2.to_bytes()), expected_ke2_hex)
  let ke2_rt = match @moonopaque.KE2::from_bytes(suite, ke2.to_bytes()) {
    Ok(v) => v
    Err(e) => fail("KE2::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(ke2_rt, ke2)

  let login_result = match
    @moonopaque.generate_ke3(
      config, client_login_state, client_identity, server_identity, ke2_rt,
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke3 failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(login_result.ke3().to_bytes()), expected_ke3_hex)
  assert_eq(
    @hash.hex_encode(login_result.export_key()),
    expected_export_key_hex,
  )
  assert_eq(
    @hash.hex_encode(login_result.session_key()),
    expected_session_key_hex,
  )
  assert_eq(login_result.export_key(), reg_export_key)
  let ke3_rt = match
    @moonopaque.KE3::from_bytes(suite, login_result.ke3().to_bytes()) {
    Ok(v) => v
    Err(e) => fail("KE3::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(ke3_rt, login_result.ke3())

  let server_session_key = match
    @moonopaque.server_finish(server_login_state, ke3_rt) {
    Ok(k) => k
    Err(e) => fail("server_finish failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(server_session_key), expected_session_key_hex)
  assert_eq(server_session_key, login_result.session_key())
}

///|
test "RFC 9807 C.1.1 Real Test Vector 1 (OPAQUE-Ristretto255-SHA512, default identities)" {
  run_real_vector(
    @moonopaque.CipherSuite::Ristretto255Sha512,
    "4f50415155452d504f43",
    None,
    None,
    "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef",
    "31323334",
    "436f7272656374486f72736542617474657279537461706c65",
    "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec",
    "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
    "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d",
    "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
    "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
    "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc",
    "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b",
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
    "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01",
    "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308",
    "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675",
    "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5",
    "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71",
    "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
    "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5",
    "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326",
    "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90",
    "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442",
    "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16",
    "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f",
  )
}

///|
test "RFC 9807 C.1.2 Real Test Vector 2 (OPAQUE-Ristretto255-SHA512, explicit identities)" {
  run_real_vector(
    @moonopaque.CipherSuite::Ristretto255Sha512,
    "4f50415155452d504f43",
    Some("616c696365"),
    Some("626f62"),
    "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef",
    "31323334",
    "436f7272656374486f72736542617474657279537461706c65",
    "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec",
    "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
    "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d",
    "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
    "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
    "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc",
    "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b",
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
    "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01",
    "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308",
    "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675",
    "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b680b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c",
    "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71",
    "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
    "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b680b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c",
    "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326",
    "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fea502150b67fe36795dd8914f164e49f81c7688a38928372134b7dccd50e09f8fed9518b7b2f94835b3c4fe4c8475e7513f20eb97ff0568a39caee3fd6251876f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a292371e7809a9031743e943fb3b56f51de903552fc91fba4e7419029951c3970b2e2f0a9dea218d22e9e4e0000855bb6421aa3610d6fc0f4033a6517030d4341",
    "7a026de1d6126905736c3f6d92463a08d209833eb793e46d0f7f15b3e0f62c7643763c02bbc6b8d3d15b63250cae98171e9260f1ffa789750f534ac11a0176d5",
    "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16",
    "ae7951123ab5befc27e62e63f52cf472d6236cb386c968cc47b7e34f866aa4bc7638356a73cfce92becf39d6a7d32a1861f12130e824241fe6cab34fbd471a57",
  )
}

///|
test "RFC 9807 C.1.5 Real Test Vector 5 (OPAQUE-P256-SHA256, default identities)" {
  run_real_vector(
    @moonopaque.CipherSuite::P256Sha256,
    "4f50415155452d504f43",
    None,
    None,
    "62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2",
    "31323334",
    "436f7272656374486f72736542617474657279537461706c65",
    "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f",
    "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
    "c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5",
    "035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874",
    "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
    "ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1",
    "633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc",
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
    "411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153",
    "c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1",
    "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214",
    "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8",
    "029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8",
    "0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874",
    "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8",
    "037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6",
    "0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b",
    "e97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e",
    "c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b",
    "484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1",
  )
}

///|
test "RFC 9807 C.1.6 Real Test Vector 6 (OPAQUE-P256-SHA256, explicit identities)" {
  run_real_vector(
    @moonopaque.CipherSuite::P256Sha256,
    "4f50415155452d504f43",
    Some("616c696365"),
    Some("626f62"),
    "62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2",
    "31323334",
    "436f7272656374486f72736542617474657279537461706c65",
    "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f",
    "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
    "c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5",
    "035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874",
    "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
    "ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1",
    "633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc",
    "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
    "411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153",
    "c497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1",
    "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214",
    "a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971",
    "029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8",
    "0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874",
    "03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f4d7773a36a208a866301dbb2858e40dc5638017527cf91aef32d3848eebe0971",
    "037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6",
    "0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae268d7f106042021c80300e4c6f585980cf39fc51a4a6bba41b0729f9b240c729e5671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b84922c7e5d074838a8f278592c53f61fb59f031e85ad480c0c71086b871e1b24",
    "46833578cee137775f6be3f01b80748daac5a694101ad0e9e7025480552da56a",
    "c3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b",
    "27766fabd8dd88ff37fbd0ef1a491e601d10d9f016c2b28c4bd1b0fb7511a3c3",
  )
}

///|
fn run_fake_vector(
  suite : @moonopaque.CipherSuite,
  context_hex : String,
  client_identity_hex : String,
  server_identity_hex : String,
  oprf_seed_hex : String,
  credential_identifier_hex : String,
  masking_nonce_hex : String,
  client_public_key_hex : String,
  server_private_key_hex : String,
  server_public_key_hex : String,
  server_nonce_hex : String,
  server_keyshare_seed_hex : String,
  masking_key_hex : String,
  ke1_hex : String,
  expected_ke2_hex : String,
) -> Unit raise {
  let config = @moonopaque.Config::new(suite, must_hex(context_hex), Identity)
  let client_id = Some(must_hex(client_identity_hex))
  let server_id = Some(must_hex(server_identity_hex))
  let server_setup = match
    @moonopaque.ServerSetup::from_keys(
      suite,
      must_hex(oprf_seed_hex),
      must_hex(server_private_key_hex),
      must_hex(server_public_key_hex),
    ) {
    Ok(s) => s
    Err(e) => fail("ServerSetup::from_keys failed: " + Show::to_string(e))
  }
  let ke1 = match @moonopaque.KE1::from_bytes(suite, must_hex(ke1_hex)) {
    Ok(v) => v
    Err(e) => fail("KE1::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(ke1.to_bytes()), ke1_hex)

  // RFC 9807 §6.3.2.2 & Appendix C.2: fake record has random client_public_key,
  // random masking_key, and all-zero envelope of length Nn + Nm.
  let fake_record = match
    @moonopaque.RegistrationRecord::new_fake(
      suite,
      must_hex(client_public_key_hex),
      must_hex(masking_key_hex),
    ) {
    Ok(r) => r
    Err(e) => fail("RegistrationRecord::new_fake failed: " + Show::to_string(e))
  }
  let (_, ke2) = match
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_id,
      client_id,
      fake_record,
      must_hex(credential_identifier_hex),
      ke1,
      must_hex(masking_nonce_hex),
      must_hex(server_nonce_hex),
      must_hex(server_keyshare_seed_hex),
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke2(fake) failed: " + Show::to_string(e))
  }
  assert_eq(@hash.hex_encode(ke2.to_bytes()), expected_ke2_hex)
  let ke2_rt = match @moonopaque.KE2::from_bytes(suite, ke2.to_bytes()) {
    Ok(v) => v
    Err(e) => fail("KE2::from_bytes failed: " + Show::to_string(e))
  }
  assert_eq(ke2_rt, ke2)

  // Also verify client safely rejects a fake KE2 generated via `generate_ke2_for_unknown_user`
  let (client_state, client_ke1) = match
    @moonopaque.generate_ke1_with_random(
      config,
      b"CorrectHorseBatteryStaple",
      Bytes::make(32, b'\x42'),
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke1_with_random failed: " + Show::to_string(e))
  }
  let (_, unknown_ke2) = match
    @moonopaque.generate_ke2_for_unknown_user(
      config,
      server_setup,
      server_id,
      client_id,
      must_hex(credential_identifier_hex),
      client_ke1,
      Bytes::make(32, b'\x99'),
    ) {
    Ok(v) => v
    Err(e) =>
      fail("generate_ke2_for_unknown_user failed: " + Show::to_string(e))
  }
  let res = @moonopaque.generate_ke3(
    config, client_state, client_id, server_id, unknown_ke2,
  )
  assert_true(
    res is Err(@moonopaque.OpaqueError::InvalidEnvelopeTag) ||
    res is Err(@moonopaque.OpaqueError::InvalidServerMac),
  )
}

///|
test "RFC 9807 C.2.1 Fake Test Vector 1 (OPAQUE-Ristretto255-SHA512)" {
  run_fake_vector(
    @moonopaque.CipherSuite::Ristretto255Sha512,
    "4f50415155452d504f43",
    "616c696365",
    "626f62",
    "743fc168d1f826ad43738933e5adb23da6fb95f95a1b069f0daa0522d0a78b617f701fc6aa46d3e7981e70de7765dfcd6b1e13e3369a582eb8dc456b10aa53b0",
    "31323334",
    "9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6",
    "84f43f9492e19c22d8bdaa4447cc3d4db1cdb5427a9f852c4707921212c36251",
    "c788585ae8b5ba2942b693b849be0c0426384e41977c18d2e81fbe30fd7c9f06",
    "825f832667480f08b0c9069da5083ac4d0e9ee31b49c4e0310031fea04d52966",
    "1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12",
    "360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2",
    "39ebd51f0e39a07a1c2d2431995b0399bca9996c5d10014d6ebab4453dc10ce5cef38ed3df6e56bfff40c2d8dd4671c2b4cf63c3d54860f31fe40220d690bb71",
    "b0a26dcaca2230b8f5e4b1bcab9c84b586140221bb8b2848486874b0be44890542d4e61ed3f8d64cdd3b9d153343eca15b9b0d5e388232793c6376bd2d9cfd0ab641d7f20a245a09f1d4dbb6e301661af7f352beb0791d055e48d3645232f77f",
    "928f79ad8df21963e91411b9f55165ba833dea918f441db967cdc09521d229259c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a632b5ab1bff96636144faa4f9f9afaac75dd88ea99cf5175902ae3f3b2195693f165f11929ba510a5978e64dcdabecbd7ee1e4380ce270e58fea58e6462d92964a1aaef72698bca1c673baeb04cc2bf7de5f3c2f5553464552d3a0f7698a9ca7f9c5e70c6cb1f706b2f175ab9d04bbd13926e816b6811a50b4aafa9799d5ed7971e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d1298251c5ba55f6b0b2d58d9ff0c88fe4176484be62a96db6e2a8c4d431bd1bf27fe6c1d0537603835217d42ebf7b2581982732e74892fd28211b31ed33863f0beaf75ba6f59474c0aaf9d78a60a9b2f4cd24d7ab54131b3c8efa192df6b72db4c",
  )
}

///|
test "RFC 9807 C.2.3 Fake Test Vector 3 (OPAQUE-P256-SHA256)" {
  run_fake_vector(
    @moonopaque.CipherSuite::P256Sha256,
    "4f50415155452d504f43",
    "616c696365",
    "626f62",
    "bb1cd59e16ac09bc0cb6d528541695d7eba2239b1613a3db3ade77b36280f725",
    "31323334",
    "9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6",
    "03b81708eae026a9370616c22e1e8542fe9dbebd36ce8a2661b708e9628f4a57fc",
    "34fbe7e830be1fe8d2187c97414e3826040cbe49b893b64229bab5e85a5888c7",
    "0221e034c0e202fe883dcfc96802a7624166fed4cfcab4ae30cf5f3290d01c88bf",
    "1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12",
    "360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2",
    "caecc6ccb4cae27cb54d8f3a1af1bac52a3d53107ce08497cdd362b1992e4e5e",
    "0396875da2b4f7749bba411513aea02dc514a48d169d8a9531bd61d3af3fa9baae42d4e61ed3f8d64cdd3b9d153343eca15b9b0d5e388232793c6376bd2d9cfd0a02147a6583983cc9973b5082db5f5070890cb373d70f7ac1b41ed2305361009784",
    "0201198dcd13f9792eb75dcfa815f61b049abfe2e3e9456d4bbbceec5f442efd049c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6facda65ce0a97b9085e7af07f61fd3fdd046d257cbf2183ce8766090b8041a8bf28d79dd4c9031ddc75bb6ddb4c291e639937840e3d39fc0d5a3d6e7723c09f7945df485bcf9aefe3fe82d149e84049e259bb5b33d6a2ff3b25e4bfb7eff0962821e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12023f82bbb24e75b8683fd13b843cd566efae996cd0016cffdcc24ee2bc937d026f80144878749a69565b433c1040aff67e94f79345de888a877422b9bbe21ec329",
  )
}

///|
fn run_e2e_flow(config : @moonopaque.Config) -> Unit raise {
  let suite = config.suite()
  let server_setup = match
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\x11')) {
    Ok(s) => s
    Err(e) => fail("ServerSetup::from_seed failed: " + Show::to_string(e))
  }
  let password = b"hunter2-super-secret"
  let cred_id = b"user-0001"
  let client_id = Some(b"alice@example.com")
  let server_id = Some(b"auth.example.com")

  let (reg_state, reg_req) = match
    @moonopaque.create_registration_request_with_random(
      config,
      password,
      Bytes::make(32, b'\x22'),
    ) {
    Ok(v) => v
    Err(e) =>
      fail("create_registration_request_with_random: " + Show::to_string(e))
  }
  let reg_resp = match
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, cred_id,
    ) {
    Ok(v) => v
    Err(e) => fail("create_registration_response: " + Show::to_string(e))
  }
  let (record, reg_export_key) = match
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp,
      client_id,
      server_id,
      Bytes::make(32, b'\x33'),
    ) {
    Ok(v) => v
    Err(e) => fail("finalize_registration_request: " + Show::to_string(e))
  }

  let (client_state, ke1) = match
    @moonopaque.generate_ke1_with_random(
      config,
      password,
      Bytes::make(32, b'\x44'),
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke1_with_random: " + Show::to_string(e))
  }
  let (server_state, ke2) = match
    @moonopaque.generate_ke2(
      config,
      server_setup,
      server_id,
      client_id,
      record,
      cred_id,
      ke1,
      Bytes::make(32, b'\x55'),
      Bytes::make(32, b'\x66'),
      Bytes::make(32, b'\x77'),
    ) {
    Ok(v) => v
    Err(e) => fail("generate_ke2: " + Show::to_string(e))
  }
  let login_res = match
    @moonopaque.generate_ke3(config, client_state, client_id, server_id, ke2) {
    Ok(v) => v
    Err(e) => fail("generate_ke3: " + Show::to_string(e))
  }
  let server_sk = match
    @moonopaque.server_finish(server_state, login_res.ke3()) {
    Ok(k) => k
    Err(e) => fail("server_finish: " + Show::to_string(e))
  }
  assert_eq(login_res.export_key(), reg_export_key)
  assert_eq(login_res.session_key(), server_sk)
}

///|
test "End-to-end OPAQUE-3DH with PBKDF2 and Argon2id KSF on both ciphersuites" {
  run_e2e_flow(
    @moonopaque.Config::ristretto255_sha512(
      context=b"app-v1",
      ksf=@moonopaque.Ksf::Pbkdf2Sha512(64),
    ),
  )
  run_e2e_flow(
    @moonopaque.Config::p256_sha256(
      context=b"app-v1",
      ksf=@moonopaque.Ksf::Pbkdf2Sha256(64),
    ),
  )
  run_e2e_flow(
    @moonopaque.Config::ristretto255_sha512(
      context=b"argon2-ristretto",
      ksf=@moonopaque.Ksf::Argon2id(1, 32, 1),
    ),
  )
  run_e2e_flow(
    @moonopaque.Config::p256_sha256(
      context=b"argon2-p256",
      ksf=@moonopaque.Ksf::Argon2id(1, 32, 1),
    ),
  )
  run_e2e_flow(
    @moonopaque.Config::p256_sha256(
      context=b"custom-ksf",
      ksf=@moonopaque.Ksf::Custom(x => @hash.sha256(x)),
    ),
  )
}

///|
test "Security checks: wrong password, tampered MACs, invalid elements & lengths" {
  let suite = @moonopaque.CipherSuite::Ristretto255Sha512
  let config = @moonopaque.Config::ristretto255_sha512(context=b"sec-test")
  let server_setup = match
    @moonopaque.ServerSetup::from_seed(suite, Bytes::make(32, b'\xaa')) {
    Ok(s) => s
    Err(e) => fail("from_seed failed: " + Show::to_string(e))
  }
  let cred_id = b"bob"
  let (reg_state, reg_req) = match
    @moonopaque.create_registration_request_with_random(
      config,
      b"right-password",
      Bytes::make(32, b'\x01'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let reg_resp = match
    @moonopaque.create_registration_response(
      config, server_setup, reg_req, cred_id,
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let (record, _) = match
    @moonopaque.finalize_registration_request(
      config,
      reg_state,
      reg_resp,
      None,
      None,
      Bytes::make(32, b'\x02'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }

  // 1. Wrong password -> InvalidEnvelopeTag
  let (wrong_client_state, wrong_ke1) = match
    @moonopaque.generate_ke1_with_random(
      config,
      b"wrong-password",
      Bytes::make(32, b'\x03'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let (_, wrong_ke2) = match
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      wrong_ke1,
      Bytes::make(32, b'\x04'),
      Bytes::make(32, b'\x05'),
      Bytes::make(32, b'\x06'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  assert_eq(
    @moonopaque.generate_ke3(config, wrong_client_state, None, None, wrong_ke2),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )

  // 2. Tampered KE2 server_mac -> InvalidServerMac
  let (ok_client_state, ok_ke1) = match
    @moonopaque.generate_ke1_with_random(
      config,
      b"right-password",
      Bytes::make(32, b'\x07'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let (ok_server_state, ok_ke2) = match
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      ok_ke1,
      Bytes::make(32, b'\x08'),
      Bytes::make(32, b'\x09'),
      Bytes::make(32, b'\x0a'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let bad_ke2_bytes = flip_last_byte(ok_ke2.to_bytes())
  let bad_ke2 = match @moonopaque.KE2::from_bytes(suite, bad_ke2_bytes) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  assert_eq(
    @moonopaque.generate_ke3(config, ok_client_state, None, None, bad_ke2),
    Err(@moonopaque.OpaqueError::InvalidServerMac),
  )

  // 3. Tampered KE3 client_mac -> InvalidClientMac
  let ok_login = match
    @moonopaque.generate_ke3(config, ok_client_state, None, None, ok_ke2) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let bad_ke3 = match
    @moonopaque.KE3::from_bytes(
      suite,
      flip_last_byte(ok_login.ke3().to_bytes()),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  assert_eq(
    @moonopaque.server_finish(ok_server_state, bad_ke3),
    Err(@moonopaque.OpaqueError::InvalidClientMac),
  )

  // 4. Identity element and invalid lengths rejected
  let zero_ristretto = Bytes::make(32, b'\x00')
  assert_eq(
    @moonopaque.RegistrationRequest::from_bytes(suite, zero_ristretto),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
  assert_eq(
    @moonopaque.RegistrationRequest::from_bytes(suite, b"\x01\x02\x03"),
    Err(@moonopaque.OpaqueError::InvalidMessageLength),
  )
  let zero_p256 = Bytes::make(33, b'\x00')
  assert_eq(
    @moonopaque.RegistrationRequest::from_bytes(
      @moonopaque.CipherSuite::P256Sha256,
      zero_p256,
    ),
    Err(@moonopaque.OpaqueError::InvalidElement),
  )
  assert_eq(
    @moonopaque.KE3::from_bytes(@moonopaque.CipherSuite::P256Sha256, b"\x00"),
    Err(@moonopaque.OpaqueError::InvalidMessageLength),
  )

  // 5. Wrong identity rejected with InvalidEnvelopeTag
  let (id_client_state, id_ke1) = match
    @moonopaque.generate_ke1_with_random(
      config,
      b"right-password",
      Bytes::make(32, b'\x0b'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let (_, id_ke2) = match
    @moonopaque.generate_ke2(
      config,
      server_setup,
      None,
      None,
      record,
      cred_id,
      id_ke1,
      Bytes::make(32, b'\x0c'),
      Bytes::make(32, b'\x0d'),
      Bytes::make(32, b'\x0e'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      id_client_state,
      Some(b"wrong-client-id"),
      None,
      id_ke2,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )

  // 6. ServerSetup::from_keys rejects mismatched keypair
  let (sk2, pk2) = match
    @moonopaque.derive_dh_keypair(suite, Bytes::make(32, b'\x77')) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  assert_eq(
    @moonopaque.ServerSetup::from_keys(
      suite,
      Bytes::make(64, b'\x11'),
      sk2,
      server_setup.server_public_key(),
    ),
    Err(@moonopaque.OpaqueError::InvalidKey),
  )
  assert_true(
    @moonopaque.ServerSetup::from_keys(
      suite,
      Bytes::make(64, b'\x11'),
      sk2,
      pk2,
    )
    is Ok(_),
  )

  // 7. Direct generate_ke2_fake produces valid wire KE2 that client rejects
  let (fk_client_state, fk_ke1) = match
    @moonopaque.generate_ke1_with_random(
      config,
      b"any-password",
      Bytes::make(32, b'\x51'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  let (_, fk_ke2) = match
    @moonopaque.generate_ke2_fake(
      config,
      server_setup,
      Some(b"server"),
      Some(b"ghost"),
      b"ghost-cred",
      fk_ke1,
      Bytes::make(32, b'\x52'),
      Bytes::make(32, b'\x53'),
      Bytes::make(32, b'\x54'),
      Bytes::make(32, b'\x55'),
      Bytes::make(64, b'\x56'),
      Bytes::make(32, b'\x00'),
      Bytes::make(64, b'\x00'),
    ) {
    Ok(v) => v
    Err(e) => fail(Show::to_string(e))
  }
  assert_eq(
    @moonopaque.generate_ke3(
      config,
      fk_client_state,
      Some(b"ghost"),
      Some(b"server"),
      fk_ke2,
    ),
    Err(@moonopaque.OpaqueError::InvalidEnvelopeTag),
  )
}
