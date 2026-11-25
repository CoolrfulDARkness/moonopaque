///|
fn argon2_le32_bytes(v : Int32) -> Bytes {
  let buf = FixedArray::make(4, b'\x00')
  store_le32(buf, 0, v.reinterpret_as_uint())
  Bytes::makei(4, i => buf[i])
}

///|
/// RFC 9106 §3.3 variable-length hash function `H'(X, tau)`.
fn argon2_h_prime(input : Bytes, tau : Int32) -> Bytes {
  let tau_le = argon2_le32_bytes(tau)
  if tau <= 64 {
    return blake2b(concat_bytes([tau_le, input]), tau)
  }
  let r = (tau + 31) / 32 - 2
  let out = FixedArray::make(tau, b'\x00')
  let mut v = blake2b(concat_bytes([tau_le, input]), 64)
  for j in 0..<32 {
    out[j] = v[j]
  }
  let mut off = 32
  for _ in 2..<=r {
    v = blake2b(v, 64)
    for j in 0..<32 {
      out[off + j] = v[j]
    }
    off += 32
  }
  let rem = tau - 32 * r
  let last = blake2b(v, rem)
  for j in 0..<rem {
    out[off + j] = last[j]
  }
  Bytes::makei(tau, i => out[i])
}

///|
fn argon2_mul_add(a : UInt64, b : UInt64) -> UInt64 {
  let a_lo = a & 0xFFFFFFFFUL
  let b_lo = b & 0xFFFFFFFFUL
  a + b + ((a_lo * b_lo) << 1)
}

///|
fn argon2_gb(
  v : FixedArray[UInt64],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  v[a] = argon2_mul_add(v[a], v[b])
  v[d] = rotr64(v[d] ^ v[a], 32)
  v[c] = argon2_mul_add(v[c], v[d])
  v[b] = rotr64(v[b] ^ v[c], 24)
  v[a] = argon2_mul_add(v[a], v[b])
  v[d] = rotr64(v[d] ^ v[a], 16)
  v[c] = argon2_mul_add(v[c], v[d])
  v[b] = rotr64(v[b] ^ v[c], 63)
}

///|
/// RFC 9106 §3.6 Blake2b-like permutation `P` on 16 64-bit words.
fn argon2_perm_p(v : FixedArray[UInt64]) -> Unit {
  argon2_gb(v, 0, 4, 8, 12)
  argon2_gb(v, 1, 5, 9, 13)
  argon2_gb(v, 2, 6, 10, 14)
  argon2_gb(v, 3, 7, 11, 15)
  argon2_gb(v, 0, 5, 10, 15)
  argon2_gb(v, 1, 6, 11, 12)
  argon2_gb(v, 2, 7, 8, 13)
  argon2_gb(v, 3, 4, 9, 14)
}

///|
/// RFC 9106 §3.5 compression function `G(X, Y)`.
/// Reads 128 words from `x` at `x_off` and `y` at `y_off`, and writes result to
/// `dst` at `dst_off` (either overwriting or XORing when `with_xor` is true).
fn argon2_compress_g(
  x : FixedArray[UInt64],
  x_off : Int32,
  y : FixedArray[UInt64],
  y_off : Int32,
  dst : FixedArray[UInt64],
  dst_off : Int32,
  with_xor : Bool,
  r_buf : FixedArray[UInt64],
  q_buf : FixedArray[UInt64],
  p_buf : FixedArray[UInt64],
) -> Unit {
  for i in 0..<128 {
    let val = x[x_off + i] ^ y[y_off + i]
    r_buf[i] = val
    q_buf[i] = val
  }
  // Apply P row-wise (8 rows of 16 uint64 words)
  for row in 0..<8 {
    let base = row * 16
    for i in 0..<16 {
      p_buf[i] = q_buf[base + i]
    }
    argon2_perm_p(p_buf)
    for i in 0..<16 {
      q_buf[base + i] = p_buf[i]
    }
  }
  // Apply P column-wise (8 columns of 8 pairs of uint64 words)
  for col in 0..<8 {
    let c2 = col * 2
    for row in 0..<8 {
      let idx = row * 16 + c2
      p_buf[row * 2] = q_buf[idx]
      p_buf[row * 2 + 1] = q_buf[idx + 1]
    }
    argon2_perm_p(p_buf)
    for row in 0..<8 {
      let idx = row * 16 + c2
      q_buf[idx] = p_buf[row * 2]
      q_buf[idx + 1] = p_buf[row * 2 + 1]
    }
  }
  if with_xor {
    for i in 0..<128 {
      dst[dst_off + i] = dst[dst_off + i] ^ q_buf[i] ^ r_buf[i]
    }
  } else {
    for i in 0..<128 {
      dst[dst_off + i] = q_buf[i] ^ r_buf[i]
    }
  }
}

///|
fn argon2_next_addresses(
  address_block : FixedArray[UInt64],
  input_block : FixedArray[UInt64],
  zero_block : FixedArray[UInt64],
  tmp_block : FixedArray[UInt64],
  r_buf : FixedArray[UInt64],
  q_buf : FixedArray[UInt64],
  p_buf : FixedArray[UInt64],
) -> Unit {
  input_block[6] = input_block[6] + 1UL
  argon2_compress_g(
    zero_block, 0, input_block, 0, tmp_block, 0, false, r_buf, q_buf, p_buf,
  )
  argon2_compress_g(
    zero_block, 0, tmp_block, 0, address_block, 0, false, r_buf, q_buf, p_buf,
  )
}

///|
/// Full RFC 9106 Argon2id (version 0x13, type y = 2) supporting optional secret key
/// `secret` and associated data `associated_data`.
pub fn argon2id_full(
  password : Bytes,
  salt : Bytes,
  secret : Bytes,
  associated_data : Bytes,
  t_cost : Int32,
  m_cost_kib : Int32,
  parallelism : Int32,
  tag_len : Int32,
) -> Bytes {
  if parallelism < 1 ||
    t_cost < 1 ||
    tag_len < 4 ||
    m_cost_kib < 8 * parallelism {
    abort("argon2id: invalid parameters")
  }
  let p = parallelism
  let m_prime = 4 * p * (m_cost_kib / (4 * p))
  let q = m_prime / p
  let segment_length = q / 4

  // Step 1: Compute H_0 (64 bytes)
  let h0_input = concat_bytes([
    argon2_le32_bytes(p),
    argon2_le32_bytes(tag_len),
    argon2_le32_bytes(m_cost_kib),
    argon2_le32_bytes(t_cost),
    argon2_le32_bytes(0x13),
    argon2_le32_bytes(2),
    argon2_le32_bytes(password.length()),
    password,
    argon2_le32_bytes(salt.length()),
    salt,
    argon2_le32_bytes(secret.length()),
    secret,
    argon2_le32_bytes(associated_data.length()),
    associated_data,
  ])
  let h0 = blake2b(h0_input, 64)

  // Step 2: Allocate memory matrix B[p][q] (each block is 128 UInt64 words)
  let mem = FixedArray::make(m_prime * 128, 0UL)

  // Step 3: Initialize first two blocks of each lane
  for lane in 0..<p {
    let b0_bytes = argon2_h_prime(
      concat_bytes([h0, argon2_le32_bytes(0), argon2_le32_bytes(lane)]),
      1024,
    )
    let b0_off = lane * q * 128
    for w in 0..<128 {
      mem[b0_off + w] = load_le64_bytes(b0_bytes, w * 8)
    }
    let b1_bytes = argon2_h_prime(
      concat_bytes([h0, argon2_le32_bytes(1), argon2_le32_bytes(lane)]),
      1024,
    )
    let b1_off = (lane * q + 1) * 128
    for w in 0..<128 {
      mem[b1_off + w] = load_le64_bytes(b1_bytes, w * 8)
    }
  }

  // Reusable scratch buffers
  let r_buf = FixedArray::make(128, 0UL)
  let q_buf = FixedArray::make(128, 0UL)
  let p_buf = FixedArray::make(16, 0UL)
  let zero_block = FixedArray::make(128, 0UL)
  let input_block = FixedArray::make(128, 0UL)
  let address_block = FixedArray::make(128, 0UL)
  let tmp_block = FixedArray::make(128, 0UL)

  // Step 4: Fill memory passes
  for pass in 0..<t_cost {
    for slice in 0..<4 {
      let data_independent = pass == 0 && slice < 2
      for lane in 0..<p {
        let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 }
        if data_independent {
          for i in 0..<128 {
            input_block[i] = 0UL
          }
          input_block[0] = pass.to_uint64()
          input_block[1] = lane.to_uint64()
          input_block[2] = slice.to_uint64()
          input_block[3] = m_prime.to_uint64()
          input_block[4] = t_cost.to_uint64()
          input_block[5] = 2UL
          input_block[6] = 0UL
          if pass == 0 && slice == 0 {
            argon2_next_addresses(
              address_block, input_block, zero_block, tmp_block, r_buf, q_buf, p_buf,
            )
          }
        }
        let mut curr_offset = slice * segment_length + starting_index
        let mut prev_offset = if curr_offset == 0 {
          q - 1
        } else {
          curr_offset - 1
        }
        for index in starting_index..<segment_length {
          let pseudo_rand = if data_independent {
            if index % 128 == 0 {
              argon2_next_addresses(
                address_block, input_block, zero_block, tmp_block, r_buf, q_buf,
                p_buf,
              )
            }
            address_block[index % 128]
          } else {
            mem[(lane * q + prev_offset) * 128]
          }
          let j1 = pseudo_rand & 0xFFFFFFFFUL
          let j2 = pseudo_rand >> 32
          let ref_lane = if pass == 0 && slice == 0 {
            lane
          } else {
            (j2 % p.to_uint64()).to_int()
          }
          let ref_area_size = if pass == 0 {
            if slice == 0 {
              index - 1
            } else if ref_lane == lane {
              slice * segment_length + index - 1
            } else {
              slice * segment_length - (if index == 0 { 1 } else { 0 })
            }
          } else if ref_lane == lane {
            q - segment_length + index - 1
          } else {
            q - segment_length - (if index == 0 { 1 } else { 0 })
          }
          let x = (j1 * j1) >> 32
          let y = (ref_area_size.to_uint64() * x) >> 32
          let rel_pos = ref_area_size.to_uint64() - 1UL - y
          let start_pos = if pass == 0 || slice == 3 {
            0
          } else {
            (slice + 1) * segment_length
          }
          let ref_index = (start_pos + rel_pos.to_int()) % q
          argon2_compress_g(
            mem,
            (lane * q + prev_offset) * 128,
            mem,
            (ref_lane * q + ref_index) * 128,
            mem,
            (lane * q + curr_offset) * 128,
            pass > 0,
            r_buf,
            q_buf,
            p_buf,
          )
          prev_offset = curr_offset
          curr_offset += 1
        }
      }
    }
  }

  // Step 5: Finalize by XORing last column across all lanes
  let final_block = FixedArray::make(128, 0UL)
  for lane in 0..<p {
    let off = (lane * q + (q - 1)) * 128
    for w in 0..<128 {
      final_block[w] = final_block[w] ^ mem[off + w]
    }
  }
  let c_bytes = FixedArray::make(1024, b'\x00')
  for w in 0..<128 {
    store_le64(c_bytes, w * 8, final_block[w])
  }
  argon2_h_prime(Bytes::makei(1024, i => c_bytes[i]), tag_len)
}

///|
/// RFC 9106 Argon2id (version 0x13, type y = 2) with empty secret and associated data.
pub fn argon2id(
  password : Bytes,
  salt : Bytes,
  t_cost : Int32,
  m_cost_kib : Int32,
  parallelism : Int32,
  tag_len : Int32,
) -> Bytes {
  argon2id_full(
    password, salt, b"", b"", t_cost, m_cost_kib, parallelism, tag_len,
  )
}
