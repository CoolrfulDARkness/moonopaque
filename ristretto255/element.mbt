///|
/// Opaque element of the RFC 9496 ristretto255 prime-order group, internally
/// represented in Ed25519 extended homogeneous Edwards coordinates (x, y, z, t)
/// where x/z and y/z lie on -x^2 + y^2 = 1 + d*x^2*y^2 and t = x*y/z.
pub struct Element {
  priv x : FieldElement
  priv y : FieldElement
  priv z : FieldElement
  priv t : FieldElement
}

///|
/// Canonical generator internal representation: the Ed25519 base point B.
let base_x : FieldElement = {
  h0: 52811034L,
  h1: 25909283L,
  h2: 16144682L,
  h3: 17082669L,
  h4: 27570973L,
  h5: 30858332L,
  h6: 40966398L,
  h7: 8378388L,
  h8: 20764389L,
  h9: 8758491L,
}

///|
let base_y : FieldElement = {
  h0: 40265304L,
  h1: 26843545L,
  h2: 13421772L,
  h3: 20132659L,
  h4: 26843545L,
  h5: 6710886L,
  h6: 53687091L,
  h7: 13421772L,
  h8: 40265318L,
  h9: 26843545L,
}

///|
let base_t : FieldElement = {
  h0: 28827043L,
  h1: 27438313L,
  h2: 39759291L,
  h3: 244362L,
  h4: 8635006L,
  h5: 11264893L,
  h6: 19351346L,
  h7: 13413597L,
  h8: 16611511L,
  h9: 27139452L,
}

///|
/// Return the identity element of ristretto255.
pub fn Element::identity() -> Element {
  {
    x: FieldElement::zero(),
    y: FieldElement::one(),
    z: FieldElement::one(),
    t: FieldElement::zero(),
  }
}

///|
/// Return the canonical generator of ristretto255 (RFC 9496 Section 4).
pub fn Element::generator() -> Element {
  { x: base_x, y: base_y, z: FieldElement::one(), t: base_t, }
}

///|
/// RFC 9496 Section 4.3.1: Decode a 32-byte canonical ristretto255 encoding.
/// Rejects wrong length, non-canonical field elements, negative s, non-square
/// ratio, negative t, or y == 0.
pub fn Element::from_bytes(bytes : Bytes) -> Element? {
  if bytes.length() != 32 {
    return None
  }
  let (is_canonical, s) = FieldElement::from_bytes_canonical(bytes)
  if is_canonical == 0L || s.is_negative() == 1L {
    return None
  }
  let one = FieldElement::one()
  let ss = s.square()
  let u1 = one.sub(ss)
  let u2 = one.add(ss)
  let u2_sqr = u2.square()
  let v = fe_d.mul(u1.square()).neg().sub(u2_sqr)
  let (was_square, invsqrt) = sqrt_ratio_m1(one, v.mul(u2_sqr))
  let den_x = invsqrt.mul(u2)
  let den_y = invsqrt.mul(den_x).mul(v)
  let x = s.add(s).mul(den_x).ct_abs()
  let y = u1.mul(den_y)
  let t = x.mul(y)
  let invalid = (1L - was_square) | t.is_negative() | y.ct_is_zero()
  if invalid != 0L {
    return None
  }
  Some({ x, y, z: one, t, })
}

///|
/// RFC 9496 Section 4.3.2: Encode a ristretto255 group element into 32 canonical bytes.
pub fn Element::to_bytes(self : Element) -> Bytes {
  let x0 = self.x
  let y0 = self.y
  let z0 = self.z
  let t0 = self.t
  let u1 = z0.add(y0).mul(z0.sub(y0))
  let u2 = x0.mul(y0)
  let (_, invsqrt) = sqrt_ratio_m1(FieldElement::one(), u1.mul(u2.square()))
  let den1 = invsqrt.mul(u1)
  let den2 = invsqrt.mul(u2)
  let z_inv = den1.mul(den2).mul(t0)
  let ix0 = x0.mul(fe_sqrt_m1)
  let iy0 = y0.mul(fe_sqrt_m1)
  let enchanted_denominator = den1.mul(fe_invsqrt_a_minus_d)
  let rotate = t0.mul(z_inv).is_negative()
  let x = FieldElement::ct_select(x0, iy0, rotate)
  let y1 = FieldElement::ct_select(y0, ix0, rotate)
  let z = z0
  let den_inv = FieldElement::ct_select(den2, enchanted_denominator, rotate)
  let y = FieldElement::ct_select(y1, y1.neg(), x.mul(z_inv).is_negative())
  let s = den_inv.mul(z.sub(y)).ct_abs()
  s.to_bytes()
}

///|
/// RFC 9496 Section 4.3.4: MAP helper mapping a 32-byte slice at `offset` to an Element.
fn map_to_element(bytes : Bytes, offset : Int32) -> Element {
  let one = FieldElement::one()
  let t = FieldElement::from_bytes_masked_at(bytes, offset)
  let r = fe_sqrt_m1.mul(t.square())
  let u = r.add(one).mul(fe_one_minus_d_sq)
  let v = fe_minus_one.sub(r.mul(fe_d)).mul(r.add(fe_d))
  let (was_square, s0) = sqrt_ratio_m1(u, v)
  let s_prime = s0.mul(t).ct_abs().neg()
  let s = FieldElement::ct_select(s_prime, s0, was_square)
  let c = FieldElement::ct_select(r, fe_minus_one, was_square)
  let n_val = c.mul(r.sub(one)).mul(fe_d_minus_one_sq).sub(v)
  let s_sq = s.square()
  let w0 = s.add(s).mul(v)
  let w1 = n_val.mul(fe_sqrt_ad_minus_one)
  let w2 = one.sub(s_sq)
  let w3 = one.add(s_sq)
  { x: w0.mul(w3), y: w2.mul(w1), z: w1.mul(w3), t: w0.mul(w2), }
}

///|
/// RFC 9496 Section 4.3.4: Derive a ristretto255 element from 64 uniform bytes.
/// Returns None if `bytes.length() != 64`.
pub fn Element::from_uniform_bytes(bytes : Bytes) -> Element? {
  if bytes.length() != 64 {
    return None
  }
  let p1 = map_to_element(bytes, 0)
  let p2 = map_to_element(bytes, 32)
  Some(p1.add(p2))
}

///|
/// RFC 9496 Section 4.3.3: Constant-time group element equality.
pub fn Element::equal(self : Element, other : Element) -> Bool {
  let c1 = self.x.mul(other.y).ct_eq(self.y.mul(other.x))
  let c2 = self.y.mul(other.y).ct_eq(self.x.mul(other.x))
  (c1 | c2) == 1L
}

///|
pub impl Eq for Element with fn equal(self, other) {
  self.equal(other)
}

///|
/// Constant-time identity check (matches all equivalent internal representations).
pub fn Element::is_identity(self : Element) -> Bool {
  self.equal(Element::identity())
}

///|
/// Complete unified twisted Edwards point addition (a = -1).
pub fn Element::add(self : Element, other : Element) -> Element {
  let a = self.y.sub(self.x).mul(other.y.sub(other.x))
  let b = self.y.add(self.x).mul(other.y.add(other.x))
  let c = self.t.mul(fe_two_d).mul(other.t)
  let zz = self.z.mul(other.z)
  let d = zz.add(zz)
  let e = b.sub(a)
  let f = d.sub(c)
  let g = d.add(c)
  let h = b.add(a)
  { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h), }
}

///|
/// Twisted Edwards point doubling (a = -1).
fn Element::double(self : Element) -> Element {
  let a = self.x.square()
  let b = self.y.square()
  let zz = self.z.square()
  let c = zz.add(zz)
  let h = a.add(b)
  let e = h.sub(self.x.add(self.y).square())
  let g = a.sub(b)
  let f = c.add(g)
  { x: e.mul(f), y: g.mul(h), z: f.mul(g), t: e.mul(h), }
}

///|
/// Group element negation: -(x, y, z, t) = (-x, y, z, -t).
pub fn Element::neg(self : Element) -> Element {
  { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg(), }
}

///|
/// Group element subtraction: self - other.
pub fn Element::sub(self : Element, other : Element) -> Element {
  self.add(other.neg())
}

///|
/// Constant-time conditional swap of two Elements when `cond == 1L`.
fn element_ct_swap(
  a : Element,
  b : Element,
  cond : Int64,
) -> (Element, Element) {
  let new_a = {
    x: FieldElement::ct_select(a.x, b.x, cond),
    y: FieldElement::ct_select(a.y, b.y, cond),
    z: FieldElement::ct_select(a.z, b.z, cond),
    t: FieldElement::ct_select(a.t, b.t, cond),
  }
  let new_b = {
    x: FieldElement::ct_select(b.x, a.x, cond),
    y: FieldElement::ct_select(b.y, a.y, cond),
    z: FieldElement::ct_select(b.z, a.z, cond),
    t: FieldElement::ct_select(b.t, a.t, cond),
  }
  (new_a, new_b)
}

///|
/// Constant-time 256-step Montgomery ladder scalar multiplication (no secret-dependent branches).
pub fn Element::scalar_mul(self : Element, s : Scalar) -> Element {
  let mut r0 = Element::identity()
  let mut r1 = self
  for i = 255; i >= 0; i = i - 1 {
    let bit = s.bit(i)
    let (s0, s1) = element_ct_swap(r0, r1, bit)
    let sum = s0.add(s1)
    let dbl = s0.double()
    let (n0, n1) = element_ct_swap(dbl, sum, bit)
    r0 = n0
    r1 = n1
  }
  r0
}

///|
/// Constant-time basepoint scalar multiplication: s * G.
pub fn Element::base_mul(s : Scalar) -> Element {
  Element::generator().scalar_mul(s)
}
