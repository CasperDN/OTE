use crypto_bigint::{modular, rand_core::OsRng, NonZero, RandomMod, Uint, U512};
use crypto_primes;
use modular::runtime_mod::{DynResidue, DynResidueParams};
use rand::random;

pub type USIZE = U512;
const SECURITY: usize = 512; // Larger security is extremely slow
const DYN_RES: usize = 8; // 8*WORD_SIZE(64) = 512
type GroupElem = DynResidue<DYN_RES>;
pub type PublicKey = GroupElem;
pub type OTParams = Vec<((GroupElem, GroupElem), (GroupElem, GroupElem))>;

#[derive(Clone)]
pub struct SafePrimeGroup {
    g: USIZE,
    p: USIZE,
    q: USIZE,
}

pub fn make_group() -> SafePrimeGroup {
    let p = crypto_primes::generate_safe_prime(Some(SECURITY));
    let q = (p.wrapping_sub(&USIZE::from(1u32))).wrapping_div(&USIZE::from(2u32)); // Should never wrap, but Rust doesn't know that.
    let g = get_generator(&p);
    return SafePrimeGroup { g, p, q };
}

// Choose the real and oblivious keys to send to Bob.
pub fn commit_choice(
    group: &SafePrimeGroup,
    sk: &Vec<USIZE>,
    choice: &Vec<bool>,
) -> Vec<(PublicKey, PublicKey)> {
    // self.sk.resize(self.k, USIZE::ZERO);
    let modulus = NonZero::new(group.p).unwrap();
    let res_params = DynResidueParams::new(&group.p);
    let g = GroupElem::new(&group.g, res_params);
    // let mut sk = Vec::with_capacity(choice.len());
    let keys = choice
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let x = USIZE::random_mod(&mut OsRng, &modulus);
            let fake_gamal = GroupElem::new(&x, res_params).square();
            // sk[i] = USIZE::random_mod(&mut OsRng, &NonZero::new(group.q).unwrap());
            let real_gamal = g.pow(&sk[i]);
            if b {
                (fake_gamal, real_gamal)
            } else {
                (real_gamal, fake_gamal)
            }
        })
        .collect::<Vec<_>>();
    keys
}

pub fn create_secret_keys(group: &SafePrimeGroup, num: usize) -> Vec<USIZE> {
    (0..num)
        .map(|_| USIZE::random_mod(&mut OsRng, &NonZero::new(group.q).unwrap()))
        .collect()
}

// Retrieve the result from Bob's encrypted messages.
pub fn receive_as_int(
    group: &SafePrimeGroup,
    m: &OTParams,
    sk: &Vec<USIZE>,
    choices: &Vec<bool>,
) -> Vec<usize> {
    receive_(group, m, sk, choices)
        .iter()
        .map(|x| x.as_limbs().first().unwrap().0 as usize)
        .collect::<Vec<_>>()
}

pub fn receive_(
    group: &SafePrimeGroup,
    m: &OTParams,
    sk: &Vec<USIZE>,
    choices: &Vec<bool>,
) -> Vec<USIZE> {
    let messages = m
        .iter()
        .zip(choices)
        .zip(sk)
        .map(|(((c_d_0, c_d_1), &b), sk)| {
            let (c, d) = if b { c_d_0 } else { c_d_1 };
            let (inverted, _) = c.invert(); // Happening modulo prime, so ignore possible error.
            let m = inverted.pow(&(sk)).mul(&d);
            let x = from_encoding(&m, &group.p, &group.q);
            let k = x.retrieve();
            U512::from(k)
        })
        .collect();
    messages
}

/**
 * Encode arbitrary numbers in the group specified by p.
 * m is the message
 * p is the prime defining the group (well we use a subgroup of the group defined by p)
 * q is the order of the subgroup we work in
 */
fn to_encoding(m: &GroupElem, p: &USIZE, q: &USIZE) -> GroupElem {
    let one = GroupElem::one(DynResidueParams::new(&p));
    if (m + one).pow(&q) == one {
        return m + one;
    } else {
        return -(m + one);
    }
}

/**
 * Decode arbitrary numbers in the group specified by p.
 * m is the encoded message
 * p is the prime defining the group
 * q is the order of the subgroup we work in
 */
fn from_encoding(m: &GroupElem, p: &USIZE, q: &USIZE) -> GroupElem {
    let one = GroupElem::one(DynResidueParams::new(&p));
    if m.retrieve() <= *q {
        m - one
    } else {
        -m - one
    }
}

pub fn bool_vec_to_usize(v: &Vec<bool>) -> USIZE {
    let mut clone = v.clone();
    clone.reverse();
    clone.resize(SECURITY, false);
    clone.reverse();
    // println!("Clone: {:?}", v);
    // println!("ByteVec: {:?}", &crate::common::bool_vec_to_byte_vec(&clone)[..]);
    // println!("After usize: {:?}", crate::common::int_vec_to_bool_vec(&USIZE::from_be_slice(&crate::common::bool_vec_to_byte_vec(&clone)[..]).to_words().to_vec().iter().take(256 / 64).rev().map(|&x| x).collect::<Vec<_>>()));
    // assert_eq!(clone, crate::common::int_vec_to_bool_vec(&USIZE::from_be_slice(&crate::common::bool_vec_to_byte_vec(&clone)[..]).to_words().to_vec().iter().rev().map(|&x| x).collect::<Vec<_>>()));
    // panic!();
    USIZE::from_be_slice(&crate::common::bool_vec_to_byte_vec(&clone)[..])
    // let modulus = NonZero::new(self.group.q).unwrap();
}

pub fn usize_to_bool_vec_len(n: &USIZE, output_bits: usize) -> Vec<bool> {
    let x =  n.to_words()
    .to_vec()
    .iter()
    // .rev()
    .take(usize::div_ceil(output_bits, 64))
    .rev()
    .map(|&x| x).collect::<Vec<_>>();
    crate::common::int_vec_to_bool_vec(&x).iter().rev().take(output_bits).rev().map(|&x| x).collect::<Vec<_>>()
}

pub fn usize_to_bool_vec(n: &USIZE) -> Vec<bool> {
    usize_to_bool_vec_len(n, 256)
}



pub fn send_usize(
    group: &SafePrimeGroup,
    keys: &Vec<(PublicKey, PublicKey)>,
    messages: &Vec<(USIZE, USIZE)>,
) -> OTParams {
    let res_params = DynResidueParams::new(&group.p);
    let modulus = NonZero::new(group.q).unwrap();
    let messages_as_elems = messages.iter().map(|(m_0, m_1)| {
        (
            GroupElem::new(m_0, res_params),
            GroupElem::new(m_1, res_params),
        )
    });
    let encode_p_q = |m: &GroupElem| to_encoding(m, &group.p, &group.q);
    let encoded_messages = messages_as_elems
        .into_iter()
        .map(|(m_0, m_1)| (encode_p_q(&m_0), encode_p_q(&m_1)))
        .collect::<Vec<_>>();
    keys.into_iter()
        .zip(encoded_messages)
        .map(|((k_0, k_1), (m_0, m_1))| {
            let r_0 = USIZE::random_mod(&mut OsRng, &modulus);
            let r_1 = USIZE::random_mod(&mut OsRng, &modulus);
            let s_0 = k_0.pow(&r_0);
            let s_1 = k_1.pow(&r_1);
            let g = GroupElem::new(&group.g, res_params);
            ((g.pow(&r_1), s_1.mul(&m_1)), (g.pow(&r_0), s_0.mul(&m_0)))
            // let r = USIZE::random_mod(&mut OsRng, &modulus);
            // let s = k.pow(&r);
            // (g.pow(&r), s.mul(&m))
        })
        .collect::<Vec<_>>()
}

pub fn send(
    group: &SafePrimeGroup,
    keys: &Vec<(PublicKey, PublicKey)>,
    messages: &Vec<(usize, usize)>,
) -> OTParams {
    let messages_as_elems = messages
        .iter()
        .map(|&(m_0, m_1)| (USIZE::from_u64(m_0 as u64), USIZE::from_u64(m_1 as u64)))
        .collect::<Vec<_>>();
    send_usize(group, keys, &messages_as_elems)
}

// Returns 1 and -1 mod p.
fn get_one_and_minus_one_mod(p: &Uint<DYN_RES>) -> (Uint<DYN_RES>, Uint<DYN_RES>) {
    let res_params = DynResidueParams::new(p);
    let one = GroupElem::one(res_params);
    let zero = GroupElem::zero(res_params);
    let minus_one = zero.sub(&one);
    return (one.retrieve(), minus_one.retrieve());
}

// Create generator for safe prime p.
fn get_generator(p: &Uint<DYN_RES>) -> Uint<DYN_RES> {
    let res_params = DynResidueParams::new(p);
    let (one, minus_one) = get_one_and_minus_one_mod(p);
    let modulus = NonZero::new(*p).unwrap();
    let mut g = USIZE::random_mod(&mut OsRng, &modulus);
    loop {
        if g != one && g != minus_one {
            return GroupElem::new(&g, res_params).square().retrieve();
        }
        g = USIZE::random_mod(&mut OsRng, &modulus);
    }
}

pub fn run_tests() {
    print!("Testing primitive... ");
    for m in 1..10 {
        let group = make_group();
        let sk = create_secret_keys(&group, 500);
        let choice_bits = (0..m).into_iter().map(|_| random()).collect::<Vec<_>>();
        let messages = (0..m).into_iter().map(|x| (x, x + 1)).collect::<Vec<_>>();
        let keys = commit_choice(&group, &sk, &choice_bits);
        let x = send(&group, &keys, &messages);
        let prediction = receive_as_int(&group, &x, &sk, &choice_bits);
        let correct = messages
            .into_iter()
            .enumerate()
            .map(|(i, m)| if choice_bits[i] { m.1 } else { m.0 })
            .collect::<Vec<_>>();
        prediction
            .into_iter()
            .zip(correct)
            .for_each(|(p, c)| assert_eq!(p, c))
    }
    println!("OK")
}
