use rand::{Rng, SeedableRng};
use sha3::{Digest, Sha3_256};

pub const OUTPUT_SIZE: usize = 256;

pub fn int_to_boolvec_len(input: usize, len: usize) -> Vec<bool> {
    (0..len)
        .rev()
        .map(|i| {
            (match input.checked_shr(i as u32) {
                Some(s) => s,
                None => 0,
            } & 1)
                != 0
        })
        .collect::<Vec<_>>()
}

pub fn byte_to_boolvec(input: u8) -> Vec<bool> {
    (0..8)
        .rev()
        .map(|i| (input >> i) & 1 != 0)
        .collect::<Vec<_>>()
}

pub fn boolvec_to_u8(input: &Vec<bool>) -> u8 {
    input.iter().fold(0, |acc, &b| ((acc << 1) + (b as u8)))
}

pub fn xor_boolvec(l: &Vec<bool>, r: &Vec<bool>) -> Vec<bool> {
    l.iter().zip(r).map(|(l, r)| l ^ r).collect::<Vec<_>>()
}

pub fn transpose(matrix: &Vec<Vec<bool>>) -> Vec<Vec<bool>> {
    let outer_axis = matrix.len();
    let inner_axis = matrix[0].len();
    let mut m_transp = Vec::new();
    let mut inner = Vec::new();
    inner.resize(outer_axis, false);
    m_transp.resize(inner_axis, inner);
    (0..inner_axis).into_iter().for_each(|row| {
        (0..outer_axis)
            .into_iter()
            .for_each(|col| m_transp[row][col] = matrix[col][row]);
    });
    m_transp
}

pub fn hash_bits(v: &Vec<bool>, j: &Vec<bool>) -> Vec<bool> {
    let mut hasher = Sha3_256::new();
    bool_vec_to_byte_vec(v)
        .rchunks(32)
        .for_each(|x| hasher.update(x));
    bool_vec_to_byte_vec(j)
        .rchunks(32)
        .for_each(|x| hasher.update(x));
    let output: [u8; 32] = *hasher.finalize().as_ref();
    output
        .iter()
        .flat_map(|&x| byte_to_boolvec(x))
        .take(OUTPUT_SIZE)
        .collect::<Vec<_>>()
}

pub fn bool_vec_to_byte_vec(v: &Vec<bool>) -> Vec<u8> {
    v.rchunks(8)
        .rev()
        .map(|x| boolvec_to_u8(&x.to_vec()))
        .collect::<Vec<u8>>()
}

pub fn get_bit(byte: u8, pos: u8) -> bool {
    (byte >> pos) & 1 != 0
}

pub fn byte_vec_to_bool_vec(v: &Vec<u8>) -> Vec<bool> {
    v.iter()
        .flat_map(|&x| {
            [
                get_bit(x, 7),
                get_bit(x, 6),
                get_bit(x, 5),
                get_bit(x, 4),
                get_bit(x, 3),
                get_bit(x, 2),
                get_bit(x, 1),
                get_bit(x, 0),
            ]
            .to_vec()
        })
        .collect::<Vec<_>>()
}

pub fn int_vec_to_bool_vec(v: &Vec<u64>) -> Vec<bool> {
    byte_vec_to_bool_vec(&v.iter().flat_map(|&x| x.to_be_bytes()).collect::<Vec<_>>())
}

pub fn int_to_bool_vec(i: usize) -> Vec<bool> {
    byte_vec_to_bool_vec(&i.to_be_bytes().to_vec())
}

// Stolen from: https://stackoverflow.com/questions/29570607/is-there-a-good-way-to-convert-a-vect-to-an-array
use std::convert::TryInto;
fn to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn pseudo_random_gen(seed: &Vec<bool>, num: usize) -> Vec<bool> {
    let bytes = bool_vec_to_byte_vec(seed);
    let mut x = rand_chacha::ChaCha12Rng::from_seed(to_array(bytes));
    (0..num).map(|_| x.gen_bool(0.5)).collect::<Vec<bool>>()
}
