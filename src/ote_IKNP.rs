use crate::common::*;
use crate::ot_primitive;
use crate::ot_primitive::bool_vec_to_usize;
use crate::ot_primitive::usize_to_bool_vec_len;
use ot_primitive::PublicKey;
use ot_primitive::SafePrimeGroup;
use rand::random;

struct Receiver {
    t: Vec<Vec<bool>>,
    rand_seeds: Vec<(Vec<bool>, Vec<bool>)>,
    choice_bits: Vec<bool>,
}

struct Sender {
    s: Vec<bool>,
    messages: Vec<(Vec<bool>, Vec<bool>)>,
}

impl Receiver {
    fn initialize(k: usize, m: usize, choice_bits: Vec<bool>) -> Receiver {
        let t = (0..m)
            .map(|_| (0..k).map(|_| random()).collect())
            .collect::<Vec<Vec<bool>>>();
        let rand_seeds = (0..m).map(|_| ((0..k).map(|_| random()).collect::<Vec<_>>(), (0..k).map(|_| random()).collect::<Vec<_>>())).collect::<Vec<_>>();
        return Receiver { t, choice_bits, rand_seeds };
    }

    fn do_protocol(&self, sender: &Sender, group: &SafePrimeGroup) -> Vec<Vec<bool>> {
        let y = sender.receive_ot_primitive(self, group);
        let z = y
            .iter()
            .zip(&self.t)
            .enumerate()
            .map(|(j, ((yj_0, yj_1), t_j))| {
                let yj = if self.choice_bits[j] { yj_1 } else { yj_0 };
                xor_boolvec(yj, &hash_bits(&int_to_bool_vec(j), t_j))
            })
            .collect::<Vec<_>>();
        z
    }

    fn send_ot_primitive(
        &self,
        group: &SafePrimeGroup,
        keys: &Vec<(PublicKey, PublicKey)>,
    ) -> (ot_primitive::OTParams, Vec<(Vec<bool>,Vec<bool>)>) {
        // let seeds
        let inputs = self.rand_seeds.iter().map(|(s_0, s_1)| (bool_vec_to_usize(s_0), bool_vec_to_usize(s_1))).collect::<Vec<_>>();
        let r_input = self.rand_seeds.iter().zip(transpose(&self.t)).map(|((s_0, s_1), row)|{
            let xor = xor_boolvec(&row, &self.choice_bits);
            (xor_boolvec(&row, & pseudo_random_gen(s_0, row.len())), xor_boolvec(&xor, &pseudo_random_gen(s_1, xor.len())))
        }).collect::<Vec<_>>();
        return (ot_primitive::send(group, keys, &inputs), r_input);
    }
}

impl Sender {
    fn initialize(k: usize, messages: Vec<(Vec<bool>, Vec<bool>)>) -> Sender {
        let s = (0..k).map(|_| random()).collect::<Vec<bool>>();
        return Sender { s, messages };
    }

    fn receive_ot_primitive(
        &self,
        receiver: &Receiver,
        group: &SafePrimeGroup,
    ) -> Vec<(Vec<bool>, Vec<bool>)> {
        let k = self.s.len();
        let m = self.messages.len();
        let sk = ot_primitive::create_secret_keys(group, k);
        let keys = ot_primitive::commit_choice(group, &sk, &self.s);
        let (res, otp) = receiver.send_ot_primitive(group, &keys);
        let values = ot_primitive::receive_(group, &res, &sk, &self.s);
        let values = self.s.iter().zip(values).zip(otp).map(|((&s, x), (x_0, x_1))| {
            if s {
                xor_boolvec(&x_1, &usize_to_bool_vec_len(&x, m))
            } else {
                xor_boolvec(&x_0, &usize_to_bool_vec_len(&x, m))
            }
        }).collect::<Vec<_>>();

        let q = transpose(&values);

        self.messages
            .iter()
            .zip(q)
            .enumerate()
            .map(|(j, ((xj_0, xj_1), q_j))| {
                let yj_0 = xor_boolvec(xj_0, &hash_bits(&int_to_bool_vec(j), &q_j));
                let yj_1 = xor_boolvec(
                    xj_1,
                    &hash_bits(&int_to_bool_vec(j), &xor_boolvec(&self.s, &q_j)),
                );
                (yj_0, yj_1)
            })
            .collect::<Vec<_>>()
    }
}

pub fn ote(messages: Vec<(Vec<bool>, Vec<bool>)>, choice: Vec<bool>, k: usize) -> Vec<Vec<bool>> {
    let m = messages.len();
    let sender = Sender::initialize(k, messages);
    let receiver = Receiver::initialize(k, m, choice);
    let group = &ot_primitive::make_group();

    receiver.do_protocol(&sender, group)
}

pub fn run_tests() {
    println!("Starting tests... ");
    for m in [1, 10, 1000, 10000] {
        for k in [128, 256] {
            println!("Running protocol with m={} and k={} .", m, k);
            for _ in 0..1 {
                let messages = (0..m)
                    .into_iter()
                    .map(|x| {
                        (
                            int_to_boolvec_len(x, OUTPUT_SIZE),
                            int_to_boolvec_len(x + 1, OUTPUT_SIZE),
                        )
                    })
                    .collect::<Vec<_>>();
                let choice_bits = (0..m).into_iter().map(|_| random()).collect::<Vec<_>>();
                let prediction = ote(messages.clone(), choice_bits.clone(), k);
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
        }
    }
    println!("Everything worked")
}
