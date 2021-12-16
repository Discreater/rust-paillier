#![cfg(feature = "inclnum")]

extern crate num;

use rand;
// use num;
// use self::num;

use super::traits::*;

impl Samplable for num::bigint::BigInt {
    fn sample_below(upper: &Self) -> Self {
        use self::num::bigint::{RandBigInt, ToBigInt};
        let mut rng = rand::rngs::OsRng::default();
        rng.gen_biguint_below(&upper.to_biguint().unwrap())
            .to_bigint()
            .unwrap() // TODO this is really ugly
    }

    fn sample(bitsize: usize) -> Self {
        use self::num::bigint::{RandBigInt, ToBigInt};
        let mut rng = rand::rngs::OsRng::default();
        rng.gen_biguint(bitsize as u64).to_bigint().unwrap()
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        use self::num::bigint::{RandBigInt, ToBigInt};
        let mut rng = rand::rngs::OsRng::default();
        rng.gen_biguint_range(&lower.to_biguint().unwrap(), &upper.to_biguint().unwrap())
            .to_bigint()
            .unwrap()
    }
}

use self::num::{Integer, Signed, Zero};
impl NumberTests for num::bigint::BigInt {
    fn is_zero(&self) -> bool {
        Zero::is_zero(self)
    }
    fn is_even(&self) -> bool {
        Integer::is_even(self)
    }
    fn is_negative(&self) -> bool {
        Signed::is_negative(self)
    }
}

// impl DivRem for num::bigint::BigInt {
//     fn divmod(dividend: &Self, module: &Self) -> (Self, Self) {
//         dividend.div_rem(module)
//     }
// }

use self::num::ToPrimitive;
impl ConvertFrom<num::bigint::BigInt> for u64 {
    fn _from(x: &num::bigint::BigInt) -> u64 {
        x.to_u64().unwrap()
    }
}

impl BitManipulation for num::bigint::BigInt {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        self.set_bit(bit as u64, bit_val);
    }
}

pub type BigInteger = num::bigint::BigInt;
