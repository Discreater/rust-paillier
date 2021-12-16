#![cfg(feature = "inclramp")]
extern crate ramp;
use super::traits::*;
use rand::rngs::OsRng;

impl Samplable for ramp::Int {
    fn sample_below(upper: &Self) -> Self {
        use self::ramp::RandomInt;
        let mut rng = OsRng::default();
        rng.gen_uint_below(upper)
    }

    fn sample(bitsize: usize) -> Self {
        use self::ramp::RandomInt;
        let mut rng = OsRng::default();
        rng.gen_uint(bitsize)
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        use self::ramp::RandomInt;
        let mut rng = OsRng::default();
        rng.gen_int_range(lower, upper)
    }
}

impl NumberTests for ramp::Int {
    fn is_zero(&self) -> bool {
        self == &0
    }
    fn is_even(&self) -> bool {
        self.is_even()
    }
    fn is_negative(&self) -> bool {
        self < &0
    }
}

impl ModPow for ramp::Int {
    fn modpow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.modpow(exponent, modulus)
    }
}

impl ConvertFrom<ramp::Int> for usize {
    fn _from(x: &ramp::Int) -> usize {
        usize::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u8 {
    fn _from(x: &ramp::Int) -> u8 {
        u8::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u16 {
    fn _from(x: &ramp::Int) -> u16 {
        u16::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u32 {
    fn _from(x: &ramp::Int) -> u32 {
        u32::from(x)
    }
}

impl ConvertFrom<ramp::Int> for u64 {
    fn _from(x: &ramp::Int) -> u64 {
        u64::from(x)
    }
}

impl BitManipulation for ramp::Int {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        self.set_bit(bit as u32, bit_val);
    }
}

pub type BigInteger = ramp::Int;
