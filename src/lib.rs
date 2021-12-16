#![feature(test)]
#![feature(min_specialization)]

extern crate test;
extern crate rand;
extern crate num_traits;

#[macro_use]
mod macros;

pub mod arithimpl;
pub mod traits;
pub mod core;
pub mod coding;

pub use crate::traits::*;
pub use crate::coding::*;
pub use crate::core::Keypair;
pub use crate::core::standard::EncryptionKey;
pub use crate::core::crt::DecryptionKey;


/// Parameterised type onto which all operations are added (see `Paillier`).
pub struct AbstractPaillier<I> {
    junk: ::std::marker::PhantomData<I>
}

impl<I> AbstractScheme for AbstractPaillier<I> {
    type BigInteger=I;
}


/*************************
  Ramp instance (default)
 *************************/

#[cfg(feature="inclramp")]
mod rampinstance
{
    pub use crate::arithimpl::rampimpl::BigInteger as RampBigInteger;
    pub type RampPaillier = crate::AbstractPaillier<RampBigInteger>;

    #[cfg(feature="defaultramp")]
    pub type BigInteger = RampBigInteger;
    #[cfg(feature="defaultramp")]
    pub type Paillier = RampPaillier;
}
#[cfg(feature="inclramp")]
pub use self::rampinstance::*;


/**************
  Num instance
 **************/

#[cfg(feature="inclnum")]
mod numinstance
{
    pub use crate::arithimpl::numimpl::BigInteger as NumBigInteger;
    pub type NumPaillier = crate::AbstractPaillier<NumBigInteger>;

    #[cfg(feature="defaultnum")]
    pub type BigInteger = NumBigInteger;
    #[cfg(feature="defaultnum")]
    pub type Paillier = NumPaillier;
}
#[cfg(feature="inclnum")]
pub use self::numinstance::*;


/**************
  GMP instance
 **************/

#[cfg(feature="inclgmp")]
mod gmpinstance
{
    pub use crate::arithimpl::gmpimpl::BigInteger as GmpBigInteger;
    pub type GmpPaillier = crate::AbstractPaillier<GmpBigInteger>;

    #[cfg(feature="defaultgmp")]
    pub type BigInteger = GmpBigInteger;
    #[cfg(feature="defaultgmp")]
    pub type Paillier = GmpPaillier;
}
#[cfg(feature="inclgmp")]
pub use self::gmpinstance::*;
