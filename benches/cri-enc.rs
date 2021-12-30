use bencher::black_box;
use criterion::{Criterion, criterion_group, criterion_main, Bencher};
use paillier::core::*;
use paillier::*;

mod helpers;
use crate::helpers::*;

fn encryption<S, EK>(b: &mut Bencher)
where
    S: AbstractScheme,
    S: TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK: From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    S: Encryption<
        EK,
        Plaintext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    <S as AbstractScheme>::BigInteger: From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);
    let m = Plaintext::from(10);
    b.iter(|| {
        S::encrypt(black_box(&ek), black_box(&m));
    });
}

fn decryption<S, EK, DK>(b: &mut Bencher)
where
    S: AbstractScheme,
    for<'kp> EK: From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    for<'kp> DK: From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    S: Encryption<
        EK,
        Plaintext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    S: Decryption<
        DK,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
        Plaintext<<S as AbstractScheme>::BigInteger>,
    >,
    S: TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger: From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);
    let dk = DK::from(keypair);
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        S::decrypt(black_box(&dk), black_box(&c));
    });
}

fn rerandomisation<S, EK>(b: &mut Bencher)
where
    S: AbstractScheme,
    S: Encryption<
        EK,
        Plaintext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    S: Rerandomisation<EK, Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S: TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK: From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger: From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        S::rerandomise(black_box(&ek), black_box(&c));
    });
}

fn addition<S, EK>(b: &mut Bencher)
where
    S: AbstractScheme,
    S: Encryption<
        EK,
        Plaintext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    S: Addition<
        EK,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    S: TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK: From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger: From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);
    let c2 = S::encrypt(&ek, &m2);

    b.iter(|| {
        S::add(black_box(&ek), black_box(&c1), black_box(&c2));
    });
}


fn multiplication<S, EK>(b: &mut Bencher)
where
    S: AbstractScheme,
    S: Encryption<
        EK,
        Plaintext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    S: Multiplication<
        EK,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
        Plaintext<<S as AbstractScheme>::BigInteger>,
        Ciphertext<<S as AbstractScheme>::BigInteger>,
    >,
    S: TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    for<'kp> EK: From<&'kp Keypair<<S as AbstractScheme>::BigInteger>>,
    <S as AbstractScheme>::BigInteger: From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = EK::from(keypair);

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);

    b.iter(|| {
        S::mul(black_box(&ek), black_box(&c1), black_box(&m2));
    });
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encription");
    #[cfg(feature = "inclramp")]
    group.bench_function("ramp-standard", |b| encryption::<RampPaillier, standard::EncryptionKey<RampBigInteger>>(b));
    #[cfg(feature = "inclramp")]
    group.bench_function("ramp-generic", |b| encryption::<RampPaillier, generic::EncryptionKey<RampBigInteger>>(b));
    #[cfg(feature = "inclnum")]
    group.bench_function("num", |b| encryption::<NumPaillier, standard::EncryptionKey<NumBigInteger>>(b));
    #[cfg(feature = "inclgmp")]
    group.bench_function("gmp", |b| encryption::<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>(b));
    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("decryption");
    #[cfg(feature = "inclramp")]
    group.bench_function("ramp", |b| decryption::<RampPaillier, standard::EncryptionKey<RampBigInteger>, crt::DecryptionKey<RampBigInteger>>(b));
    #[cfg(feature = "inclnum")]
    group.bench_function("num", |b| decryption::<NumPaillier, standard::EncryptionKey<NumBigInteger>, crt::DecryptionKey<NumBigInteger>>(b));
    #[cfg(feature = "inclgmp")]
    group.bench_function("gmp", |b| decryption::<GmpPaillier, standard::EncryptionKey<GmpBigInteger>, crt::DecryptionKey<GmpBigInteger>>(b));
    group.finish();
}

fn bench_rerandomisation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rerandomisation");
    #[cfg(feature = "inclramp")]
    group.bench_function("ramp", |b| rerandomisation::<RampPaillier, standard::EncryptionKey<RampBigInteger>>(b));
    #[cfg(feature = "inclnum")]
    group.bench_function("num", |b| rerandomisation::<NumPaillier, standard::EncryptionKey<NumBigInteger>>(b));
    #[cfg(feature = "inclgmp")]
    group.bench_function("gmp", |b| rerandomisation::<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>(b));
    group.finish();
}

fn bench_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("addition");
    #[cfg(feature = "inclramp")]
    group.bench_function("ramp", |b| addition::<RampPaillier, standard::EncryptionKey<RampBigInteger>>(b));
    #[cfg(feature = "inclnum")]
    group.bench_function("num", |b| addition::<NumPaillier, standard::EncryptionKey<NumBigInteger>>(b));
    #[cfg(feature = "inclgmp")]
    group.bench_function("gmp", |b| addition::<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>(b));
    group.finish();
}

fn bench_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiplication");
    #[cfg(feature = "inclramp")]
    group.bench_function("ramp", |b| multiplication::<RampPaillier, standard::EncryptionKey<RampBigInteger>>(b));
    #[cfg(feature = "inclnum")]
    group.bench_function("num", |b| multiplication::<NumPaillier, standard::EncryptionKey<NumBigInteger>>(b));
    #[cfg(feature = "inclgmp")]
    group.bench_function("gmp", |b| multiplication::<GmpPaillier, standard::EncryptionKey<GmpBigInteger>>(b));
    group.finish();
}


criterion_group!(benches, bench_encryption, bench_decryption, bench_rerandomisation, bench_addition, bench_multiplication);
criterion_main!(benches);