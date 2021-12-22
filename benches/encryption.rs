use criterion::{black_box, criterion_group, criterion_main, Criterion};
extern crate num_traits;
extern crate paillier;

use paillier::encoding::*;
use paillier::*;

mod helpers;
use crate::helpers::*;

pub fn bench_encryption_ek<KS: KeySize>(c: &mut Criterion) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);
    c.bench_function("encryption ek", |b| {
        b.iter(|| {
            let _ = Paillier::encrypt(black_box(&ek), black_box(10));
        })
    });
}

pub fn bench_encryption_dk<KS: KeySize>(c: &mut Criterion) {
    let ref keypair = KS::keypair();
    let dk = DecryptionKey::from(keypair);
    c.bench_function("encryption dk", |b| {
        b.iter(|| {
            let _ = Paillier::encrypt(black_box(&dk), black_box(10));
        })
    });
}

pub fn bench_decryption<KS: KeySize>(c: &mut Criterion) {
    let ref keypair = KS::keypair();
    let (ek, dk) = keypair.keys();

    let cipher = Paillier::encrypt(&ek, 10);
    c.bench_function("decryption", |b| {
        b.iter(|| {
            let _ = Paillier::decrypt(black_box(&dk), black_box(&cipher));
        })
    });
}

pub fn bench_rerandomisation<KS: KeySize>(c: &mut Criterion) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);

    let cipher = Paillier::encrypt(&ek, 10);
    c.bench_function("rerandomisation", |b| {
        b.iter(|| {
            let _ = Paillier::rerandomize(black_box(&ek), black_box(&cipher));
        })
    });
}

pub fn bench_addition<KS: KeySize>(c: &mut Criterion) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);

    let c1 = Paillier::encrypt(&ek, 10);
    let c2 = Paillier::encrypt(&ek, 20);
    c.bench_function("addition", |b| {
        b.iter(|| {
            let _ = Paillier::add(black_box(&ek), black_box(&c1), black_box(&c2));
        })
    });
}

pub fn bench_multiplication<KS: KeySize>(c: &mut Criterion) {
    let ref keypair = KS::keypair();
    let ek = EncryptionKey::from(keypair);

    let cipher = Paillier::encrypt(&ek, 10);
    c.bench_function("multiplication", |b| {
        b.iter(|| {
            let _ = Paillier::mul(black_box(&ek), black_box(&cipher), black_box(20));
        })
    });
}

criterion_group!(
    ks_2048,
    self::bench_encryption_ek<KeySize2048>,
    self::bench_encryption_dk<KeySize2048>,
    self::bench_decryption<KeySize2048>,
    self::bench_rerandomisation<KeySize2048>,
    self::bench_addition<KeySize2048>,
    self::bench_multiplication<KeySize2048>
);

criterion_group!(
    ks_4096,
    bench_encryption_ek<KeySize4096>,
    bench_decryption<KeySize4096>,
    bench_encryption_dk<KeySize4096>,
    bench_rerandomisation<KeySize4096>,
    bench_addition<KeySize4096>,
    bench_multiplication<KeySize4096>
);

criterion_main!(ks_4096);
