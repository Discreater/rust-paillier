use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};

use std::ops::{Add, AddAssign, Mul};

use num::Zero;
use paillier::integral::{scalar, vector, Code};
use paillier::*;
use rand::distributions::Uniform;
use rand::Rng;

#[derive(Debug, Clone)]
struct Matrix<T, const D: usize> {
    inner: Vec<T>,
    dims: [usize; D],
}

struct MatrixNoDot<T, const D: usize> {
    inner: T,
    dims: [usize; D],
}

impl<T, const D: usize> Matrix<T, D> {
    fn map_bin<F>(&self, other: &Self, f: F) -> Self
    where
        F: Fn((&T, &T)) -> T,
    {
        Self {
            inner: self.inner.iter().zip(other.inner.iter()).map(f).collect(),
            dims: self.dims,
        }
    }
}

impl<T, const D: usize> Matrix<T, D>
where
    for<'a> T: AddAssign<&'a T>,
    for<'a, 'b> &'a T: Add<&'b T, Output = T>,
    for<'a, 'b> &'a T: Mul<&'b T, Output = T>,
{
    fn add(&self, other: &Matrix<T, D>) -> Self {
        assert_eq!(self.dims, other.dims);
        Self {
            inner: self
                .inner
                .iter()
                .zip(other.inner.iter())
                .map(|(a, b)| a + b)
                .collect(),
            dims: self.dims,
        }
    }

    fn mul(&self, other: &Matrix<T, D>) -> Self {
        assert_eq!(self.dims, other.dims);
        Self {
            inner: self
                .inner
                .iter()
                .zip(other.inner.iter())
                .map(|(a, b)| a * b)
                .collect(),
            dims: self.dims,
        }
    }
}

fn rand_vec(size: usize) -> Vec<u64> {
    rand::thread_rng()
        .sample_iter(&Uniform::from(0..2000))
        .take(size)
        .collect()
}

impl<const D: usize> Matrix<u64, D> {
    fn rand(dims: &[usize; D]) -> Self {
        let size = dims.iter().product();
        let inner = rand_vec(size);
        Self {
            inner,
            dims: dims.clone(),
        }
    }

    fn encrypt(
        &self,
        eek: &EncodingEncryptionKey<EncryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Matrix<scalar::Ciphertext<BigInteger, u64>, D> {
        Matrix {
            inner: self
                .inner
                .iter()
                .map(|m| Paillier::encrypt(eek, m))
                .collect(),
            dims: self.dims,
        }
    }

    fn encrypt_no_dot(
        &self,
        eek: &EncodingEncryptionKey<EncryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> MatrixNoDot<vector::Ciphertext<BigInteger, u64>, D> {
        MatrixNoDot {
            inner: Paillier::encrypt(eek, &self.inner),
            dims: self.dims,
        }
    }
}

impl<const D: usize> Matrix<scalar::Ciphertext<BigInteger, u64>, D> {
    fn decrypt(
        &self,
        ddk: &DecodingDecryptionKey<DecryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Matrix<u64, D> {
        Matrix {
            inner: self
                .inner
                .iter()
                .map(|m| Paillier::decrypt(ddk, m))
                .collect(),
            dims: self.dims,
        }
    }
}

impl<const D: usize> MatrixNoDot<vector::Ciphertext<BigInteger, u64>, D> {
    fn decrypt(
        &self,
        ddk: &DecodingDecryptionKey<DecryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Matrix<u64, D> {
        Matrix {
            inner: Paillier::decrypt(ddk, &self.inner),
            dims: self.dims,
        }
    }
}

impl<T, const D: usize> PartialEq for Matrix<T, D>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.dims == other.dims && self.inner == other.inner
    }
}

impl<T> Matrix<T, 2>
where
    T: Zero,
    for<'a> T: AddAssign<&'a T>,
    T: Add<T, Output = T>,
    for<'a, 'b> &'a T: Mul<&'b T, Output = T>,
{
    fn dot(&self, other: &Self) -> Self {
        assert_eq!(self.dims[1], other.dims[0]);
        let mut inner = Vec::with_capacity(self.dims[0] * other.dims[1]);
        for i in 0..self.dims[0] {
            for j in 0..other.dims[1] {
                let mut sum = T::zero();
                for k in 0..self.dims[1] {
                    sum +=
                        &(&self.inner[i * self.dims[0] + k] * &other.inner[k * other.dims[1] + j]);
                }
                inner.push(sum);
            }
        }
        Self {
            inner,
            dims: [self.dims[0], other.dims[1]],
        }
    }
}

impl Matrix<scalar::Ciphertext<BigInteger, u64>, 2> {
    fn dot_encrypted(
        &self,
        other: &Matrix<u64, 2>,
        eek: &EncodingEncryptionKey<EncryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Self {
        assert_eq!(self.dims[1], other.dims[0]);
        let mut inner = Vec::with_capacity(self.dims[0] * other.dims[1]);
        for i in 0..self.dims[0] {
            for j in 0..other.dims[1] {
                let mut sum = Paillier::mul(eek, &self.inner[i * self.dims[0]], &other.inner[j]);
                for k in 1..self.dims[1] {
                    let m = Paillier::mul(
                        eek,
                        &self.inner[i * self.dims[0] + k],
                        &other.inner[k * other.dims[1] + j],
                    );
                    sum = Paillier::add(eek, &sum, &m);
                }
                inner.push(sum);
            }
        }
        Self {
            inner,
            dims: [self.dims[0], other.dims[1]],
        }
    }
}

impl<const D: usize> Matrix<scalar::Ciphertext<BigInteger, u64>, D> {
    fn mul_encrypted(
        &self,
        other: &Matrix<u64, D>,
        eek: &EncodingEncryptionKey<EncryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Self {
        assert_eq!(self.dims, other.dims);
        let inner = self
            .inner
            .iter()
            .zip(other.inner.iter())
            .map(|(a, b)| Paillier::mul(eek, a, b))
            .collect();

        Self {
            inner,
            dims: self.dims,
        }
    }
}

impl<const D: usize> Matrix<scalar::Ciphertext<BigInteger, u64>, D> {
    fn add_encrypted(
        &self,
        other: &Self,
        eek: &EncodingEncryptionKey<EncryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Self {
        assert_eq!(self.dims, other.dims);
        let inner = self
            .inner
            .iter()
            .zip(other.inner.iter())
            .map(|(a, b)| Paillier::add(eek, a, b))
            .collect();

        Self {
            inner,
            dims: self.dims,
        }
    }
}

impl<const D: usize> MatrixNoDot<vector::Ciphertext<BigInteger, u64>, D> {
    fn add_encrypted(
        &self,
        other: &Self,
        eek: &EncodingEncryptionKey<EncryptionKey<BigInteger>, Code<BigInteger>>,
    ) -> Self {
        assert_eq!(self.dims, other.dims);
        Self {
            inner: Paillier::add(eek, &self.inner, &other.inner),
            dims: self.dims,
        }
    }
}

const matrix_size: [usize; 2] = [100, 100];

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let (ek, dk) = Paillier::keypair().keys();
            let code: Code<BigInteger> = integral::Code::default();

            let _eek = ek.with_code(&code);
            let _ddk = dk.with_code(&code);
        })
    });
}

fn bench_encryption(c: &mut Criterion) {
    c.bench_function("encryption", |b| {
        let (ek, dk) = Paillier::keypair().keys();
        let code: Code<BigInteger> = integral::Code::default();

        let eek = ek.with_code(&code);
        let _ddk = dk.with_code(&code);
        let p = Matrix::rand(&matrix_size);
        b.iter(|| {
            let _ = p.encrypt(black_box(&eek));
        });
    });
}

fn bench_decryption(c: &mut Criterion) {
    c.bench_function("decryption", |b| {
        let (ek, dk) = Paillier::keypair().keys();
        let code: Code<BigInteger> = integral::Code::default();

        let eek = ek.with_code(&code);
        let ddk = dk.with_code(&code);
        let p = Matrix::rand(&matrix_size);
        let c = p.encrypt(black_box(&eek));
        b.iter(|| {
            c.decrypt(black_box(&ddk));
        });
    });
}

fn bench_addition(c: &mut Criterion) {
    c.bench_function("addition", |b| {
        let (ek, dk) = Paillier::keypair().keys();
        let code: Code<BigInteger> = integral::Code::default();

        let eek = ek.with_code(&code);
        let _ddk = dk.with_code(&code);
        let p1 = Matrix::rand(&matrix_size);
        let p2 = Matrix::rand(&matrix_size);
        let c1 = p1.encrypt(&eek);
        let c2 = p2.encrypt(&eek);
        b.iter(|| {
            c1.add_encrypted(black_box(&c2), black_box(&eek));
        });
    });
}

fn bench_multiplication(c: &mut Criterion) {
    c.bench_function("multiplication", |b| {
        let (ek, dk) = Paillier::keypair().keys();
        let code: Code<BigInteger> = integral::Code::default();

        let eek = ek.with_code(&code);
        let _ddk = dk.with_code(&code);
        let p1 = Matrix::rand(&matrix_size);
        let p2 = Matrix::rand(&matrix_size);
        let c1 = p1.encrypt(&eek);
        b.iter(|| {
            c1.mul_encrypted(black_box(&p2), black_box(&eek));
        });
    });
}

fn bench_dot(c: &mut Criterion) {
    c.bench_function("dot", |b| {
        let (ek, dk) = Paillier::keypair().keys();
        let code: Code<BigInteger> = integral::Code::default();

        let eek = ek.with_code(&code);
        let _ddk = dk.with_code(&code);
        let p1 = Matrix::rand(&matrix_size);
        let p2 = Matrix::rand(&matrix_size);
        let c1 = p1.encrypt(&eek);
        b.iter(|| {
            c1.dot_encrypted(black_box(&p2), black_box(&eek));
        });
    });
}

fn bench_addition_full(c: &mut Criterion) {
    c.bench_function("addition full", |b| {
        b.iter(|| {
            let (ek, dk) = Paillier::keypair().keys();
            let code: Code<BigInteger> = integral::Code::default();

            let eek = ek.with_code(&code);
            let ddk = dk.with_code(&code);

            let p1 = Matrix::rand(&matrix_size);
            let p2 = Matrix::rand(&matrix_size);
            let c1 = p1.encrypt(&eek);
            let c2 = p2.encrypt(&eek);
            let r = c1.add_encrypted(&c2, &eek);
            r.decrypt(&ddk)
        });
    });
}

fn bench_multiplication_full(c: &mut Criterion) {
    c.bench_function("multiplication full", |b| {
        b.iter(|| {
            let (ek, dk) = Paillier::keypair().keys();
            let code: Code<BigInteger> = integral::Code::default();

            let eek = ek.with_code(&code);
            let ddk = dk.with_code(&code);

            let p1 = Matrix::rand(&matrix_size);
            let p2 = Matrix::rand(&matrix_size);
            let c1 = p1.encrypt(&eek);
            let r = c1.mul_encrypted(&p2, &eek);
            r.decrypt(&ddk)
        });
    });
}

fn bench_dot_full(c: &mut Criterion) {
    c.bench_function("dot full", |b| {
        b.iter(|| {
            let (ek, dk) = Paillier::keypair().keys();
            let code: Code<BigInteger> = integral::Code::default();

            let eek = ek.with_code(&code);
            let ddk = dk.with_code(&code);

            let p1 = Matrix::rand(&matrix_size);
            let p2 = Matrix::rand(&matrix_size);
            let c1 = p1.encrypt(&eek);
            let r = c1.dot_encrypted(&p2, &eek);
            r.decrypt(&ddk)
        });
    });
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = 
    bench_keygen,
    bench_encryption,
    bench_decryption,
    bench_addition,
    bench_multiplication,
    bench_dot,
    bench_addition_full,
    bench_multiplication_full,
    bench_dot_full
}
criterion_main!(benches);
