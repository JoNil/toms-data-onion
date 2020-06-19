use aes::{BlockCipher, NewBlockCipher};
use byteorder::{BigEndian, WriteBytesExt};
use generic_array::{
    arr,
    sequence::{Concat, Split},
    typenum::U8,
    GenericArray,
};
use std::error::Error;

/// AES Key Wrap
/// As defined in RFC 3394.
pub fn wrap(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    assert_eq!(data.len() % 8, 0, "data must be a multiple of 64bit");

    let aes_size = key.len() * 8;
    match aes_size {
        128 => Ok(wrap_128(key, iv, data)),
        192 => Ok(wrap_192(key, iv, data)),
        256 => Ok(wrap_256(key, iv, data)),
        _ => Err(format!("invalid aes key size: {}", aes_size).into()),
    }
}

/// AES Key Unwrap
/// As defined in RFC 3394.
pub fn unwrap(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    assert_eq!(data.len() % 8, 0, "data must be a multiple of 64bit");

    let aes_size = key.len() * 8;
    match aes_size {
        128 => unwrap_128(key, iv, data),
        192 => unwrap_192(key, iv, data),
        256 => unwrap_256(key, iv, data),
        _ => return Err(format!("invalid aes key size: {}", aes_size).into()),
    }
}

macro_rules! impl_aes_kw {
    ($name_wrap:ident, $name_unwrap:ident, $size:expr, $hasher:ty) => {
        #[inline]
        fn $name_wrap(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
            // 0) Prepare inputs

            // number of 64 bit blocks in the input data
            let n = data.len() / 8;

            let p: Vec<_> = data.chunks(8).map(|chunk|{
                GenericArray::<u8, _>::clone_from_slice(chunk)
            }).collect();

            let key = GenericArray::from_slice(key);

            // 1) Initialize variables

            //   Set A to the IV
            let mut a = *GenericArray::<u8, U8>::from_slice(iv);

            //   for i = 1 to n: R[i] = P[i]
            let mut r = p.clone();

            // 2) calculate intermediate values

            let mut t_arr = arr![u8; 0, 0, 0, 0, 0, 0, 0, 0];
            for j in 0..=5 {
                for i in 0..n {
                    let t = (n * j + (i + 1)) as u64;

                    let cipher = <$hasher as NewBlockCipher>::new(&key);
                    // Safe to unwrap, as we know the size of t_arr.
                    (&mut t_arr[..]).write_u64::<BigEndian>(t).unwrap();

                    // A | R[i]
                    let mut b = a.concat(r[i]);
                    // B = AES(K, ..)
                    cipher.encrypt_block(&mut b);

                    let (hi, lo) = b.split();

                    // A = MSB(64, B) ^ t
                    a = hi;
                    a.iter_mut().zip(t_arr.iter()).for_each(|(ai, ti)| *ai ^= ti);

                    // R[i] = LSB(64, B)
                    r[i] = lo;
                }
            }

            // 3) output the results
            r.iter().fold(a.to_vec(), |mut acc, v| {
                acc.extend(v);
                acc
            })
        }

        #[inline]
        fn $name_unwrap(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            // 0) Prepare inputs

            let n = (data.len() / 8) - 1;

            let c: Vec<_> = data.chunks(8).map(|chunk|{
                GenericArray::<u8, _>::clone_from_slice(chunk)
            }).collect();

            let key = GenericArray::from_slice(key);

            // 1) Initialize variables

            //   A = C[0]
            let mut a = c[0];

            //   for i = 1 to n: R[i] = C[i]
            let mut r = (&c[1..]).to_vec();

            // 2) calculate intermediate values

            let mut t_arr = arr![u8; 0, 0, 0, 0, 0, 0, 0, 0];

            for j in (0..=5).rev() {
                for i in (0..n).rev() {
                    let t = (n * j + (i + 1)) as u64;

                    let cipher = <$hasher as NewBlockCipher>::new(&key);
                    // Safe to unwrap, as we know the size of t_arr.
                    (&mut t_arr[..]).write_u64::<BigEndian>(t).unwrap();

                    // A ^ t
                    a.iter_mut().zip(t_arr.iter()).for_each(|(ai, ti)| *ai ^= ti);

                    // (A ^ t) | R[i]
                    let mut b = a.concat(r[i]);
                    // B = AES-1(K, ..)
                    cipher.decrypt_block(&mut b);

                    let (hi, lo) = b.split();

                    // A = MSB(64, B)
                    a = hi;

                    // R[i] = LSB(64, B)
                    r[i] = lo;
                }
            }

            // 3) output the results

            if a == *GenericArray::<u8, U8>::from_slice(iv) {
                Ok(r.iter().fold(Vec::with_capacity(r.len() * 8), |mut acc, v| {
                    acc.extend(v);
                    acc
                }))
            } else {
                return Err("failed integrity check".into());
            }
        }
    };
}

impl_aes_kw!(wrap_128, unwrap_128, 128, aes::Aes128);
impl_aes_kw!(wrap_192, unwrap_192, 192, aes::Aes192);
impl_aes_kw!(wrap_256, unwrap_256, 256, aes::Aes256);
