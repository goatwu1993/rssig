//! RustCrypto implementations used by both CMS and webpki path/CRL validation.
use crate::domain::{ErrorCode, Stage, VerificationError, hex};
use anyhow::Result;
use rsa::pkcs8::DecodePublicKey;
use rustls_pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::Digest;
use signature::Verifier;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
impl Hash {
    pub fn from_oid(oid: &[u8]) -> Result<Self> {
        match oid {
            [0x2b, 0x0e, 3, 2, 0x1a] => Ok(Self::Sha1),
            [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1] => Ok(Self::Sha256),
            [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2] => Ok(Self::Sha384),
            [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3] => Ok(Self::Sha512),
            _ => Err(unsupported_algorithm(oid, "unsupported digest OID").into()),
        }
    }
    pub fn hasher(self) -> Box<dyn sha2::digest::DynDigest> {
        match self {
            Self::Sha1 => Box::new(sha1::Sha1::default()),
            Self::Sha256 => Box::new(sha2::Sha256::default()),
            Self::Sha384 => Box::new(sha2::Sha384::default()),
            Self::Sha512 => Box::new(sha2::Sha512::default()),
        }
    }
    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(bytes).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
        }
    }
}

pub(crate) fn verify_spki(
    spki: &[u8],
    hash: Hash,
    algorithm: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    // Do not silently treat RSA-PSS or arbitrary algorithm identifiers as RSA.
    let rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1];
    if algorithm.starts_with(&rsa) {
        let suffix = *algorithm.last().unwrap();
        let expected = match hash {
            Hash::Sha1 => 5,
            Hash::Sha256 => 11,
            Hash::Sha384 => 12,
            Hash::Sha512 => 13,
        };
        if algorithm.len() != 9 || (suffix != 1 && suffix != expected) {
            return Err(unsupported_algorithm(
                algorithm,
                "unsupported or inconsistent RSA signature algorithm",
            )
            .into());
        }
        let key = rsa::RsaPublicKey::from_public_key_der(spki)?;
        use rsa::traits::PublicKeyParts;
        if key.n().bits() < 2048 {
            return Err(VerificationError::new(
                ErrorCode::WeakAlgorithm,
                Stage::Cms,
                "RSA keys shorter than 2048 bits are rejected",
            )
            .detail("key_bits", key.n().bits())
            .detail("minimum_key_bits", 2048)
            .into());
        }
        let sig = rsa::pkcs1v15::Signature::try_from(sig)?;
        match hash {
            Hash::Sha1 => rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key).verify(msg, &sig)?,
            Hash::Sha256 => {
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key).verify(msg, &sig)?
            }
            Hash::Sha384 => {
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key).verify(msg, &sig)?
            }
            Hash::Sha512 => {
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key).verify(msg, &sig)?
            }
        }
    } else if algorithm == [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2] && hash == Hash::Sha256 {
        p256::ecdsa::VerifyingKey::from_public_key_der(spki)?
            .verify(msg, &p256::ecdsa::Signature::from_der(sig)?)?;
    } else if algorithm == [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3] && hash == Hash::Sha384 {
        p384::ecdsa::VerifyingKey::from_public_key_der(spki)?
            .verify(msg, &p384::ecdsa::Signature::from_der(sig)?)?;
    } else {
        return Err(unsupported_algorithm(algorithm, "unsupported signature algorithm").into());
    }
    Ok(())
}

fn unsupported_algorithm(oid: &[u8], message: &str) -> VerificationError {
    VerificationError::new(ErrorCode::UnsupportedAlgorithm, Stage::Cms, message)
        .detail(
            "oid",
            ::der::asn1::ObjectIdentifier::from_bytes(oid)
                .ok()
                .map(|o| o.to_string()),
        )
        .detail("oid_value_hex", hex(oid))
}

#[derive(Debug)]
struct RustCryptoAlgorithm {
    public: &'static [u8],
    signature: &'static [u8],
    hash: Hash,
    kind: u8,
}
impl SignatureVerificationAlgorithm for RustCryptoAlgorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(self.public)
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(self.signature)
    }
    fn verify_signature(
        &self,
        key: &[u8],
        msg: &[u8],
        sig: &[u8],
    ) -> std::result::Result<(), InvalidSignature> {
        let result = match self.kind {
            0 => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                let key = rsa::RsaPublicKey::from_pkcs1_der(key).map_err(|_| InvalidSignature)?;
                use rsa::traits::PublicKeyParts;
                if key.n().bits() < 2048 {
                    return Err(InvalidSignature);
                }
                let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| InvalidSignature)?;
                match self.hash {
                    Hash::Sha1 => {
                        rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key).verify(msg, &sig)
                    }
                    Hash::Sha256 => {
                        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key).verify(msg, &sig)
                    }
                    Hash::Sha384 => {
                        rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key).verify(msg, &sig)
                    }
                    Hash::Sha512 => {
                        rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key).verify(msg, &sig)
                    }
                }
            }
            1 => p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .map_err(|_| InvalidSignature)?
                .verify(
                    msg,
                    &p256::ecdsa::Signature::from_der(sig).map_err(|_| InvalidSignature)?,
                ),
            _ => p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .map_err(|_| InvalidSignature)?
                .verify(
                    msg,
                    &p384::ecdsa::Signature::from_der(sig).map_err(|_| InvalidSignature)?,
                ),
        };
        result.map_err(|_| InvalidSignature)
    }
}

const RSA: &[u8] = &[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0];
static RSA256: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public: RSA,
    signature: &[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0],
    hash: Hash::Sha256,
    kind: 0,
};
static RSA384: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public: RSA,
    signature: &[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 12, 5, 0],
    hash: Hash::Sha384,
    kind: 0,
};
static RSA512: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public: RSA,
    signature: &[6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 13, 5, 0],
    hash: Hash::Sha512,
    kind: 0,
};
static EC256: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public: &[
        6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
    ],
    signature: &[6, 8, 42, 134, 72, 206, 61, 4, 3, 2],
    hash: Hash::Sha256,
    kind: 1,
};
static EC384: RustCryptoAlgorithm = RustCryptoAlgorithm {
    public: &[6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34],
    signature: &[6, 8, 42, 134, 72, 206, 61, 4, 3, 3],
    hash: Hash::Sha384,
    kind: 2,
};
pub(crate) static ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] =
    &[&RSA256, &RSA384, &RSA512, &EC256, &EC384];
