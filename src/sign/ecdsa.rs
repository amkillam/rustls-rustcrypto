#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, sync::Arc};
use core::marker::PhantomData;

use paste::paste;
use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};

macro_rules! impl_ecdsa {
    ($name: ident, $scheme: expr, $signing_key: ty, $signature: ty) => {
        paste! {
            #[derive(Debug)]
            pub struct [<EcdsaSigningKey $name>] {
                key:    Arc<$signing_key>,
                scheme: SignatureScheme,
            }

            impl TryFrom<&PrivateKeyDer<'_>> for [<EcdsaSigningKey $name>] {
                type Error = rustls::Error;

                fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
                    let pkey = match value {
                        PrivateKeyDer::Pkcs8(der) => {
                           $signing_key::from_pkcs8_der(der.secret_pkcs8_der()).map_err(|e| format!("failed to decrypt private key: {e}"))
                        },
                        PrivateKeyDer::Sec1(sec1) => {
use der::Decode;
use der::asn1::OctetStringRef;
                            let private_key = sec1.secret_sec1_der();

                            let params_oid = sec1::EcPrivateKey::from_der(private_key)
        .map_err(|e| rustls::Error::General(format!("failed to parse EC private key: {}", e)))?
        .parameters
        .and_then(|params| params.named_curve());

    let algorithm = pkcs8::AlgorithmIdentifierRef {
        oid: sec1::ALGORITHM_OID,
        parameters: params_oid.as_ref().map(Into::into),
    };

    let private_key = OctetStringRef::new(private_key).map_err(|e| {
        rustls::Error::General(format!("failed to parse private key octet string: {}", e))
    })?;

    let info = pkcs8::PrivateKeyInfoRef {
        algorithm,
        private_key,
        public_key: None,
    };

    Ok($signing_key::try_from(info).map_err(|e| {
        rustls::Error::General(format!("failed to create ECDSA signing key: {}", e))
    })?)
                        },
                        PrivateKeyDer::Pkcs1(_) => Err(format!("ECDSA does not support PKCS#1 key")),
                        _ => Err("not supported".into()),
                    };
                    pkey.map(|kp| {
                        Self {
                            key:    Arc::new(kp),
                            scheme: $scheme,
                        }
                    }).map_err(rustls::Error::General)
                }
            }

            impl SigningKey for [<EcdsaSigningKey $name>] {
                fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
                    if offered.contains(&self.scheme) {
                        Some(Box::new(super::GenericRandomizedSigner::<$signature, _> {
                            _marker: PhantomData,
                            key:     self.key.clone(),
                            scheme:  self.scheme,
                        }))
                    } else {
                        None
                    }
                }

                fn algorithm(&self) -> SignatureAlgorithm {
                    SignatureAlgorithm::ECDSA
                }
            }
        }
    };
}

impl_ecdsa! {P256, SignatureScheme::ECDSA_NISTP256_SHA256, p256::ecdsa::SigningKey, p256::ecdsa::DerSignature}
impl_ecdsa! {P384, SignatureScheme::ECDSA_NISTP384_SHA384, p384::ecdsa::SigningKey, p384::ecdsa::DerSignature}
