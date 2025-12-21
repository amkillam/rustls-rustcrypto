#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, string::ToString, sync::Arc};
use core::marker::PhantomData;
use der::Decode;
use der::asn1::OctetStringRef;

use pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::sign::Signer;
use rustls::{SignatureAlgorithm, SignatureScheme};

#[derive(Debug)]
pub struct Ed25519SigningKey {
    key: Arc<ed25519_dalek::SigningKey>,
    scheme: SignatureScheme,
}

fn ed25519_signing_key_from_sec1_der(
    private_key: &[u8],
) -> Result<ed25519_dalek::SigningKey, rustls::Error> {
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

    ed25519_dalek::SigningKey::try_from(info)
        .map_err(|e| rustls::Error::General(format!("failed to create Ed25519 signing key: {}", e)))
}

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519SigningKey {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                ed25519_dalek::SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
                    .map_err(|e| {
                        rustls::Error::General(format!("failed to decrypt private key: {e}"))
                    })
                    .map(|kp| Self {
                        key: Arc::new(kp),
                        scheme: SignatureScheme::ED25519,
                    })
                    .map_err(|e| rustls::Error::General(e.to_string()))
            }
            PrivateKeyDer::Sec1(sec1) => {
                let secret_key = sec1.secret_sec1_der();
                ed25519_signing_key_from_sec1_der(secret_key).map(|kp| Ed25519SigningKey {
                    key: Arc::new(kp),
                    scheme: SignatureScheme::ED25519,
                })
            }
            PrivateKeyDer::Pkcs1(_) => Err(rustls::Error::General(
                "ED25519 does not support PKCS#1 key".to_string(),
            )),
            _ => Err(rustls::Error::General("not supported".into())),
        }
    }
}

impl rustls::sign::SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(super::GenericSigner {
                _marker: PhantomData,
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
