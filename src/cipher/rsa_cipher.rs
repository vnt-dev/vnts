use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::protocol::body::RsaSecretBody;
use crate::protocol::NetPacket;
use rsa::pkcs8::der::Decode;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Digest;

#[derive(Clone)]
pub struct RsaCipher {
    inner: Arc<Inner>,
}

struct Inner {
    private_key: RsaPrivateKey,
    public_key_der: Vec<u8>,
}

impl RsaCipher {
    pub fn new() -> io::Result<Self> {
        let priv_key_path = PathBuf::from("key/private_key.pem");
        let private_key = if priv_key_path.exists() {
            let key = std::fs::read_to_string(priv_key_path)?;
            let private_key = match RsaPrivateKey::from_pkcs8_pem(&key) {
                Ok(private_key) => private_key,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("'key/private_key.pem' content error {}", e),
                    ));
                }
            };
            private_key
        } else {
            let path = PathBuf::from("key");
            if !path.exists() {
                std::fs::create_dir(path)?;
            }
            let mut rng = rand::thread_rng();
            let bits = 2048;
            let private_key = match RsaPrivateKey::new(&mut rng, bits) {
                Ok(private_key) => private_key,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to generate a key {}", e),
                    ));
                }
            };
            match private_key.write_pkcs8_pem_file(priv_key_path, LineEnding::CRLF) {
                Ok(_) => {}
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to write to file 'key/private_key.pem' {}", e),
                    ));
                }
            };
            private_key
        };
        let public_key = RsaPublicKey::from(&private_key);
        match public_key.write_public_key_pem_file("key/public_key.pem", LineEnding::CRLF) {
            Ok(_) => {}
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to write to file 'key/public_key.pem' {}", e),
                ));
            }
        };
        let public_key_der = match public_key.to_public_key_der() {
            Ok(public_key_der) => public_key_der.to_vec(),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("to_public_key_der failed {}", e),
                ));
            }
        };
        let inner = Inner {
            private_key,
            public_key_der,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
    pub fn finger(&self) -> io::Result<String> {
        match rsa::pkcs8::SubjectPublicKeyInfo::from_der(&self.inner.public_key_der) {
            Ok(spki) => match spki.fingerprint_base64() {
                Ok(finger) => Ok(finger),
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("fingerprint_base64 error {}", e),
                )),
            },
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("from_der error {}", e),
            )),
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.inner.public_key_der
    }
}

impl RsaCipher {
    pub fn decrypt<B: AsRef<[u8]>>(
        &self,
        net_packet: &NetPacket<B>,
    ) -> io::Result<RsaSecretBody<Vec<u8>>> {
        match self
            .inner
            .private_key
            .decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, net_packet.payload())
        {
            Ok(rs) => {
                let mut nonce_raw = [0; 12];
                nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
                nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
                nonce_raw[8] = net_packet.protocol().into();
                nonce_raw[9] = net_packet.transport_protocol();
                nonce_raw[10] = net_packet.is_gateway() as u8;
                nonce_raw[11] = net_packet.source_ttl();
                let secret_body = RsaSecretBody::new(rs)?;
                let mut hasher = sha2::Sha256::new();
                hasher.update(secret_body.body());
                hasher.update(nonce_raw);
                let key: [u8; 32] = hasher.finalize().into();
                if secret_body.finger() != &key[16..] {
                    return Err(io::Error::new(io::ErrorKind::Other, "finger err"));
                }
                Ok(secret_body)
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("decrypt failed {}", e),
            )),
        }
    }
}
