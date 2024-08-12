use color_eyre::eyre::{eyre, Context, Result};

pub fn decode_key_base64<const N: usize>(input: &str) -> Result<[u8; N]> {
    use base64::prelude::BASE64_STANDARD;

    use base64::Engine;
    let d = BASE64_STANDARD
        .decode(input)
        .wrap_err("Invalid base64 value provided")?;

    let (k, tail) = d
        .as_slice()
        .split_first_chunk::<N>()
        .ok_or_else(|| eyre!("Not enough bytes provided, got {} expected {N}", d.len()))?;

    if !tail.is_empty() {
        return Err(eyre!(
            "Too many bytes provided, got {} expected {N}",
            d.len()
        ));
    }
    Ok(*k)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum CryptoMode {
    Encrypt,
    Sign,
}

#[derive(Clone, Debug)]
pub struct ChaChaParams {
    pub(super) key: [u8; 32],
    pub(super) nonce: [u8; 12],
    pub mode: CryptoMode,
}

impl ChaChaParams {
    pub fn new(key: &str, nonce: &str, mode: CryptoMode) -> Result<Self> {
        let key = decode_key_base64(key).wrap_err("Could not parse key")?;
        let nonce = decode_key_base64(nonce).wrap_err("Could not parse nonce")?;
        Ok(Self { key, nonce, mode })
    }
}
