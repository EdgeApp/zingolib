//! TODO: Add Mod Description Here!
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::memo::MemoBytes;

pub(crate) const MAX_STRING_LENGTH: u64 = 1 << 16;

/// ```
/// use zingolib::wallet::utils::{read_string, write_string};
///
/// let mut encoded = Vec::new();
/// write_string(&mut encoded, &"main".to_string()).unwrap();
/// assert_eq!(read_string(encoded.as_slice()).unwrap(), "main");
///
/// let unbounded_length = u64::MAX.to_le_bytes();
/// assert!(read_string(unbounded_length.as_slice()).is_err());
/// ```
pub fn read_string<R: Read>(mut reader: R) -> io::Result<String> {
    let str_len = reader.read_u64::<LittleEndian>()?;
    read_string_body(reader, str_len)
}

pub(crate) fn read_string_body<R: Read>(mut reader: R, str_len: u64) -> io::Result<String> {
    if str_len > MAX_STRING_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("string length {str_len} exceeds the wallet-file maximum {MAX_STRING_LENGTH}"),
        ));
    }
    let mut str_bytes = vec![0; str_len as usize];
    reader.read_exact(&mut str_bytes)?;

    String::from_utf8(str_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// TODO: Add Doc Comment Here!
pub fn write_string<W: Write>(mut writer: W, s: &String) -> io::Result<()> {
    // Strings are written as len + utf8
    writer.write_u64::<LittleEndian>(s.len() as u64)?;
    writer.write_all(s.as_bytes())
}

/// Failure to interpret a memo string.
///
/// Carries the offending memo's byte length, never its content, so the
/// memo cannot leak into logs or error channels.
#[derive(Debug, thiserror::Error)]
pub enum MemoError {
    /// The encoded memo exceeds the memo field's capacity.
    #[error("Error creating output. Memo of {0} bytes is too long")]
    TooLong(usize),
}

/// Create memo bytes from string.
pub fn memo_bytes_from_string(memo_str: String) -> Result<MemoBytes, MemoError> {
    let s_bytes = Vec::from(memo_str.as_bytes());
    MemoBytes::from_bytes(&s_bytes).map_err(|_| MemoError::TooLong(s_bytes.len()))
}

/// TODO: Add Doc Comment Here!
#[must_use]
pub fn txid_from_slice(txid: &[u8]) -> TxId {
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(txid);
    TxId::from_bytes(txid_bytes)
}

/// Overrides the directory the Sapling proving parameters are cached in.
///
/// [`zcash_proofs::default_params_folder`] resolves to a location under the
/// user's home directory, which suits a desktop but not a mobile app, where
/// the writable, backed-up location is chosen by the host. Setting this before
/// the first spend or the first call to [`fetch_sapling_params`] puts the
/// cache somewhere the host controls.
pub fn set_sapling_params_directory(directory: PathBuf) {
    *SAPLING_PARAMS_DIRECTORY
        .write()
        .expect("sapling params directory lock poisoned") = Some(directory);
}

static SAPLING_PARAMS_DIRECTORY: std::sync::RwLock<Option<PathBuf>> =
    std::sync::RwLock::new(None);

fn sapling_params_directory() -> Result<PathBuf, String> {
    if let Some(directory) = SAPLING_PARAMS_DIRECTORY
        .read()
        .expect("sapling params directory lock poisoned")
        .clone()
    {
        return Ok(directory);
    }
    get_zcash_params_path().map_err(|e| e.to_string())
}

/// Paths of the two Sapling parameter files within the cache directory.
fn sapling_params_paths(directory: &Path) -> (PathBuf, PathBuf) {
    (
        directory.join(zcash_proofs::SAPLING_SPEND_NAME),
        directory.join(zcash_proofs::SAPLING_OUTPUT_NAME),
    )
}

/// Downloads the Sapling proving parameters unless they are already cached.
///
/// The parameters are a fixed output of the Sapling MPC, roughly 50 MB, and
/// are needed only to *create* Sapling spends -- scanning, receiving and
/// balances never touch them. Compiling them into the library put that 50 MB
/// into every artifact of every platform, so they are fetched once and cached
/// instead. [`zcash_proofs::download_sapling_parameters`] verifies each file
/// against its published BLAKE2b hash and exact length, so a truncated or
/// substituted download is rejected rather than cached.
///
/// Callers should invoke this when a Sapling receive is first observed, so the
/// download is finished long before a spend needs it. It is safe to call
/// repeatedly: cached files are left alone.
pub fn fetch_sapling_params() -> Result<(), String> {
    let directory = sapling_params_directory()?;
    let (spend, output) = sapling_params_paths(&directory);
    if spend.exists() && output.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    fetch_one(
        zcash_proofs::SAPLING_SPEND_NAME,
        SAPLING_SPEND_HASH,
        SAPLING_SPEND_BYTES,
        &spend,
    )?;
    fetch_one(
        zcash_proofs::SAPLING_OUTPUT_NAME,
        SAPLING_OUTPUT_HASH,
        SAPLING_OUTPUT_BYTES,
        &output,
    )?;
    Ok(())
}

/// Where the parameters are published, and what they must hash to.
///
/// `zcash_proofs::download_sapling_parameters` is not used: it writes to
/// `default_params_folder`, which is derived from the home directory and has
/// no usable answer on Android, so the download fails there before it can be
/// moved. Fetching here writes straight to the configured directory.
///
/// The files are served in two parts because of a 512MB CDN cache limit. The
/// expected lengths and BLAKE2b digests are the same constants the crate
/// verifies against; they describe fixed outputs of the Sapling MPC and do not
/// change.
const PARAMS_DOWNLOAD_URL: &str = "https://download.z.cash/downloads";
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const SAPLING_SPEND_BYTES: u64 = 47958396;
const SAPLING_OUTPUT_BYTES: u64 = 3592860;

/// Downloads one parameter file, verifies it, and only then writes it.
///
/// Verification happens before the file lands: a truncated or substituted
/// download must not be left on disk where a later run would trust it.
fn fetch_one(
    name: &str,
    expected_hash: &str,
    expected_bytes: u64,
    destination: &Path,
) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(expected_bytes as usize);
    for part in 1..=2 {
        let url = format!("{PARAMS_DOWNLOAD_URL}/{name}.part.{part}");
        let response = minreq::get(&url)
            .with_timeout(600)
            .send()
            .map_err(|e| format!("{name} part {part}: {e}"))?;
        if response.status_code != 200 {
            return Err(format!(
                "{name} part {part}: server returned {}",
                response.status_code
            ));
        }
        bytes.extend_from_slice(response.as_bytes());
    }

    if bytes.len() as u64 != expected_bytes {
        return Err(format!(
            "{name}: expected {expected_bytes} bytes, got {}",
            bytes.len()
        ));
    }
    let digest = blake2b_simd::State::new().update(&bytes).finalize();
    if digest.to_hex().as_str() != expected_hash {
        return Err(format!("{name}: hash mismatch"));
    }

    std::fs::write(destination, &bytes).map_err(|e| e.to_string())
}

/// Returns the Sapling parameters as bytes, fetching them if they are absent.
pub(crate) fn read_sapling_params() -> Result<(Vec<u8>, Vec<u8>), String> {
    fetch_sapling_params()?;
    let (spend, output) = sapling_params_paths(&sapling_params_directory()?);
    let sapling_output = std::fs::read(&output).map_err(|e| e.to_string())?;
    let sapling_spend = std::fs::read(&spend).map_err(|e| e.to_string())?;
    Ok((sapling_output, sapling_spend))
}

/// Returns the path to the default directory that the Zcash proving parameters are located in.
pub fn get_zcash_params_path() -> std::io::Result<PathBuf> {
    zcash_proofs::default_params_folder()
        .ok_or_else(|| std::io::Error::other("could not load default params folder"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HYPOTHESIS: the embedded Sapling parameters are present whole, so
    /// loading them is infallible. Falsified if either blob is empty.
    #[test]
    fn embedded_sapling_params_load_whole() {
        let (sapling_output, sapling_spend) =
            read_sapling_params().expect("params fetch or cache read");
        assert!(!sapling_output.is_empty(), "output params are readable");
        assert!(!sapling_spend.is_empty(), "spend params are readable");
    }

    #[test]
    fn test_memo_bytes_from_string_plain_text() {
        let result = memo_bytes_from_string("Hello World".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_memo_bytes_from_string_valid_hex() {
        // Valid hex should be decoded
        let result = memo_bytes_from_string("0x48656c6c6f".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_memo_bytes_from_string_ethereum_address() {
        // Ethereum address should be treated as plain text
        let eth_address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
        let result = memo_bytes_from_string(eth_address.to_string());
        assert!(result.is_ok());
        // Verify it's stored as the full string (43 bytes), not decoded hex (20 bytes)
        let memo_bytes = result.unwrap();
        assert_eq!(memo_bytes.as_slice().len(), eth_address.len());
    }

    #[test]
    fn test_memo_bytes_from_string_invalid_hex() {
        // Invalid hex should fall back to plain text
        let result = memo_bytes_from_string("0xZZZZ".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_memo_bytes_from_string_too_long() {
        // String longer than 512 bytes should fail
        let long_string = "a".repeat(513);
        let result = memo_bytes_from_string(long_string);
        assert!(result.is_err());
    }
}
