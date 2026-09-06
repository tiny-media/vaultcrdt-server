use loro::VersionVector;
use std::collections::HashMap;

use crate::errors::ServerError;

/// VersionVector → JSON bytes (wire format, compatible with TS JSON.parse)
pub fn vv_to_json_bytes(vv: &VersionVector) -> Vec<u8> {
    let map: HashMap<String, i32> = vv.iter().map(|(&k, &v)| (k.to_string(), v)).collect();
    serde_json::to_vec(&map).expect("VV serialization cannot fail")
}

/// JSON bytes → VersionVector
pub fn vv_from_json_bytes(bytes: &[u8]) -> Result<VersionVector, ServerError> {
    let map: HashMap<String, i32> = serde_json::from_slice(bytes)
        .map_err(|e| ServerError::Sync(format!("invalid VV JSON: {e}")))?;
    let mut vv = VersionVector::new();
    for (peer_str, counter) in map {
        let peer: u64 = peer_str
            .parse()
            .map_err(|e| ServerError::Sync(format!("invalid peer ID in VV: {e}")))?;
        vv.insert(peer, counter);
    }
    Ok(vv)
}

/// VersionVector → binary bytes (DB format, Loro native encoding)
pub fn vv_to_db_bytes(vv: &VersionVector) -> Vec<u8> {
    vv.encode()
}

/// DB bytes → VersionVector
pub fn vv_from_db_bytes(bytes: &[u8]) -> Result<VersionVector, ServerError> {
    VersionVector::decode(bytes).map_err(|e| ServerError::Sync(format!("invalid VV bytes: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_roundtrip() {
        let mut vv = VersionVector::new();
        vv.insert(42, 10);
        vv.insert(99, 5);

        let bytes = vv_to_json_bytes(&vv);
        let decoded = vv_from_json_bytes(&bytes).unwrap();

        assert_eq!(decoded.get(&42), Some(&10));
        assert_eq!(decoded.get(&99), Some(&5));
    }

    #[test]
    fn test_db_roundtrip() {
        let mut vv = VersionVector::new();
        vv.insert(42, 10);
        vv.insert(99, 5);

        let bytes = vv_to_db_bytes(&vv);
        let decoded = vv_from_db_bytes(&bytes).unwrap();

        assert_eq!(decoded.get(&42), Some(&10));
        assert_eq!(decoded.get(&99), Some(&5));
    }

    #[test]
    fn test_empty_vv() {
        let vv = VersionVector::new();

        let json = vv_to_json_bytes(&vv);
        let db = vv_to_db_bytes(&vv);

        let json_decoded = vv_from_json_bytes(&json).unwrap();
        let db_decoded = vv_from_db_bytes(&db).unwrap();

        assert!(json_decoded.is_empty());
        assert!(db_decoded.is_empty());
    }
}
