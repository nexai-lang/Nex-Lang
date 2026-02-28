use crate::replay::{self, ReplayOptions, ReplayResult};
use crate::runtime::event_reader::{EventReader, KIND_EVIDENCE_FINAL};
use crate::runtime::identity;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};

pub const BUNDLE_MAGIC: [u8; 4] = *b"NEXB";
pub const BUNDLE_FORMAT_VERSION: u16 = 1;
pub const BUNDLE_HASH_ALG_SHA256: u8 = 1;
pub const BUNDLE_SIG_ALG_ED25519: u8 = 1;
pub const BUNDLE_FLAG_NONE: u8 = 0;

const DEFAULT_MAX_BUNDLE_BYTES: usize = 768 * 1024 * 1024;
const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_EVENTS_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_MAX_EVIDENCE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BundleData {
    pub format_version: u16,
    pub hash_alg: u8,
    pub sig_alg: u8,
    pub flags: u8,
    pub header_json: String,
    pub events_bytes: Vec<u8>,
    pub evidence_bytes: Vec<u8>,
    pub policy_bytes: Vec<u8>,
    pub source_bytes: Vec<u8>,
    pub codegen_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct BundleHeaderMeta {
    bundle_format: String,
    compression: String,
    events_sha256_hex: String,
    evidence_sha256_hex: String,
    source_hash_hex: String,
    codegen_hash_hex: String,
    policy_hash_hex: String,
    provider_id: String,
    public_key_b64: String,
    sig_mode: String,
}

#[derive(Debug, Clone)]
struct BundleHeaderWrite<'a> {
    events_sha256_hex: &'a str,
    evidence_sha256_hex: &'a str,
    source_hash_hex: &'a str,
    codegen_hash_hex: &'a str,
    policy_hash_hex: &'a str,
    provider_id: &'a str,
    public_key_b64: &'a str,
    sig_mode: &'a str,
}

#[derive(Debug, Clone)]
struct EvidenceSummary {
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    public_key_b64: String,
    signature_b64: String,
    provider_id: String,
    hash_alg: u8,
    sig_alg: u8,
    sig_mode: String,
}

#[derive(Debug, Clone)]
struct EventsEvidence {
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    evidence_payload: Vec<u8>,
}

fn err_invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn create_bundle<P: AsRef<Path>, Q: AsRef<Path>>(
    events_path: P,
    out_path: Q,
) -> io::Result<()> {
    let events_path = events_path.as_ref();
    let out_path = out_path.as_ref();

    let events_bytes = fs::read(events_path)?;
    ensure_len_cap(
        "events section",
        events_bytes.len(),
        cap_from_env("NEX_BUNDLE_MAX_EVENTS_BYTES", DEFAULT_MAX_EVENTS_BYTES),
    )?;

    let extracted = extract_events_evidence(&events_bytes)?;
    let evidence = parse_evidence_payload(&extracted.evidence_payload)?;

    let events_sha256_hex = sha256_hex(&events_bytes);
    let evidence_sha256_hex = sha256_hex(&extracted.evidence_payload);
    let source_hash_hex = hex::encode(extracted.source_hash);
    let codegen_hash_hex = hex::encode(extracted.codegen_hash);
    let policy_hash_hex = hex::encode(evidence.policy_hash);

    let header_json = canonical_header_json(BundleHeaderWrite {
        events_sha256_hex: &events_sha256_hex,
        evidence_sha256_hex: &evidence_sha256_hex,
        source_hash_hex: &source_hash_hex,
        codegen_hash_hex: &codegen_hash_hex,
        policy_hash_hex: &policy_hash_hex,
        provider_id: &evidence.provider_id,
        public_key_b64: &evidence.public_key_b64,
        sig_mode: &evidence.sig_mode,
    });
    ensure_len_cap(
        "bundle header",
        header_json.len(),
        cap_from_env("NEX_BUNDLE_MAX_HEADER_BYTES", DEFAULT_MAX_HEADER_BYTES),
    )?;

    let policy_bytes = policy_hash_hex.as_bytes().to_vec();
    let source_bytes = source_hash_hex.as_bytes().to_vec();
    let codegen_bytes = codegen_hash_hex.as_bytes().to_vec();

    let mut out = Vec::new();
    out.extend_from_slice(&BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_FORMAT_VERSION.to_le_bytes());
    out.push(evidence.hash_alg);
    out.push(evidence.sig_alg);
    out.push(BUNDLE_FLAG_NONE);

    let header_len = u32::try_from(header_json.len())
        .map_err(|_| err_invalid("bundle header length does not fit in u32"))?;
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(header_json.as_bytes());

    append_section(&mut out, &events_bytes)?;
    append_section(&mut out, &extracted.evidence_payload)?;
    append_section(&mut out, &policy_bytes)?;
    append_section(&mut out, &source_bytes)?;
    append_section(&mut out, &codegen_bytes)?;

    ensure_len_cap(
        "bundle",
        out.len(),
        cap_from_env("NEX_BUNDLE_MAX_BYTES", DEFAULT_MAX_BUNDLE_BYTES),
    )?;

    fs::write(out_path, out)
}

pub fn read_bundle<P: AsRef<Path>>(bundle_path: P) -> io::Result<BundleData> {
    let bundle_path = bundle_path.as_ref();
    let max_bundle = cap_from_env("NEX_BUNDLE_MAX_BYTES", DEFAULT_MAX_BUNDLE_BYTES);

    let meta = fs::metadata(bundle_path)?;
    if meta.len() > max_bundle as u64 {
        return Err(err_invalid(format!(
            "bundle size {} exceeds max {}",
            meta.len(),
            max_bundle
        )));
    }

    let bytes = fs::read(bundle_path)?;
    parse_bundle_bytes(&bytes)
}

pub fn replay_bundle_with_options<P: AsRef<Path>>(
    bundle_path: P,
    options: ReplayOptions,
) -> io::Result<ReplayResult> {
    let bundle = read_bundle(bundle_path)?;
    validate_bundle(&bundle)?;

    let temp_events_path = replay_temp_events_path(&bundle.events_bytes);
    fs::write(&temp_events_path, &bundle.events_bytes)?;

    let replay_result = replay::verify_log_with_options(&temp_events_path, options);
    let _ = fs::remove_file(&temp_events_path);
    replay_result
}

fn replay_temp_events_path(events_bytes: &[u8]) -> PathBuf {
    let digest = sha256_hex(events_bytes);
    let short = &digest[..16];
    env::temp_dir().join(format!("nex_bundle_replay_{}.events.bin", short))
}

fn parse_bundle_bytes(bytes: &[u8]) -> io::Result<BundleData> {
    ensure_len_cap(
        "bundle",
        bytes.len(),
        cap_from_env("NEX_BUNDLE_MAX_BYTES", DEFAULT_MAX_BUNDLE_BYTES),
    )?;

    let mut offset = 0usize;

    let magic = read_bytes(bytes, &mut offset, 4, "magic")?;
    if magic != BUNDLE_MAGIC {
        return Err(err_invalid("invalid bundle magic"));
    }

    let format_version = read_u16(bytes, &mut offset, "format_version")?;
    if format_version != BUNDLE_FORMAT_VERSION {
        return Err(err_invalid(format!(
            "unsupported bundle format_version: {}",
            format_version
        )));
    }

    let hash_alg = read_u8(bytes, &mut offset, "hash_alg")?;
    let sig_alg = read_u8(bytes, &mut offset, "sig_alg")?;
    let flags = read_u8(bytes, &mut offset, "flags")?;

    let header_len = usize::try_from(read_u32(bytes, &mut offset, "header_len")?)
        .map_err(|_| err_invalid("header_len does not fit usize"))?;
    ensure_len_cap(
        "bundle header",
        header_len,
        cap_from_env("NEX_BUNDLE_MAX_HEADER_BYTES", DEFAULT_MAX_HEADER_BYTES),
    )?;

    let header_bytes = read_bytes(bytes, &mut offset, header_len, "header_json")?;
    let header_json = std::str::from_utf8(&header_bytes)
        .map_err(|e| err_invalid(format!("bundle header_json utf8: {}", e)))?
        .to_string();

    let events_bytes = read_section(
        bytes,
        &mut offset,
        "events",
        cap_from_env("NEX_BUNDLE_MAX_EVENTS_BYTES", DEFAULT_MAX_EVENTS_BYTES),
    )?;
    let evidence_bytes = read_section(
        bytes,
        &mut offset,
        "evidence",
        cap_from_env("NEX_BUNDLE_MAX_EVIDENCE_BYTES", DEFAULT_MAX_EVIDENCE_BYTES),
    )?;
    let policy_bytes = read_section(
        bytes,
        &mut offset,
        "policy",
        cap_from_env("NEX_BUNDLE_MAX_ARTIFACT_BYTES", DEFAULT_MAX_ARTIFACT_BYTES),
    )?;
    let source_bytes = read_section(
        bytes,
        &mut offset,
        "source",
        cap_from_env("NEX_BUNDLE_MAX_ARTIFACT_BYTES", DEFAULT_MAX_ARTIFACT_BYTES),
    )?;
    let codegen_bytes = read_section(
        bytes,
        &mut offset,
        "codegen",
        cap_from_env("NEX_BUNDLE_MAX_ARTIFACT_BYTES", DEFAULT_MAX_ARTIFACT_BYTES),
    )?;

    if offset != bytes.len() {
        return Err(err_invalid("bundle has trailing bytes"));
    }

    Ok(BundleData {
        format_version,
        hash_alg,
        sig_alg,
        flags,
        header_json,
        events_bytes,
        evidence_bytes,
        policy_bytes,
        source_bytes,
        codegen_bytes,
    })
}

fn validate_bundle(bundle: &BundleData) -> io::Result<()> {
    if bundle.format_version != BUNDLE_FORMAT_VERSION {
        return Err(err_invalid(format!(
            "unsupported bundle format_version: {}",
            bundle.format_version
        )));
    }

    if bundle.flags != BUNDLE_FLAG_NONE {
        return Err(err_invalid(format!(
            "unsupported bundle flags: {}",
            bundle.flags
        )));
    }

    if bundle.hash_alg != BUNDLE_HASH_ALG_SHA256 {
        return Err(err_invalid(format!(
            "unsupported bundle hash_alg: {}",
            bundle.hash_alg
        )));
    }

    if bundle.sig_alg != BUNDLE_SIG_ALG_ED25519 {
        return Err(err_invalid(format!(
            "unsupported bundle sig_alg: {}",
            bundle.sig_alg
        )));
    }

    let header = parse_bundle_header_json(&bundle.header_json)?;
    if header.bundle_format != "nexbundle-v1" {
        return Err(err_invalid("unsupported bundle_format in header_json"));
    }
    if header.compression != "none" {
        return Err(err_invalid("unsupported compression in header_json"));
    }

    let extracted = extract_events_evidence(&bundle.events_bytes)?;
    if extracted.evidence_payload != bundle.evidence_bytes {
        return Err(err_invalid(
            "bundle evidence section mismatch with events stream",
        ));
    }

    let evidence = parse_evidence_payload(&bundle.evidence_bytes)?;

    if evidence.hash_alg != bundle.hash_alg {
        return Err(err_invalid("bundle hash_alg does not match evidence"));
    }

    if evidence.sig_alg != bundle.sig_alg {
        return Err(err_invalid("bundle sig_alg does not match evidence"));
    }

    if header.provider_id != evidence.provider_id {
        return Err(err_invalid("header provider_id mismatch"));
    }
    if header.public_key_b64 != evidence.public_key_b64 {
        return Err(err_invalid("header public_key_b64 mismatch"));
    }
    if header.sig_mode != evidence.sig_mode {
        return Err(err_invalid("header sig_mode mismatch"));
    }

    let events_sha256_hex = sha256_hex(&bundle.events_bytes);
    if header.events_sha256_hex != events_sha256_hex {
        return Err(err_invalid("header events_sha256_hex mismatch"));
    }

    let evidence_sha256_hex = sha256_hex(&bundle.evidence_bytes);
    if header.evidence_sha256_hex != evidence_sha256_hex {
        return Err(err_invalid("header evidence_sha256_hex mismatch"));
    }

    let source_hash_hex = hex::encode(extracted.source_hash);
    if header.source_hash_hex != source_hash_hex {
        return Err(err_invalid("header source_hash_hex mismatch"));
    }

    let codegen_hash_hex = hex::encode(extracted.codegen_hash);
    if header.codegen_hash_hex != codegen_hash_hex {
        return Err(err_invalid("header codegen_hash_hex mismatch"));
    }

    let policy_hash_hex = hex::encode(evidence.policy_hash);
    if header.policy_hash_hex != policy_hash_hex {
        return Err(err_invalid("header policy_hash_hex mismatch"));
    }

    if !bundle.policy_bytes.is_empty() {
        let policy_hex = std::str::from_utf8(&bundle.policy_bytes)
            .map_err(|e| err_invalid(format!("policy section utf8: {}", e)))?;
        if policy_hex != policy_hash_hex {
            return Err(err_invalid("policy section hash mismatch"));
        }
    }

    if !bundle.source_bytes.is_empty() {
        let source_hex = std::str::from_utf8(&bundle.source_bytes)
            .map_err(|e| err_invalid(format!("source section utf8: {}", e)))?;
        if source_hex != source_hash_hex {
            return Err(err_invalid("source section hash mismatch"));
        }
    }

    if !bundle.codegen_bytes.is_empty() {
        let codegen_hex = std::str::from_utf8(&bundle.codegen_bytes)
            .map_err(|e| err_invalid(format!("codegen section utf8: {}", e)))?;
        if codegen_hex != codegen_hash_hex {
            return Err(err_invalid("codegen section hash mismatch"));
        }
    }

    Ok(())
}

fn parse_evidence_payload(payload: &[u8]) -> io::Result<EvidenceSummary> {
    const LEGACY_FIXED: usize = 4 + 32 * 4;
    const V081_FIXED: usize = 4 + 4 + 4 + 4 + 32 * 4;

    if payload.len() < LEGACY_FIXED + 2 + 2 {
        return Err(err_invalid(format!(
            "EvidenceFinal payload too short: {}",
            payload.len()
        )));
    }

    fn read_u32_at(payload: &[u8], off: usize, field: &str) -> io::Result<u32> {
        let end = off.saturating_add(4);
        let bytes = payload
            .get(off..end)
            .ok_or_else(|| err_invalid(format!("EvidenceFinal {} out of bounds", field)))?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(arr))
    }

    fn read_arr32_at(payload: &[u8], off: usize, field: &str) -> io::Result<[u8; 32]> {
        let end = off.saturating_add(32);
        let bytes = payload
            .get(off..end)
            .ok_or_else(|| err_invalid(format!("EvidenceFinal {} out of bounds", field)))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn parse_tail(payload: &[u8], prefix_len: usize) -> io::Result<(String, String, String)> {
        let pk_len_end = prefix_len.saturating_add(2);
        let pk_len_bytes = payload
            .get(prefix_len..pk_len_end)
            .ok_or_else(|| err_invalid("EvidenceFinal public key length out of bounds"))?;
        let pk_len = u16::from_le_bytes([pk_len_bytes[0], pk_len_bytes[1]]) as usize;

        let pk_start = pk_len_end;
        let pk_end = pk_start.saturating_add(pk_len);
        if pk_end + 2 > payload.len() {
            return Err(err_invalid("EvidenceFinal public key length out of bounds"));
        }

        let sig_len_bytes = &payload[pk_end..pk_end + 2];
        let sig_len = u16::from_le_bytes([sig_len_bytes[0], sig_len_bytes[1]]) as usize;
        let sig_start = pk_end + 2;
        let sig_end = sig_start.saturating_add(sig_len);
        if sig_end > payload.len() {
            return Err(err_invalid("EvidenceFinal signature length mismatch"));
        }

        let public_key_b64 = std::str::from_utf8(&payload[pk_start..pk_end])
            .map_err(|e| err_invalid(format!("EvidenceFinal public key utf8: {}", e)))?
            .to_string();

        let signature_b64 = std::str::from_utf8(&payload[sig_start..sig_end])
            .map_err(|e| err_invalid(format!("EvidenceFinal signature utf8: {}", e)))?
            .to_string();

        let provider_id = if sig_end == payload.len() {
            identity::FILE_IDENTITY_PROVIDER_ID.to_string()
        } else {
            if sig_end + 2 > payload.len() {
                return Err(err_invalid(
                    "EvidenceFinal provider_id length out of bounds",
                ));
            }
            let provider_len =
                u16::from_le_bytes([payload[sig_end], payload[sig_end + 1]]) as usize;
            let provider_start = sig_end + 2;
            let provider_end = provider_start.saturating_add(provider_len);
            if provider_end != payload.len() {
                return Err(err_invalid("EvidenceFinal provider_id length mismatch"));
            }
            std::str::from_utf8(&payload[provider_start..provider_end])
                .map_err(|e| err_invalid(format!("EvidenceFinal provider_id utf8: {}", e)))?
                .to_string()
        };

        Ok((public_key_b64, signature_b64, provider_id))
    }

    if payload.len() >= V081_FIXED + 2 + 2 {
        let format = read_u32_at(payload, 0, "format")?;
        let hash_alg_raw = read_u32_at(payload, 4, "hash_alg")?;
        let sig_alg_raw = read_u32_at(payload, 8, "sig_alg")?;

        if let Ok((public_key_b64, signature_b64, provider_id)) = parse_tail(payload, V081_FIXED) {
            let hash_alg = identity::HashAlg::from_u32(hash_alg_raw).ok_or_else(|| {
                err_invalid(format!("unsupported evidence hash_alg: {}", hash_alg_raw))
            })?;
            let sig_alg = identity::SigAlg::from_u32(sig_alg_raw).ok_or_else(|| {
                err_invalid(format!("unsupported evidence sig_alg: {}", sig_alg_raw))
            })?;
            if format != identity::EvidenceVersion::FORMAT_V0_8_1 {
                return Err(err_invalid(format!(
                    "unsupported evidence format: {}",
                    format
                )));
            }

            identity::decode_b64_fixed::<32>(&public_key_b64, "public_key_b64")?;
            identity::decode_b64_fixed::<64>(&signature_b64, "signature_b64")?;

            return Ok(EvidenceSummary {
                source_hash: read_arr32_at(payload, 16, "source_hash")?,
                codegen_hash: read_arr32_at(payload, 48, "codegen_hash")?,
                policy_hash: read_arr32_at(payload, 80, "policy_hash")?,
                public_key_b64,
                signature_b64,
                provider_id,
                hash_alg: hash_alg.as_u16() as u8,
                sig_alg: sig_alg.as_u16() as u8,
                sig_mode: "v0.8.1".to_string(),
            });
        }
    }

    let (public_key_b64, signature_b64, provider_id) = parse_tail(payload, LEGACY_FIXED)?;
    identity::decode_b64_fixed::<32>(&public_key_b64, "public_key_b64")?;
    identity::decode_b64_fixed::<64>(&signature_b64, "signature_b64")?;

    Ok(EvidenceSummary {
        source_hash: read_arr32_at(payload, 4, "source_hash")?,
        codegen_hash: read_arr32_at(payload, 36, "codegen_hash")?,
        policy_hash: read_arr32_at(payload, 68, "policy_hash")?,
        public_key_b64,
        signature_b64,
        provider_id,
        hash_alg: BUNDLE_HASH_ALG_SHA256,
        sig_alg: BUNDLE_SIG_ALG_ED25519,
        sig_mode: "legacy-v0.8.0".to_string(),
    })
}

fn extract_events_evidence(events_bytes: &[u8]) -> io::Result<EventsEvidence> {
    let mut reader = EventReader::new(Cursor::new(events_bytes));
    let header = reader.read_log_header()?;

    let mut evidence_payload: Option<Vec<u8>> = None;

    while let Some(ev) = reader.read_next()? {
        if ev.kind == KIND_EVIDENCE_FINAL {
            if evidence_payload.is_some() {
                return Err(err_invalid("duplicate EvidenceFinal in events stream"));
            }
            evidence_payload = Some(ev.payload);
        }
    }

    let evidence_payload =
        evidence_payload.ok_or_else(|| err_invalid("missing EvidenceFinal in events stream"))?;

    Ok(EventsEvidence {
        source_hash: header.source_hash,
        codegen_hash: header.codegen_hash,
        evidence_payload,
    })
}

fn parse_bundle_header_json(doc: &str) -> io::Result<BundleHeaderMeta> {
    Ok(BundleHeaderMeta {
        bundle_format: parse_json_string(doc, "bundle_format")?,
        compression: parse_json_string(doc, "compression")?,
        events_sha256_hex: parse_json_string(doc, "events_sha256_hex")?,
        evidence_sha256_hex: parse_json_string(doc, "evidence_sha256_hex")?,
        source_hash_hex: parse_json_string(doc, "source_hash_hex")?,
        codegen_hash_hex: parse_json_string(doc, "codegen_hash_hex")?,
        policy_hash_hex: parse_json_string(doc, "policy_hash_hex")?,
        provider_id: parse_json_string(doc, "provider_id")?,
        public_key_b64: parse_json_string(doc, "public_key_b64")?,
        sig_mode: parse_json_string(doc, "sig_mode")?,
    })
}

fn canonical_header_json(meta: BundleHeaderWrite<'_>) -> String {
    format!(
        "{{\"bundle_format\":\"nexbundle-v1\",\"codegen_hash_hex\":\"{}\",\"compression\":\"none\",\"evidence_sha256_hex\":\"{}\",\"events_sha256_hex\":\"{}\",\"policy_hash_hex\":\"{}\",\"provider_id\":\"{}\",\"public_key_b64\":\"{}\",\"sig_mode\":\"{}\",\"source_hash_hex\":\"{}\"}}",
        escape_json(meta.codegen_hash_hex),
        escape_json(meta.evidence_sha256_hex),
        escape_json(meta.events_sha256_hex),
        escape_json(meta.policy_hash_hex),
        escape_json(meta.provider_id),
        escape_json(meta.public_key_b64),
        escape_json(meta.sig_mode),
        escape_json(meta.source_hash_hex),
    )
}

fn append_section(dst: &mut Vec<u8>, section: &[u8]) -> io::Result<()> {
    let len = u64::try_from(section.len())
        .map_err(|_| err_invalid("section length does not fit in u64"))?;
    dst.extend_from_slice(&len.to_le_bytes());
    dst.extend_from_slice(section);
    Ok(())
}

fn read_section(
    bytes: &[u8],
    offset: &mut usize,
    section_name: &str,
    cap: usize,
) -> io::Result<Vec<u8>> {
    let declared = read_u64(bytes, offset, &format!("{}_len", section_name))?;
    let len = usize::try_from(declared).map_err(|_| {
        err_invalid(format!(
            "{} section length {} does not fit usize",
            section_name, declared
        ))
    })?;
    ensure_len_cap(&format!("{} section", section_name), len, cap)?;
    read_bytes(bytes, offset, len, section_name)
}

fn read_u8(bytes: &[u8], offset: &mut usize, field: &str) -> io::Result<u8> {
    let next = offset
        .checked_add(1)
        .ok_or_else(|| err_invalid(format!("{} offset overflow", field)))?;
    if next > bytes.len() {
        return Err(err_invalid(format!("{} out of bounds", field)));
    }
    let v = bytes[*offset];
    *offset = next;
    Ok(v)
}

fn read_u16(bytes: &[u8], offset: &mut usize, field: &str) -> io::Result<u16> {
    let data = read_bytes(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

fn read_u32(bytes: &[u8], offset: &mut usize, field: &str) -> io::Result<u32> {
    let data = read_bytes(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn read_u64(bytes: &[u8], offset: &mut usize, field: &str) -> io::Result<u64> {
    let data = read_bytes(bytes, offset, 8, field)?;
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

fn read_bytes(bytes: &[u8], offset: &mut usize, len: usize, field: &str) -> io::Result<Vec<u8>> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| err_invalid(format!("{} offset overflow", field)))?;
    if end > bytes.len() {
        return Err(err_invalid(format!("{} out of bounds", field)));
    }
    let out = bytes[*offset..end].to_vec();
    *offset = end;
    Ok(out)
}

fn ensure_len_cap(name: &str, len: usize, cap: usize) -> io::Result<()> {
    if len > cap {
        return Err(err_invalid(format!(
            "{} length {} exceeds cap {}",
            name, len, cap
        )));
    }
    Ok(())
}

fn cap_from_env(var: &str, default: usize) -> usize {
    match env::var(var) {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(parsed) => parsed.min(usize::MAX as u64) as usize,
            Err(_) => default,
        },
        Err(_) => default,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn parse_json_string(doc: &str, key: &str) -> io::Result<String> {
    let needle = format!("\"{}\":\"", key);
    let key_pos = doc
        .find(&needle)
        .ok_or_else(|| err_invalid(format!("missing JSON string key '{}'", key)))?;
    let mut i = key_pos + needle.len();
    let bytes = doc.as_bytes();
    let mut out = String::new();

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            return Ok(out);
        }
        if b == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return Err(err_invalid(format!("invalid escape in '{}'", key)));
            }
            let esc = bytes[i] as char;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                _ => {
                    return Err(err_invalid(format!(
                        "unsupported escape \\{} in '{}'",
                        esc, key
                    )))
                }
            }
        } else {
            out.push(b as char);
        }
        i += 1;
    }

    Err(err_invalid(format!(
        "unterminated JSON string for key '{}'",
        key
    )))
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

#[allow(dead_code)]
pub fn extract_bundle_public_key_b64<P: AsRef<Path>>(bundle_path: P) -> io::Result<String> {
    let bundle = read_bundle(bundle_path)?;
    let evidence = parse_evidence_payload(&bundle.evidence_bytes)?;
    Ok(evidence.public_key_b64)
}

#[allow(dead_code)]
pub fn extract_bundle_signature_b64<P: AsRef<Path>>(bundle_path: P) -> io::Result<String> {
    let bundle = read_bundle(bundle_path)?;
    let evidence = parse_evidence_payload(&bundle.evidence_bytes)?;
    Ok(evidence.signature_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_json_is_canonical_and_parseable() {
        let s = canonical_header_json(BundleHeaderWrite {
            events_sha256_hex: "aa",
            evidence_sha256_hex: "bb",
            source_hash_hex: "cc",
            codegen_hash_hex: "dd",
            policy_hash_hex: "ee",
            provider_id: "file-v1",
            public_key_b64: "pk",
            sig_mode: "v0.8.1",
        });

        let parsed = parse_bundle_header_json(&s).expect("parse header_json");
        assert_eq!(parsed.bundle_format, "nexbundle-v1");
        assert_eq!(parsed.compression, "none");
        assert_eq!(parsed.events_sha256_hex, "aa");
        assert_eq!(parsed.evidence_sha256_hex, "bb");
        assert_eq!(parsed.source_hash_hex, "cc");
        assert_eq!(parsed.codegen_hash_hex, "dd");
        assert_eq!(parsed.policy_hash_hex, "ee");
        assert_eq!(parsed.provider_id, "file-v1");
        assert_eq!(parsed.public_key_b64, "pk");
        assert_eq!(parsed.sig_mode, "v0.8.1");
    }
}
