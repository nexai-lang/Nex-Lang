#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::agent_bus::AgentId;

pub const EVIDENCE_DOMAIN_LEGACY: &[u8] = b"NEX-EVIDENCE-V1";
pub const EVIDENCE_DOMAIN_V0_8_1: &[u8] = b"NEX-EVIDENCE-V1";
pub const FILE_IDENTITY_PROVIDER_ID: &str = "file-v1";
pub const KEYCHAIN_IDENTITY_PROVIDER_ID: &str = "keychain-v1";
pub const TRUST_REGISTRY_FORMAT_VERSION: u32 = 1;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256 = 1,
}

impl HashAlg {
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[inline]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Sha256),
            _ => None,
        }
    }

    #[inline]
    pub const fn from_u32(v: u32) -> Option<Self> {
        if v > u16::MAX as u32 {
            return None;
        }
        Self::from_u16(v as u16)
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    Ed25519 = 1,
}

impl SigAlg {
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[inline]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Ed25519),
            _ => None,
        }
    }

    #[inline]
    pub const fn from_u32(v: u32) -> Option<Self> {
        if v > u16::MAX as u32 {
            return None;
        }
        Self::from_u16(v as u16)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceVersion {
    pub format: u32,
    pub hash_alg: HashAlg,
    pub sig_alg: SigAlg,
}

impl EvidenceVersion {
    pub const FORMAT_V0_8_1: u32 = 1;

    #[inline]
    pub const fn v0_8_1() -> Self {
        Self {
            format: Self::FORMAT_V0_8_1,
            hash_alg: HashAlg::Sha256,
            sig_alg: SigAlg::Ed25519,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityKeypair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

pub type SignatureBytes = [u8; 64];

pub trait IdentityProvider {
    fn sign(&self, msg: &[u8]) -> io::Result<SignatureBytes>;
    fn public_key(&self) -> io::Result<[u8; 32]>;
    fn provider_id(&self) -> &'static str;
}

#[derive(Clone, Debug)]
pub struct FileIdentityProvider {
    agent_id: AgentId,
    root: PathBuf,
}

impl FileIdentityProvider {
    pub fn new(agent_id: AgentId, root: PathBuf) -> Self {
        Self { agent_id, root }
    }

    fn ensure_keypair(&self) -> io::Result<IdentityKeypair> {
        ensure_keypair_at(self.agent_id, &self.root)
    }
}

impl IdentityProvider for FileIdentityProvider {
    fn sign(&self, msg: &[u8]) -> io::Result<SignatureBytes> {
        let keypair = self.ensure_keypair()?;
        let signing_key = SigningKey::from_bytes(&keypair.secret_key);
        Ok(signing_key.sign(msg).to_bytes())
    }

    fn public_key(&self) -> io::Result<[u8; 32]> {
        Ok(self.ensure_keypair()?.public_key)
    }

    fn provider_id(&self) -> &'static str {
        FILE_IDENTITY_PROVIDER_ID
    }
}

#[derive(Clone, Debug, Default)]
pub struct KeychainIdentityProviderStub;

impl IdentityProvider for KeychainIdentityProviderStub {
    fn sign(&self, _msg: &[u8]) -> io::Result<SignatureBytes> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "keychain identity provider is not implemented",
        ))
    }

    fn public_key(&self) -> io::Result<[u8; 32]> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "keychain identity provider is not implemented",
        ))
    }

    fn provider_id(&self) -> &'static str {
        KEYCHAIN_IDENTITY_PROVIDER_ID
    }
}

pub fn default_file_identity_provider(agent_id: AgentId) -> FileIdentityProvider {
    FileIdentityProvider::new(agent_id, resolve_home_root())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceChain {
    pub agent_id: AgentId,
    pub source_hash: [u8; 32],
    pub codegen_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub run_hash: [u8; 32],
    pub signature: SignatureBytes,
}

pub fn key_generate(_agent_id: AgentId) -> io::Result<IdentityKeypair> {
    let mut csprng = OsRng;
    let mut secret_key = [0u8; 32];
    csprng.fill_bytes(&mut secret_key);

    let signing_key = SigningKey::from_bytes(&secret_key);
    let public_key = signing_key.verifying_key().to_bytes();

    Ok(IdentityKeypair {
        public_key,
        secret_key,
    })
}

pub fn key_store(agent_id: AgentId, keypair: &IdentityKeypair) -> io::Result<()> {
    key_store_at(agent_id, keypair, &resolve_home_root())
}

pub fn key_load(agent_id: AgentId) -> io::Result<IdentityKeypair> {
    key_load_at(agent_id, &resolve_home_root())
}

pub fn key_load_public(agent_id: AgentId) -> io::Result<[u8; 32]> {
    Ok(key_load(agent_id)?.public_key)
}

pub fn key_rotate(agent_id: AgentId) -> io::Result<IdentityKeypair> {
    key_rotate_at(agent_id, &resolve_home_root())
}

pub fn ensure_keypair(agent_id: AgentId) -> io::Result<IdentityKeypair> {
    ensure_keypair_at(agent_id, &resolve_home_root())
}

pub fn ensure_keypair_at(agent_id: AgentId, root: &Path) -> io::Result<IdentityKeypair> {
    match key_load_at(agent_id, root) {
        Ok(kp) => Ok(kp),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let kp = key_generate(agent_id)?;
            key_store_at(agent_id, &kp, root)?;
            Ok(kp)
        }
        Err(e) => Err(e),
    }
}

pub fn key_store_at(agent_id: AgentId, keypair: &IdentityKeypair, root: &Path) -> io::Result<()> {
    let dir = keys_dir(root);
    fs::create_dir_all(&dir)?;

    let public_key_b64 = encode_b64(&keypair.public_key);
    let secret_key_b64 = encode_b64(&keypair.secret_key);

    let json = format!(
        "{{\"agent_id\":{},\"public_key_b64\":\"{}\",\"secret_key_b64\":\"{}\",\"created_epoch\":null}}\n",
        agent_id, public_key_b64, secret_key_b64
    );

    fs::write(agent_key_path(root, agent_id), json.as_bytes())
}

pub fn key_load_at(agent_id: AgentId, root: &Path) -> io::Result<IdentityKeypair> {
    let path = agent_key_path(root, agent_id);
    let doc = fs::read_to_string(&path)?;

    let parsed_agent_id = parse_json_u32(&doc, "agent_id")?;
    if parsed_agent_id != agent_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "agent id mismatch in {}: expected {}, got {}",
                path.display(),
                agent_id,
                parsed_agent_id
            ),
        ));
    }

    let public_key_b64 = parse_json_string(&doc, "public_key_b64")?;
    let secret_key_b64 = parse_json_string(&doc, "secret_key_b64")?;

    let public_key = decode_b64_fixed::<32>(&public_key_b64, "public_key_b64")?;
    let secret_key = decode_b64_fixed::<32>(&secret_key_b64, "secret_key_b64")?;

    Ok(IdentityKeypair {
        public_key,
        secret_key,
    })
}

pub fn key_rotate_at(agent_id: AgentId, root: &Path) -> io::Result<IdentityKeypair> {
    if let Ok(prev) = key_load_at(agent_id, root) {
        append_public_history(root, agent_id, prev.public_key)?;
    }

    let next = key_generate(agent_id)?;
    key_store_at(agent_id, &next, root)?;
    Ok(next)
}

pub fn load_public_history(agent_id: AgentId) -> io::Result<Vec<[u8; 32]>> {
    load_public_history_at(agent_id, &resolve_home_root())
}

pub fn load_public_history_at(agent_id: AgentId, root: &Path) -> io::Result<Vec<[u8; 32]>> {
    let path = agent_pubhist_path(root, agent_id);
    let doc = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut out = Vec::new();
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let pk_b64 = parse_json_string(trimmed, "public_key_b64")?;
        let pk = decode_b64_fixed::<32>(&pk_b64, "public_key_b64")?;
        out.push(pk);
    }
    Ok(out)
}

pub fn evidence_message_legacy(
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(EVIDENCE_DOMAIN_LEGACY.len() + 4 + 32 * 4);
    msg.extend_from_slice(EVIDENCE_DOMAIN_LEGACY);
    msg.extend_from_slice(&agent_id.to_le_bytes());
    msg.extend_from_slice(&source_hash);
    msg.extend_from_slice(&codegen_hash);
    msg.extend_from_slice(&policy_hash);
    msg.extend_from_slice(&run_hash);
    msg
}

pub fn evidence_message_v0_8_1(
    version: EvidenceVersion,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(EVIDENCE_DOMAIN_V0_8_1.len() + 2 + 2 + 2 + 4 + 32 * 4);
    msg.extend_from_slice(EVIDENCE_DOMAIN_V0_8_1);
    msg.extend_from_slice(&(version.format as u16).to_le_bytes());
    msg.extend_from_slice(&version.sig_alg.as_u16().to_le_bytes());
    msg.extend_from_slice(&version.hash_alg.as_u16().to_le_bytes());
    msg.extend_from_slice(&agent_id.to_le_bytes());
    msg.extend_from_slice(&source_hash);
    msg.extend_from_slice(&codegen_hash);
    msg.extend_from_slice(&policy_hash);
    msg.extend_from_slice(&run_hash);
    msg
}

pub fn evidence_message(
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> Vec<u8> {
    evidence_message_legacy(agent_id, source_hash, codegen_hash, policy_hash, run_hash)
}

pub fn sign_evidence_legacy(
    keypair: &IdentityKeypair,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> SignatureBytes {
    let msg = evidence_message_legacy(agent_id, source_hash, codegen_hash, policy_hash, run_hash);
    let signing_key = SigningKey::from_bytes(&keypair.secret_key);
    let sig = signing_key.sign(&msg);
    sig.to_bytes()
}

pub fn sign_evidence(
    keypair: &IdentityKeypair,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> SignatureBytes {
    sign_evidence_legacy(
        keypair,
        agent_id,
        source_hash,
        codegen_hash,
        policy_hash,
        run_hash,
    )
}

pub fn sign_evidence_v0_8_1(
    keypair: &IdentityKeypair,
    version: EvidenceVersion,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> SignatureBytes {
    let msg = evidence_message_v0_8_1(
        version,
        agent_id,
        source_hash,
        codegen_hash,
        policy_hash,
        run_hash,
    );
    let signing_key = SigningKey::from_bytes(&keypair.secret_key);
    let sig = signing_key.sign(&msg);
    sig.to_bytes()
}

pub fn sign_evidence_v0_8_1_with_provider(
    provider: &dyn IdentityProvider,
    version: EvidenceVersion,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> io::Result<SignatureBytes> {
    let msg = evidence_message_v0_8_1(
        version,
        agent_id,
        source_hash,
        codegen_hash,
        policy_hash,
        run_hash,
    );
    provider.sign(&msg)
}

pub fn verify_evidence_signature_legacy(
    public_key: &[u8; 32],
    signature: &SignatureBytes,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> bool {
    let msg = evidence_message_legacy(agent_id, source_hash, codegen_hash, policy_hash, run_hash);
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(&msg, &sig).is_ok()
}

pub fn verify_evidence_signature(
    public_key: &[u8; 32],
    signature: &SignatureBytes,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> bool {
    verify_evidence_signature_legacy(
        public_key,
        signature,
        agent_id,
        source_hash,
        codegen_hash,
        policy_hash,
        run_hash,
    )
}

pub fn verify_evidence_signature_v0_8_1(
    public_key: &[u8; 32],
    signature: &SignatureBytes,
    version: EvidenceVersion,
    agent_id: AgentId,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> bool {
    let msg = evidence_message_v0_8_1(
        version,
        agent_id,
        source_hash,
        codegen_hash,
        policy_hash,
        run_hash,
    );
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(&msg, &sig).is_ok()
}

pub fn encode_b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_b64_fixed<const N: usize>(value: &str, field: &str) -> io::Result<[u8; N]> {
    let decoded = STANDARD.decode(value).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid base64 in {}: {}", field, e),
        )
    })?;
    if decoded.len() != N {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} decoded len mismatch: expected {}, got {}",
                field,
                N,
                decoded.len()
            ),
        ));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

pub fn resolve_home_root() -> PathBuf {
    match env::var("NEX_HOME") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => PathBuf::from("./nex_data"),
    }
}

pub fn trust_registry_path(root: &Path) -> PathBuf {
    root.join("trust").join("registry.json")
}

pub fn load_trusted_public_keys() -> io::Result<Vec<String>> {
    load_trusted_public_keys_at(&resolve_home_root())
}

pub fn load_trusted_public_keys_at(root: &Path) -> io::Result<Vec<String>> {
    let path = trust_registry_path(root);
    let doc = match fs::read_to_string(&path) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let format_version = parse_json_u32(&doc, "format_version")?;
    if format_version != TRUST_REGISTRY_FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported trust registry format_version: {}",
                format_version
            ),
        ));
    }

    let mut keys = parse_json_string_array(&doc, "trusted_public_keys")?;
    keys.sort();
    keys.dedup();
    for key in &keys {
        decode_b64_fixed::<32>(key, "trusted_public_keys[]")?;
    }
    Ok(keys)
}

pub fn is_public_key_trusted(public_key_b64: &str) -> io::Result<bool> {
    is_public_key_trusted_at(&resolve_home_root(), public_key_b64)
}

pub fn is_public_key_trusted_at(root: &Path, public_key_b64: &str) -> io::Result<bool> {
    decode_b64_fixed::<32>(public_key_b64, "public_key_b64")?;
    let keys = load_trusted_public_keys_at(root)?;
    Ok(keys.iter().any(|k| k == public_key_b64))
}

pub fn register_trusted_public_key(public_key_b64: &str) -> io::Result<()> {
    register_trusted_public_key_at(&resolve_home_root(), public_key_b64)
}

pub fn register_trusted_public_key_at(root: &Path, public_key_b64: &str) -> io::Result<()> {
    decode_b64_fixed::<32>(public_key_b64, "public_key_b64")?;

    let mut keys = load_trusted_public_keys_at(root)?;
    if !keys.iter().any(|k| k == public_key_b64) {
        keys.push(public_key_b64.to_string());
    }
    keys.sort();
    keys.dedup();

    write_trust_registry_at(root, &keys)
}

fn write_trust_registry_at(root: &Path, trusted_public_keys: &[String]) -> io::Result<()> {
    let mut keys = trusted_public_keys.to_vec();
    keys.sort();
    keys.dedup();

    let trust_dir = root.join("trust");
    fs::create_dir_all(&trust_dir)?;

    let mut json = String::new();
    json.push_str("{\"format_version\":1,\"trusted_public_keys\":[");
    for (idx, key) in keys.iter().enumerate() {
        if idx > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(&escape_json(key));
        json.push('"');
    }
    json.push_str("]}\n");

    fs::write(trust_registry_path(root), json.as_bytes())
}

fn keys_dir(root: &Path) -> PathBuf {
    root.join("keys")
}

fn agent_key_path(root: &Path, agent_id: AgentId) -> PathBuf {
    keys_dir(root).join(format!("agent_{}.json", agent_id))
}

fn agent_pubhist_path(root: &Path, agent_id: AgentId) -> PathBuf {
    keys_dir(root).join(format!("agent_{}.pubhist.jsonl", agent_id))
}

fn append_public_history(root: &Path, agent_id: AgentId, public_key: [u8; 32]) -> io::Result<()> {
    let dir = keys_dir(root);
    fs::create_dir_all(&dir)?;

    let path = agent_pubhist_path(root, agent_id);
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;

    let line = format!(
        "{{\"agent_id\":{},\"public_key_b64\":\"{}\",\"created_epoch\":null}}\n",
        agent_id,
        encode_b64(&public_key)
    );
    f.write_all(line.as_bytes())
}

fn parse_json_u32(doc: &str, key: &str) -> io::Result<u32> {
    let raw = parse_json_value_slice(doc, key)?;
    raw.parse::<u32>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid u32 for {}: {}", key, e),
        )
    })
}

fn parse_json_string(doc: &str, key: &str) -> io::Result<String> {
    let mut slice = parse_json_value_slice(doc, key)?;
    if !slice.starts_with('"') || !slice.ends_with('"') || slice.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("field {} is not a JSON string", key),
        ));
    }
    slice = &slice[1..slice.len() - 1];
    if slice.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("field {} contains unsupported escapes", key),
        ));
    }
    Ok(slice.to_string())
}

fn parse_json_string_array(doc: &str, key: &str) -> io::Result<Vec<String>> {
    let raw = parse_json_value_slice(doc, key)?;
    if !raw.starts_with('[') || !raw.ends_with(']') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("field {} is not a JSON array", key),
        ));
    }

    let mut out = Vec::new();
    let mut rest = raw[1..raw.len() - 1].trim();
    while !rest.is_empty() {
        if !rest.starts_with('"') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("field {} contains non-string array value", key),
            ));
        }

        let tail = &rest[1..];
        let end = tail.find('"').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unterminated string in {}", key),
            )
        })?;
        let value = &tail[..end];
        if value.contains('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("field {} contains unsupported escapes", key),
            ));
        }
        out.push(value.to_string());

        rest = tail[end + 1..].trim_start();
        if rest.is_empty() {
            break;
        }

        if !rest.starts_with(',') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("field {} contains malformed array separator", key),
            ));
        }
        rest = rest[1..].trim_start();
    }

    Ok(out)
}

fn parse_json_value_slice<'a>(doc: &'a str, key: &str) -> io::Result<&'a str> {
    let needle = format!("\"{}\"", key);
    let key_pos = doc.find(&needle).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("missing field {}", key))
    })?;

    let after_key = &doc[key_pos + needle.len()..];
    let colon_pos = after_key.find(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing ':' for field {}", key),
        )
    })?;

    let mut value = after_key[colon_pos + 1..].trim_start();

    if value.starts_with('"') {
        let end = value[1..].find('"').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unterminated string for field {}", key),
            )
        })? + 2;
        return Ok(&value[..end]);
    }

    if value.starts_with('[') {
        let end = value.find(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unterminated array for field {}", key),
            )
        })? + 1;
        return Ok(&value[..end]);
    }

    let end = value
        .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
        .unwrap_or(value.len());
    value = &value[..end];
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("empty value for field {}", key),
        ));
    }
    Ok(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v081_message_domain_and_version_bytes_are_canonical() {
        let version = EvidenceVersion::v0_8_1();
        let msg =
            evidence_message_v0_8_1(version, 7, [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]);
        assert!(msg.starts_with(EVIDENCE_DOMAIN_V0_8_1));

        let off = EVIDENCE_DOMAIN_V0_8_1.len();
        assert_eq!(&msg[off..off + 2], &(version.format as u16).to_le_bytes());
        assert_eq!(
            &msg[off + 2..off + 4],
            &version.sig_alg.as_u16().to_le_bytes()
        );
        assert_eq!(
            &msg[off + 4..off + 6],
            &version.hash_alg.as_u16().to_le_bytes()
        );
    }

    #[test]
    fn fixed_ed25519_vector_verifies() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let vk = VerifyingKey::from_bytes(&public_key).expect("valid fixed public key");
        let sig = Signature::from_bytes(&signature);
        assert!(vk.verify(&[], &sig).is_ok());
    }

    #[test]
    fn fixed_ed25519_vector_fails_when_message_tampered() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let vk = VerifyingKey::from_bytes(&public_key).expect("valid fixed public key");
        let sig = Signature::from_bytes(&signature);
        assert!(vk.verify(&[0u8], &sig).is_err());
    }

    #[test]
    fn trust_registry_roundtrip_is_deterministic() {
        let root = std::env::temp_dir().join("nex_identity_registry_roundtrip");
        let _ = fs::remove_dir_all(&root);

        let key_a = encode_b64(&[1u8; 32]);
        let key_b = encode_b64(&[2u8; 32]);
        register_trusted_public_key_at(&root, &key_b).expect("register key b");
        register_trusted_public_key_at(&root, &key_a).expect("register key a");
        register_trusted_public_key_at(&root, &key_a).expect("register duplicate key a");

        let keys = load_trusted_public_keys_at(&root).expect("load registry keys");
        assert_eq!(keys, vec![key_a.clone(), key_b.clone()]);
        assert!(is_public_key_trusted_at(&root, &key_a).expect("trust lookup a"));
        assert!(is_public_key_trusted_at(&root, &key_b).expect("trust lookup b"));

        let _ = fs::remove_dir_all(&root);
    }
}
