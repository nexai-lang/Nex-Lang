use std::fmt;

use super::capability_flow::{
    self, AgentBoundaryFlow, CapabilityFlowReport, FunctionCapabilityFlow, TaskBoundaryFlow,
};
use super::schema_validation::{self, ChannelSchemaDecl, ChannelSendUse, SchemaValidationReport};
use crate::hir::types;

pub const GOVERNANCEFACTS_MAGIC: [u8; 8] = *b"NEXGOV\0\0";
pub const GOVERNANCEFACTS_VERSION: u32 = 1;

#[derive(Debug)]
pub enum GovernanceFactsError {
    CapabilityFlow(capability_flow::CapabilityFlowError),
    SchemaValidation(schema_validation::SchemaValidationError),
}

impl fmt::Display for GovernanceFactsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GovernanceFactsError::CapabilityFlow(err) => write!(f, "{}", err),
            GovernanceFactsError::SchemaValidation(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for GovernanceFactsError {}

impl From<capability_flow::CapabilityFlowError> for GovernanceFactsError {
    fn from(value: capability_flow::CapabilityFlowError) -> Self {
        GovernanceFactsError::CapabilityFlow(value)
    }
}

impl From<schema_validation::SchemaValidationError> for GovernanceFactsError {
    fn from(value: schema_validation::SchemaValidationError) -> Self {
        GovernanceFactsError::SchemaValidation(value)
    }
}

pub fn encode(program: &types::Program) -> Result<Vec<u8>, GovernanceFactsError> {
    let capability_report = capability_flow::analyze(program);
    capability_flow::enforce_declared_capabilities(program, &capability_report)?;

    let schema_report = schema_validation::analyze(program);
    schema_validation::enforce(&schema_report)?;

    Ok(encode_from_reports(&capability_report, &schema_report))
}

pub fn encode_from_reports(
    capability_report: &CapabilityFlowReport,
    schema_report: &SchemaValidationReport,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GOVERNANCEFACTS_MAGIC);
    write_u32(&mut out, GOVERNANCEFACTS_VERSION);

    encode_capability_flow(capability_report, &mut out);
    encode_schema_validation(schema_report, &mut out);

    out
}

fn encode_capability_flow(report: &CapabilityFlowReport, dst: &mut Vec<u8>) {
    let mut function_flows = report.function_flows.clone();
    function_flows.sort_by(|a, b| capability_flow_order(a).cmp(&capability_flow_order(b)));

    write_len(dst, function_flows.len());
    for flow in &function_flows {
        encode_function_flow(flow, dst);
    }

    let mut task_boundaries = report.task_boundaries.clone();
    task_boundaries.sort_by(|a, b| task_boundary_order(a).cmp(&task_boundary_order(b)));

    write_len(dst, task_boundaries.len());
    for boundary in &task_boundaries {
        encode_task_boundary(boundary, dst);
    }

    let mut agent_boundaries = report.agent_boundaries.clone();
    agent_boundaries.sort_by(|a, b| agent_boundary_order(a).cmp(&agent_boundary_order(b)));

    write_len(dst, agent_boundaries.len());
    for boundary in &agent_boundaries {
        encode_agent_boundary(boundary, dst);
    }
}

fn capability_flow_order(flow: &FunctionCapabilityFlow) -> (String, usize, usize) {
    (
        flow.function.clone(),
        flow.name_span.line,
        flow.name_span.col,
    )
}

fn task_boundary_order(boundary: &TaskBoundaryFlow) -> (String, usize, usize) {
    (
        boundary.function.clone(),
        boundary.span.line,
        boundary.span.col,
    )
}

fn agent_boundary_order(boundary: &AgentBoundaryFlow) -> (String, usize, usize, String) {
    (
        boundary.function.clone(),
        boundary.span.line,
        boundary.span.col,
        boundary.required_capability.clone(),
    )
}

fn encode_function_flow(flow: &FunctionCapabilityFlow, dst: &mut Vec<u8>) {
    write_string(dst, &flow.function);
    write_u64(dst, flow.name_span.line as u64);
    write_u64(dst, flow.name_span.col as u64);

    let mut caps = flow.required_capabilities.clone();
    caps.sort();
    caps.dedup();

    write_len(dst, caps.len());
    for capability in &caps {
        write_string(dst, capability);
    }
}

fn encode_task_boundary(boundary: &TaskBoundaryFlow, dst: &mut Vec<u8>) {
    write_string(dst, &boundary.function);
    write_u64(dst, boundary.span.line as u64);
    write_u64(dst, boundary.span.col as u64);

    let mut caps = boundary.required_capabilities.clone();
    caps.sort();
    caps.dedup();

    write_len(dst, caps.len());
    for capability in &caps {
        write_string(dst, capability);
    }
}

fn encode_agent_boundary(boundary: &AgentBoundaryFlow, dst: &mut Vec<u8>) {
    write_string(dst, &boundary.function);
    write_u64(dst, boundary.span.line as u64);
    write_u64(dst, boundary.span.col as u64);
    write_string(dst, &boundary.required_capability);
}

fn encode_schema_validation(report: &SchemaValidationReport, dst: &mut Vec<u8>) {
    let mut channel_declarations = report.channel_declarations.clone();
    channel_declarations.sort_by(|a, b| channel_decl_order(a).cmp(&channel_decl_order(b)));

    write_len(dst, channel_declarations.len());
    for decl in &channel_declarations {
        encode_channel_decl(decl, dst);
    }

    let mut send_uses = report.send_uses.clone();
    send_uses.sort_by(|a, b| send_use_order(a).cmp(&send_use_order(b)));

    write_len(dst, send_uses.len());
    for send in &send_uses {
        encode_send_use(send, dst);
    }
}

fn channel_decl_order(decl: &ChannelSchemaDecl) -> (String, String, String, usize, usize) {
    (
        decl.channel_key.clone(),
        decl.canonical_schema.clone(),
        decl.function.clone(),
        decl.span.line,
        decl.span.col,
    )
}

fn send_use_order(send: &ChannelSendUse) -> (String, String, String, usize, usize) {
    (
        send.channel_key.clone(),
        send.canonical_schema.clone(),
        send.function.clone(),
        send.span.line,
        send.span.col,
    )
}

fn encode_channel_decl(decl: &ChannelSchemaDecl, dst: &mut Vec<u8>) {
    write_string(dst, &decl.function);
    write_u64(dst, decl.span.line as u64);
    write_u64(dst, decl.span.col as u64);
    write_string(dst, &decl.channel_key);
    write_string(dst, &decl.canonical_schema);
    write_u64(dst, decl.schema_id);
}

fn encode_send_use(send: &ChannelSendUse, dst: &mut Vec<u8>) {
    write_string(dst, &send.function);
    write_u64(dst, send.span.line as u64);
    write_u64(dst, send.span.col as u64);
    write_string(dst, &send.channel_key);
    write_string(dst, &send.canonical_schema);
    write_u64(dst, send.schema_id);
}

fn write_u32(dst: &mut Vec<u8>, value: u32) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(dst: &mut Vec<u8>, value: u64) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_len(dst: &mut Vec<u8>, len: usize) {
    let len_u64 = u64::try_from(len).expect("length must fit in u64");
    write_u64(dst, len_u64);
}

fn write_string(dst: &mut Vec<u8>, value: &str) {
    write_len(dst, value.len());
    dst.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::encode;
    use crate::hir::lower::lower_to_hir;

    struct GoldenCase {
        name: &'static str,
        source: &'static str,
        golden_relpath: &'static str,
    }

    const GOLDEN_CASES: &[GoldenCase] = &[
        GoldenCase {
            name: "capability_governancefacts",
            source: r#"
                cap fs.read("cfg/*");
                cap net.listen(8000..9000);

                fn main() {
                    fs.read("cfg/app.nex");
                    net.listen(8080);
                    return;
                }
            "#,
            golden_relpath: "src/hir/golden/capability_governancefacts.hex",
        },
        GoldenCase {
            name: "schema_governancefacts",
            source: r#"
                fn main() {
                    bus.channel("alerts", "AlertV1");
                    bus.send("alerts", "AlertV1", "payload");
                    return;
                }
            "#,
            golden_relpath: "src/hir/golden/schema_governancefacts.hex",
        },
    ];

    #[test]
    fn governancefacts_golden_bytes_match_exactly() {
        let update = std::env::var("NEX_UPDATE_GOVERNANCEFACTS_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        for case in GOLDEN_CASES {
            let hir = parse_and_lower(case.source);
            let encoded = encode(&hir).expect("governancefacts encode should succeed");
            let path = project_root().join(case.golden_relpath);

            if update {
                fs::write(&path, format!("{}\n", to_hex(&encoded)))
                    .expect("write governancefacts golden");
            }

            let expected_hex = fs::read_to_string(&path).expect("read governancefacts golden");
            let expected = from_hex(&expected_hex).expect("parse governancefacts golden");
            assert_eq!(
                encoded, expected,
                "governancefacts golden mismatch for {}",
                case.name
            );
        }
    }

    fn parse_and_lower(source: &str) -> crate::hir::types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        lower_to_hir(&ast)
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble_to_hex((byte >> 4) & 0x0f));
            out.push(nibble_to_hex(byte & 0x0f));
        }
        out
    }

    fn nibble_to_hex(nibble: u8) -> char {
        match nibble {
            0..=9 => (b'0' + nibble) as char,
            10..=15 => (b'a' + (nibble - 10)) as char,
            _ => unreachable!("nibble out of range"),
        }
    }

    fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
        let mut filtered = String::with_capacity(hex.len());
        for ch in hex.chars() {
            if !ch.is_whitespace() {
                filtered.push(ch);
            }
        }

        if filtered.len() % 2 != 0 {
            return Err("hex length must be even".to_string());
        }

        let mut out = Vec::with_capacity(filtered.len() / 2);
        let bytes = filtered.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let hi = hex_value(bytes[i]).ok_or_else(|| "invalid hex".to_string())?;
            let lo = hex_value(bytes[i + 1]).ok_or_else(|| "invalid hex".to_string())?;
            out.push((hi << 4) | lo);
            i += 2;
        }

        Ok(out)
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
}
