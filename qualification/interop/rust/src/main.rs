//! Qualification-only synchronous pipe. Diagnostics contain fixed codes only.
use anonymizer::{
    Capture, CaptureLimits, Confidence, FindingAction, FindingKind, FindingSource, SourceFinding,
    Span, TokenSink,
};
use redact_secret_restore::{
    CommitState, ErrorCode, Limits, ResolvedValues, RestoreAuthority, RestoreError, RestoreField,
    RestorePlan, RestoreRequest, TrustedContext,
};
use std::io::{self, Write};

fn hex(text: &str) -> String {
    text.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Result<String, ()> {
    if text.len() % 2 != 0 {
        return Err(());
    }
    let bytes: Result<Vec<u8>, _> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
        .collect();
    String::from_utf8(bytes.map_err(|_| ())?).map_err(|_| ())
}
fn line() -> Result<String, ()> {
    let mut s = String::new();
    if io::stdin().read_line(&mut s).map_err(|_| ())? == 0 {
        return Err(());
    }
    Ok(s.trim_end_matches(['\r', '\n']).to_owned())
}
fn rpc(operation: &str, data: &[String]) -> Result<Vec<String>, ()> {
    println!("call\t{}\t{}", operation, data.join("\t"));
    io::stdout().flush().map_err(|_| ())?;
    let reply = line()?;
    let mut parts = reply.split('\t');
    if parts.next() != Some("ok") {
        return Err(());
    }
    Ok(parts.map(str::to_owned).collect())
}
struct Sink;
impl TokenSink for Sink {
    type Error = ();
    fn begin(&mut self) -> Result<(), ()> {
        rpc("begin", &[]).map(|_| ())
    }
    fn stage(&mut self, captures: &[Capture<'_>], _: CaptureLimits) -> Result<Vec<String>, ()> {
        let data = captures
            .iter()
            .map(|c| {
                let s = c.accepted().span();
                format!("{}:{}:{}", s.start, s.end, hex(c.value()))
            })
            .collect::<Vec<_>>();
        rpc("stage", &data)
    }
    fn commit(&mut self) -> Result<(), ()> {
        rpc("commit", &[]).map(|_| ())
    }
    fn abort(&mut self) -> Result<(), ()> {
        rpc("abort", &[]).map(|_| ())
    }
}
struct Authority;
fn authority_error() -> RestoreError {
    RestoreError::new(ErrorCode::Denied, CommitState::NotCommitted)
}
fn plan_data(plan: &RestorePlan<'_>) -> Vec<String> {
    let c = plan.context();
    let mut data = vec![
        hex(c.tenant),
        hex(c.principal),
        hex(c.session),
        hex(c.sink),
        hex(c.purpose),
        plan.captures().join(","),
    ];
    data.extend(
        plan.fields()
            .iter()
            .map(|f| format!("{}:{}", hex(f.path), hex(f.text))),
    );
    data
}
impl RestoreAuthority for Authority {
    type Grant = String;
    fn preflight(&self, plan: &RestorePlan<'_>) -> Result<String, RestoreError> {
        rpc("preflight", &plan_data(plan))
            .map_err(|_| authority_error())?
            .first()
            .cloned()
            .ok_or_else(authority_error)
    }
    fn consume(
        &mut self,
        grant: String,
        plan: &RestorePlan<'_>,
    ) -> Result<ResolvedValues, RestoreError> {
        let mut data = vec![grant];
        data.extend(plan_data(plan));
        println!("call\tconsume\t{}", data.join("\t"));
        io::stdout().flush().map_err(|_| {
            RestoreError::new(ErrorCode::AuthorityUnavailable, CommitState::Indeterminate)
        })?;
        let reply = line().map_err(|_| {
            RestoreError::new(ErrorCode::AuthorityUnavailable, CommitState::Indeterminate)
        })?;
        let parts = reply.split('\t').collect::<Vec<_>>();
        if parts.first().copied() != Some("ok") {
            let state = match parts.get(1).copied() {
                Some("not-committed") => CommitState::NotCommitted,
                Some("committed") => CommitState::Committed,
                _ => CommitState::Indeterminate,
            };
            return Err(RestoreError::new(ErrorCode::AuthorityUnavailable, state));
        }
        let values = parts[1..]
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let values = values
            .iter()
            .map(|v| unhex(v))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RestoreError::new(ErrorCode::AuthorityContract, CommitState::Committed))?;
        Ok(ResolvedValues::new(values))
    }
}
fn run(command: &str) -> Result<(), ()> {
    let p = command.split('\t').collect::<Vec<_>>();
    match p.first().copied() {
        Some("anonymize") | Some("irreversible") => {
            let input = unhex(p.get(1).ok_or(())?)?;
            let findings = p[2..]
                .iter()
                .map(|s| {
                    let pair = s.split(':').collect::<Vec<_>>();
                    Ok(SourceFinding {
                        span: Span {
                            start: pair.first().ok_or(())?.parse().map_err(|_| ())?,
                            end: pair.get(1).ok_or(())?.parse().map_err(|_| ())?,
                        },
                        kind: FindingKind::Credential,
                        source: FindingSource::Caller(1),
                        confidence: Confidence::Unknown,
                        action: FindingAction::Redact,
                    })
                })
                .collect::<Result<Vec<_>, ()>>()?;
            if p[0] == "irreversible" {
                match anonymizer::anonymize(&input, &findings) {
                    Ok(output) => println!("done\tirreversible\t{}", hex(output.text())),
                    Err(_) => println!("denied\tirreversible"),
                }
                io::stdout().flush().map_err(|_| ())?;
                return Ok(());
            }
            match anonymizer::anonymize_reversible(
                &input,
                &findings,
                &mut Sink,
                CaptureLimits::default(),
            ) {
                Ok(output) => println!("done\tanonymize\t{}", hex(output.text())),
                Err(_) => println!("denied\tanonymize"),
            }
        }
        Some("probe") => {
            println!("done\tprobe");
        }
        Some("scan") => {
            let text = unhex(p.get(1).ok_or(())?)?;
            let fields = [RestoreField {
                path: "body",
                text: &text,
            }];
            let ids = ["synthetic-capture"];
            let request = RestoreRequest {
                context: TrustedContext {
                    tenant: "t",
                    principal: "p",
                    session: "s",
                    sink: "reply",
                    purpose: "qualification",
                },
                captures: &ids,
                fields: &fields,
            };
            match RestorePlan::build(&request, Limits::default()) {
                Ok(plan) => println!("done\tscan\t{}", plan.occurrences().len()),
                Err(_) => println!("denied\tscan"),
            }
        }
        Some("restore") => {
            if p.len() < 7 {
                return Err(());
            }
            let ids = p[6].split(',').collect::<Vec<_>>();
            let context = p[1..6]
                .iter()
                .map(|s| unhex(s))
                .collect::<Result<Vec<_>, _>>()?;
            let owned = p[7..]
                .iter()
                .map(|s| {
                    let (a, b) = s.split_once(':').ok_or(())?;
                    Ok((unhex(a)?, unhex(b)?))
                })
                .collect::<Result<Vec<_>, ()>>()?;
            let fields = owned
                .iter()
                .map(|(path, text)| RestoreField { path, text })
                .collect::<Vec<_>>();
            let request = RestoreRequest {
                context: TrustedContext {
                    tenant: &context[0],
                    principal: &context[1],
                    session: &context[2],
                    sink: &context[3],
                    purpose: &context[4],
                },
                captures: &ids,
                fields: &fields,
            };
            match redact_secret_restore::restore(&request, &mut Authority, Limits::default()) {
                Ok(output) => {
                    let values = output.fields().iter().map(|f| hex(f)).collect::<Vec<_>>();
                    println!("done\trestore\t{}", values.join("\t"));
                }
                Err(e) => println!("denied\trestore\t{:?}", e.commit),
            }
        }
        _ => return Err(()),
    }
    io::stdout().flush().map_err(|_| ())
}
fn main() {
    while let Ok(command) = line() {
        if run(&command).is_err() {
            println!("denied\tprotocol");
            let _ = io::stdout().flush();
        }
    }
}
