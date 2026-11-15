//! `Get-Command` metadata pipeline — a special kind of PSRP pipeline
//! that asks the server which commands are available.
//!
//! The server uses this to implement implicit remoting (`Import-PSSession`).
//! Unlike a normal `CreatePipeline`, the body is a `GetCommandMetadata`
//! message (`0x0002_100A`) that carries a list of name patterns and the
//! command types to return.

use uuid::Uuid;

use crate::clixml::decode::{DecodeBudget, parse_clixml_transient, parse_clixml_within};
use crate::clixml::{PsObject, PsValue, to_clixml};
use crate::error::{PsrpError, Result};
use crate::message::MessageType;
use crate::pipeline::{PipelineState, stop_abandoned_pipeline};
use crate::runspace::RunspacePool;
use crate::transport::PsrpTransport;

/// Bitmask of command types to query, mirroring
/// `System.Management.Automation.CommandTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandType(u32);

impl CommandType {
    pub const ALIAS: Self = Self(0x0001);
    pub const FUNCTION: Self = Self(0x0002);
    pub const FILTER: Self = Self(0x0004);
    pub const CMDLET: Self = Self(0x0008);
    pub const EXTERNAL_SCRIPT: Self = Self(0x0010);
    pub const APPLICATION: Self = Self(0x0020);
    pub const SCRIPT: Self = Self(0x0040);
    pub const WORKFLOW: Self = Self(0x0080);
    pub const CONFIGURATION: Self = Self(0x0100);
    pub const ALL: Self = Self(0x01FF);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for CommandType {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for CommandType {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Describe one command returned by a metadata query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommandMetadata {
    pub name: String,
    pub namespace: Option<String>,
    pub has_common_parameters: Option<bool>,
    pub command_type: Option<i32>,
    pub parameters: Vec<ParameterMetadata>,
}

/// One parameter of a [`CommandMetadata`] entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParameterMetadata {
    pub name: String,
    pub parameter_type: Option<String>,
    pub is_mandatory: Option<bool>,
    pub position: Option<i32>,
}

impl CommandMetadata {
    pub(crate) fn from_ps_object(value: &PsValue) -> Option<Self> {
        let obj = value.properties()?;
        Some(Self {
            name: obj
                .get("Name")
                .and_then(PsValue::as_str)
                .unwrap_or_default()
                .to_string(),
            namespace: obj
                .get("Namespace")
                .and_then(PsValue::as_str)
                .map(str::to_string),
            has_common_parameters: obj.get("HasCommonParameters").and_then(PsValue::as_bool),
            command_type: obj.get("CommandType").and_then(PsValue::as_i32),
            parameters: match obj.get("Parameters") {
                Some(PsValue::List(list)) => list
                    .iter()
                    .filter_map(ParameterMetadata::from_ps_value)
                    .collect(),
                _ => Vec::new(),
            },
        })
    }
}

impl ParameterMetadata {
    pub(crate) fn from_ps_value(value: &PsValue) -> Option<Self> {
        let obj = value.properties()?;
        Some(Self {
            name: obj
                .get("Name")
                .and_then(PsValue::as_str)
                .unwrap_or_default()
                .to_string(),
            parameter_type: obj
                .get("ParameterType")
                .and_then(PsValue::as_str)
                .map(str::to_string),
            is_mandatory: obj.get("IsMandatory").and_then(PsValue::as_bool),
            position: obj.get("Position").and_then(PsValue::as_i32),
        })
    }
}

impl<T: PsrpTransport> RunspacePool<T> {
    /// Ask the server for metadata about every command matching `patterns`
    /// (wildcards accepted) whose type intersects `command_type`.
    ///
    /// Sends a `GetCommandMetadata` message, drains the resulting
    /// pipeline, and returns a decoded [`CommandMetadata`] list.
    ///
    /// # Errors
    ///
    /// Only a pipeline that completed returns its list: one the server
    /// reports `Failed` is a [`PsrpError::PipelineFailed`], `Stopped` a
    /// [`PsrpError::Stopped`] and `Disconnected` a [`PsrpError::BadState`],
    /// since a list cut short would pass for the whole of it. The read is
    /// bounded by the pool's [`ReceiveLimits`](crate::ReceiveLimits) like a
    /// pipeline's; a reply that passes them, or does not decode, ends the
    /// call with that error after the server has been asked to stop.
    pub async fn get_command_metadata(
        &mut self,
        patterns: &[&str],
        command_type: CommandType,
    ) -> Result<Vec<CommandMetadata>> {
        self.get_command_metadata_as(Uuid::new_v4(), patterns, command_type)
            .await
    }

    /// [`get_command_metadata`](Self::get_command_metadata) under a pipeline
    /// id the caller chose (the tests have to know it to answer).
    async fn get_command_metadata_as(
        &mut self,
        pid: Uuid,
        patterns: &[&str],
        command_type: CommandType,
    ) -> Result<Vec<CommandMetadata>> {
        let rpid = self.id();
        let body = build_get_command_metadata_body(patterns, command_type);
        self.send_pipeline_message(MessageType::GetCommandMetadata, pid, body)
            .await?;

        let mut budget = DecodeBudget::new(self.receive_limits().max_pipeline_size());
        let mut out = Vec::new();
        loop {
            let msg = match self.next_message().await {
                Ok(msg) => msg,
                Err(e) => {
                    stop_abandoned_pipeline(self, false).await;
                    return Err(e);
                }
            };
            // Same rule as for a pipeline: what is addressed to another one
            // (or carries a forged id) must not end up in this result, nor
            // end it. This loop used to take every `PipelineOutput` and every
            // `PipelineState` it read.
            if msg.pid != pid || msg.rpid != rpid {
                tracing::debug!(
                    expected_pid = %pid,
                    got_pid = %msg.pid,
                    mt = ?msg.message_type,
                    "dropping command-metadata message with mismatched pid/rpid",
                );
                continue;
            }
            match msg.message_type {
                MessageType::PipelineOutput => {
                    let values = match parse_clixml_within(&msg.data, &mut budget) {
                        Ok(values) => values,
                        Err(e) => {
                            stop_abandoned_pipeline(self, false).await;
                            return Err(e);
                        }
                    };
                    out.extend(values.iter().filter_map(CommandMetadata::from_ps_object));
                }
                MessageType::PipelineState => match state_from_xml(&msg.data, &budget) {
                    Some(PipelineState::Failed) => {
                        return Err(PsrpError::PipelineFailed(
                            match crate::runspace::state::terminal_state_reason(&msg.data, &budget)
                            {
                                Some(reason) => {
                                    format!("GetCommandMetadata pipeline failed: {reason}")
                                }
                                None => "GetCommandMetadata pipeline failed".into(),
                            },
                        ));
                    }
                    Some(PipelineState::Stopped) => return Err(PsrpError::Stopped),
                    Some(PipelineState::Disconnected) => {
                        return Err(PsrpError::BadState {
                            expected: format!("{:?}", PipelineState::Completed),
                            actual: format!("{:?}", PipelineState::Disconnected),
                        });
                    }
                    Some(state) if state.is_terminal() => return Ok(out),
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

pub(crate) fn state_from_xml(xml: &str, budget: &DecodeBudget) -> Option<PipelineState> {
    parse_clixml_transient(xml, budget).ok().and_then(|values| {
        values.into_iter().find_map(|v| match v {
            PsValue::Object(obj) => obj
                .get("PipelineState")
                .and_then(PsValue::as_i32)
                .map(pipeline_state_from_i32),
            _ => None,
        })
    })
}

fn pipeline_state_from_i32(v: i32) -> PipelineState {
    // Mirror pipeline::PipelineState::from_i32 without exposing it.
    match v {
        0 => PipelineState::NotStarted,
        1 => PipelineState::Running,
        2 => PipelineState::Stopping,
        3 => PipelineState::Stopped,
        4 => PipelineState::Completed,
        5 => PipelineState::Failed,
        6 => PipelineState::Disconnected,
        _ => PipelineState::Unknown,
    }
}

fn build_get_command_metadata_body(patterns: &[&str], command_type: CommandType) -> String {
    let names = PsValue::List(
        patterns
            .iter()
            .map(|p| PsValue::String((*p).to_string()))
            .collect(),
    );
    let obj = PsObject::new()
        .with("Name", names)
        .with(
            "CommandType",
            PsValue::I32(command_type.bits().cast_signed()),
        )
        .with("Namespace", PsValue::List(Vec::new()))
        .with("ArgumentList", PsValue::List(Vec::new()));
    to_clixml(&PsValue::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::PsObject;

    #[test]
    fn command_type_constants() {
        assert_eq!(CommandType::CMDLET.bits(), 0x0008);
        assert_eq!(CommandType::ALL.bits(), 0x01FF);
        let combo = CommandType::CMDLET | CommandType::FUNCTION;
        assert!(combo.contains(CommandType::CMDLET));
        assert!(combo.contains(CommandType::FUNCTION));
        assert!(!combo.contains(CommandType::ALIAS));
    }

    #[test]
    fn get_command_metadata_body_contains_name_and_type() {
        let body = build_get_command_metadata_body(&["Get-*", "Set-*"], CommandType::CMDLET);
        assert!(body.contains("<S>Get-*</S>"));
        assert!(body.contains("<S>Set-*</S>"));
        // CommandType::CMDLET = 0x0008 = 8
        assert!(body.contains("<I32 N=\"CommandType\">8</I32>"));
    }

    #[test]
    fn decode_command_metadata_object() {
        let obj = PsObject::new()
            .with("Name", PsValue::String("Get-Date".into()))
            .with("HasCommonParameters", PsValue::Bool(true))
            .with("CommandType", PsValue::I32(8))
            .with(
                "Parameters",
                PsValue::List(vec![PsValue::Object(
                    PsObject::new()
                        .with("Name", PsValue::String("Format".into()))
                        .with("ParameterType", PsValue::String("System.String".into()))
                        .with("IsMandatory", PsValue::Bool(false))
                        .with("Position", PsValue::I32(0)),
                )]),
            );
        let cm = CommandMetadata::from_ps_object(&PsValue::Object(obj)).unwrap();
        assert_eq!(cm.name, "Get-Date");
        assert_eq!(cm.has_common_parameters, Some(true));
        assert_eq!(cm.command_type, Some(8));
        assert_eq!(cm.parameters.len(), 1);
        assert_eq!(cm.parameters[0].name, "Format");
        assert_eq!(
            cm.parameters[0].parameter_type.as_deref(),
            Some("System.String")
        );
    }

    #[test]
    fn decode_rejects_non_object() {
        assert!(CommandMetadata::from_ps_object(&PsValue::I32(1)).is_none());
    }

    #[test]
    fn pipeline_state_shim_matches() {
        assert_eq!(pipeline_state_from_i32(0), PipelineState::NotStarted);
        assert_eq!(pipeline_state_from_i32(1), PipelineState::Running);
        assert_eq!(pipeline_state_from_i32(2), PipelineState::Stopping);
        assert_eq!(pipeline_state_from_i32(3), PipelineState::Stopped);
        assert_eq!(pipeline_state_from_i32(4), PipelineState::Completed);
        assert_eq!(pipeline_state_from_i32(5), PipelineState::Failed);
        assert_eq!(pipeline_state_from_i32(6), PipelineState::Disconnected);
        assert_eq!(pipeline_state_from_i32(99), PipelineState::Unknown);
    }

    #[test]
    fn state_from_xml_missing_is_none() {
        let budget = DecodeBudget::default();
        assert!(state_from_xml("<Obj RefId=\"0\"><MS/></Obj>", &budget).is_none());
    }

    #[test]
    fn state_from_xml_ok() {
        let xml = to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(4)),
        ));
        assert_eq!(
            state_from_xml(&xml, &DecodeBudget::default()),
            Some(PipelineState::Completed)
        );
    }

    // ---------- Phase D: end-to-end tests ----------

    use crate::fragment::encode_message;
    use crate::message::{Destination, PsrpMessage};
    use crate::runspace::RunspacePoolState;
    use crate::transport::mock::MockTransport;
    use uuid::Uuid;

    fn wire_msg(mt: MessageType, data: String) -> Vec<u8> {
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data,
        }
        .encode()
    }

    fn opened_state() -> Vec<u8> {
        wire_msg(
            MessageType::RunspacePoolState,
            to_clixml(&PsValue::Object(PsObject::new().with(
                "RunspaceState",
                PsValue::I32(RunspacePoolState::Opened as i32),
            ))),
        )
    }

    fn pipeline_state(state: PipelineState) -> Vec<u8> {
        wire_msg(
            MessageType::PipelineState,
            to_clixml(&PsValue::Object(
                PsObject::new().with("PipelineState", PsValue::I32(state as i32)),
            )),
        )
    }

    /// `data` as a message of pipeline `pid` in pool `rpid`.
    fn wire_for(mt: MessageType, data: String, rpid: Uuid, pid: Uuid) -> Vec<u8> {
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid,
            pid,
            data,
        }
        .encode()
    }

    fn state_body(state: PipelineState) -> String {
        to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(state as i32)),
        ))
    }

    fn cmdlet(name: &str) -> String {
        to_clixml(&PsValue::Object(
            PsObject::new()
                .with("Name", PsValue::String(name.into()))
                .with("CommandType", PsValue::I32(8)),
        ))
    }

    /// An opened pool, a pipeline id, and `messages` queued as the answer to
    /// that pipeline.
    async fn pool_answering(
        t: &MockTransport,
        messages: &[(MessageType, String)],
    ) -> (crate::runspace::RunspacePool<MockTransport>, Uuid) {
        t.push_incoming(encode_message(1, &opened_state()));
        let pool = crate::runspace::RunspacePool::open_with_transport(t.clone())
            .await
            .unwrap();
        let pid = Uuid::new_v4();
        for (oid, (mt, data)) in (10u64..).zip(messages) {
            let msg = wire_for(*mt, data.clone(), pool.id(), pid);
            t.push_incoming(encode_message(oid, &msg));
        }
        (pool, pid)
    }

    #[tokio::test]
    async fn get_command_metadata_returns_items() {
        let t = MockTransport::new();
        // Two cmdlets emitted as PipelineOutput.
        let (mut pool, pid) = pool_answering(
            &t,
            &[
                (MessageType::PipelineOutput, cmdlet("Get-Date")),
                (MessageType::PipelineOutput, cmdlet("Get-Process")),
                (
                    MessageType::PipelineState,
                    state_body(PipelineState::Completed),
                ),
            ],
        )
        .await;
        let cmds = pool
            .get_command_metadata_as(pid, &["Get-*"], CommandType::CMDLET)
            .await
            .unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].name, "Get-Date");
        assert_eq!(cmds[1].name, "Get-Process");
        assert!(!*t.stopped.lock().unwrap());
        let _ = pool.close().await;
    }

    /// Regression: the loop had no pipeline filter, so the output and the
    /// terminal state of any other pipeline (or of a forged id) were taken
    /// for the answer.
    #[tokio::test]
    async fn get_command_metadata_ignores_other_pipelines() {
        let t = MockTransport::new();
        let (mut pool, pid) = pool_answering(&t, &[]).await;
        let rpid = pool.id();
        let completed = state_body(PipelineState::Completed);
        let queue = [
            // Another pipeline of this pool, then the pool itself, then
            // the right pipeline id under another pool's.
            (
                MessageType::PipelineOutput,
                cmdlet("Forged-One"),
                rpid,
                Uuid::new_v4(),
            ),
            (
                MessageType::PipelineOutput,
                cmdlet("Forged-Two"),
                rpid,
                Uuid::nil(),
            ),
            (
                MessageType::PipelineOutput,
                cmdlet("Forged-Three"),
                Uuid::new_v4(),
                pid,
            ),
            (
                MessageType::PipelineState,
                completed.clone(),
                rpid,
                Uuid::new_v4(),
            ),
            (
                MessageType::PipelineState,
                completed.clone(),
                Uuid::nil(),
                Uuid::nil(),
            ),
            (MessageType::PipelineOutput, cmdlet("Get-Date"), rpid, pid),
            (MessageType::PipelineState, completed, rpid, pid),
        ];
        for (oid, (mt, data, rpid, pid)) in (10u64..).zip(queue) {
            t.push_incoming(encode_message(oid, &wire_for(mt, data, rpid, pid)));
        }
        let cmds = pool
            .get_command_metadata_as(pid, &["Get-*"], CommandType::CMDLET)
            .await
            .unwrap();
        let names: Vec<_> = cmds.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["Get-Date"]);
        let _ = pool.close().await;
    }

    /// The public entry point picks a fresh pipeline id, so an answer on the
    /// nil id is not its answer.
    #[tokio::test]
    async fn get_command_metadata_uses_its_own_pipeline_id() {
        let t = MockTransport::new();
        let (mut pool, _) = pool_answering(&t, &[]).await;
        t.push_incoming(encode_message(
            10,
            &pipeline_state(PipelineState::Completed),
        ));
        let err = pool
            .get_command_metadata(&["Get-*"], CommandType::CMDLET)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mock inbox empty"), "{err}");
        assert_eq!(t.pipeline_starts().len(), 1);
        assert!(!t.pipeline_starts()[0].is_nil());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn get_command_metadata_failure_carries_the_server_reason() {
        let t = MockTransport::new();
        let exception = PsObject::new().with("Message", PsValue::String("no such module".into()));
        let record = PsObject::new().with("Exception", PsValue::Object(exception));
        let body = to_clixml(&PsValue::Object(
            PsObject::new()
                .with("PipelineState", PsValue::I32(PipelineState::Failed as i32))
                .with("ExceptionAsErrorRecord", PsValue::Object(record)),
        ));
        let (mut pool, pid) = pool_answering(&t, &[(MessageType::PipelineState, body)]).await;
        let err = pool
            .get_command_metadata_as(pid, &["Nothing"], CommandType::ALL)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, crate::error::PsrpError::PipelineFailed(m)
                if m == "GetCommandMetadata pipeline failed: no such module"),
            "{err:?}"
        );
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn get_command_metadata_failed_pipeline_errors() {
        let t = MockTransport::new();
        let (mut pool, pid) = pool_answering(
            &t,
            &[(
                MessageType::PipelineState,
                state_body(PipelineState::Failed),
            )],
        )
        .await;
        let err = pool
            .get_command_metadata_as(pid, &["Nothing"], CommandType::ALL)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, crate::error::PsrpError::PipelineFailed(m)
                if m == "GetCommandMetadata pipeline failed"),
            "{err:?}"
        );
        let _ = pool.close().await;
    }

    /// A list cut short is not returned as if it were whole.
    #[tokio::test]
    async fn get_command_metadata_stopped_or_disconnected_is_an_error() {
        for state in [PipelineState::Stopped, PipelineState::Disconnected] {
            let t = MockTransport::new();
            let (mut pool, pid) = pool_answering(
                &t,
                &[
                    (MessageType::PipelineOutput, cmdlet("Get-Date")),
                    // Not terminal: the read goes on.
                    (
                        MessageType::PipelineState,
                        state_body(PipelineState::Running),
                    ),
                    (MessageType::PipelineState, state_body(state)),
                ],
            )
            .await;
            let err = pool
                .get_command_metadata_as(pid, &["Get-*"], CommandType::CMDLET)
                .await
                .unwrap_err();
            match state {
                PipelineState::Stopped => assert!(matches!(err, PsrpError::Stopped), "{err:?}"),
                _ => assert!(
                    matches!(&err, PsrpError::BadState { expected, actual }
                        if expected == "Completed" && actual == "Disconnected"),
                    "{err:?}"
                ),
            }
            let _ = pool.close().await;
        }
    }

    /// The reply is bounded like a pipeline's, and a reply the client gives
    /// up on is stopped on the server.
    #[tokio::test]
    async fn get_command_metadata_is_bounded_and_stops_what_it_abandons() {
        let reply = [
            (MessageType::PipelineOutput, cmdlet("Get-Date")),
            (MessageType::PipelineOutput, cmdlet("Get-Process")),
            (
                MessageType::PipelineState,
                state_body(PipelineState::Completed),
            ),
        ];
        // A limit that the first object fits in, and the two do not.
        let mut budget = DecodeBudget::new(usize::MAX);
        parse_clixml_within(&cmdlet("Get-Date"), &mut budget).unwrap();
        let one = budget.used() * 3 / 2;
        assert!(one > 0);

        let t = MockTransport::new();
        let (mut pool, pid) = pool_answering(&t, &reply).await;
        pool.set_receive_limits(pool.receive_limits().with_max_pipeline_size(one));
        let err = pool
            .get_command_metadata_as(pid, &["Get-*"], CommandType::CMDLET)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Clixml(_)), "{err:?}");
        assert!(err.to_string().contains("limit"), "{err}");
        assert!(*t.stopped.lock().unwrap(), "the command was left running");
        let _ = pool.close().await;

        // A reply that does not decode: same.
        let t = MockTransport::new();
        let (mut pool, pid) = pool_answering(
            &t,
            &[(MessageType::PipelineOutput, "<I32>x</I32>".to_string())],
        )
        .await;
        let err = pool
            .get_command_metadata_as(pid, &["Get-*"], CommandType::CMDLET)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Clixml(_)), "{err:?}");
        assert!(*t.stopped.lock().unwrap(), "the command was left running");
        let _ = pool.close().await;

        // A transport error is not answered with a stop signal.
        let t = MockTransport::new();
        let (mut pool, pid) = pool_answering(&t, &[]).await;
        let err = pool
            .get_command_metadata_as(pid, &["Get-*"], CommandType::CMDLET)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mock inbox empty"), "{err}");
        assert!(!*t.stopped.lock().unwrap());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn get_command_metadata_empty_result() {
        let t = MockTransport::new();
        let (mut pool, pid) = pool_answering(
            &t,
            &[(
                MessageType::PipelineState,
                state_body(PipelineState::Completed),
            )],
        )
        .await;
        let cmds = pool
            .get_command_metadata_as(pid, &["None-*"], CommandType::CMDLET)
            .await
            .unwrap();
        assert_eq!(cmds.len(), 0, "{cmds:?}");
        let _ = pool.close().await;
    }

    #[test]
    fn command_type_bit_and() {
        let mask = CommandType::ALL & CommandType::CMDLET;
        assert_eq!(mask.bits(), CommandType::CMDLET.bits());
        let empty = CommandType::empty();
        assert_eq!(empty.bits(), 0);
    }

    #[test]
    fn command_type_bit_or() {
        let combined = CommandType::CMDLET | CommandType::FUNCTION;
        assert!(combined.contains(CommandType::CMDLET));
        assert!(combined.contains(CommandType::FUNCTION));
        assert!(!combined.contains(CommandType::ALIAS));
        // Verify OR produces the correct bits (not XOR)
        assert_eq!(
            combined.bits(),
            CommandType::CMDLET.bits() | CommandType::FUNCTION.bits()
        );
        // OR with self should be idempotent (XOR would zero it out)
        let double = CommandType::CMDLET | CommandType::CMDLET;
        assert!(double.contains(CommandType::CMDLET));
        assert_eq!(double.bits(), CommandType::CMDLET.bits());
    }
}
