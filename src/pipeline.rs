//! Pipeline builder and executor.

use uuid::Uuid;

#[cfg(test)]
use crate::clixml::PsObject;
use crate::clixml::PsValue;
use crate::clixml::decode::{DecodeBudget, parse_clixml_transient, parse_clixml_within};
use crate::error::{MAX_SERVER_MESSAGE_CHARS, PsrpError, Result, escape_remote_text};
use crate::message::{MessageType, PsrpMessage};
use crate::records::{
    ErrorRecord, FromPsObject, InformationRecord, ProgressRecord, TraceRecord, WarningRecord,
};
use crate::runspace::RunspacePool;
use crate::transport::PsrpTransport;

impl PipelineResult {
    /// Decode every value on the `errors` stream as an [`ErrorRecord`],
    /// dropping any that don't match the expected shape.
    #[must_use]
    pub fn typed_errors(&self) -> Vec<ErrorRecord> {
        self.errors
            .iter()
            .filter_map(ErrorRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `warnings` stream as a [`WarningRecord`].
    #[must_use]
    pub fn typed_warnings(&self) -> Vec<WarningRecord> {
        self.warnings
            .iter()
            .filter_map(WarningRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `information` stream as an
    /// [`InformationRecord`].
    #[must_use]
    pub fn typed_information(&self) -> Vec<InformationRecord> {
        self.information
            .iter()
            .filter_map(InformationRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `progress` stream as a [`ProgressRecord`].
    #[must_use]
    pub fn typed_progress(&self) -> Vec<ProgressRecord> {
        self.progress
            .iter()
            .filter_map(ProgressRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `verbose` stream as a [`TraceRecord`].
    #[must_use]
    pub fn typed_verbose(&self) -> Vec<TraceRecord> {
        self.verbose
            .iter()
            .filter_map(TraceRecord::from_ps_object)
            .collect()
    }

    /// Decode every value on the `debug` stream as a [`TraceRecord`].
    #[must_use]
    pub fn typed_debug(&self) -> Vec<TraceRecord> {
        self.debug
            .iter()
            .filter_map(TraceRecord::from_ps_object)
            .collect()
    }
}

/// Result of a completed pipeline run, carrying every PSRP stream separately.
#[derive(Debug, Default, Clone)]
pub struct PipelineResult {
    pub output: Vec<PsValue>,
    pub errors: Vec<PsValue>,
    pub warnings: Vec<PsValue>,
    pub verbose: Vec<PsValue>,
    pub debug: Vec<PsValue>,
    pub information: Vec<PsValue>,
    pub progress: Vec<PsValue>,
    pub state: PipelineState,
}

/// Server-reported pipeline state (MS-PSRP §2.2.3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PipelineState {
    #[default]
    NotStarted,
    Running,
    Stopping,
    Stopped,
    Completed,
    Failed,
    Disconnected,
    Unknown,
}

impl PipelineState {
    fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::NotStarted,
            1 => Self::Running,
            2 => Self::Stopping,
            3 => Self::Stopped,
            4 => Self::Completed,
            5 => Self::Failed,
            6 => Self::Disconnected,
            _ => Self::Unknown,
        }
    }

    /// True when the pipeline has reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Stopped | Self::Disconnected
        )
    }
}

/// One argument to a [`Command`].
///
/// PowerShell commands accept three kinds of argument:
/// * **Named**: `-Name svchost` — a name/value pair.
/// * **Positional**: `svchost` — a bare value, bound by position.
/// * **Switch**: `-Force` — a flag, no value.
#[derive(Debug, Clone)]
pub enum Argument {
    /// `-Name value`
    Named { name: String, value: PsValue },
    /// Positional argument (no name).
    Positional(PsValue),
    /// `-SwitchName` — boolean flag, no value.
    Switch(String),
}

/// A single command within a pipeline.
#[derive(Debug, Clone)]
pub struct Command {
    pub name: String,
    pub arguments: Vec<Argument>,
    pub is_script: bool,
    /// If true, errors from this command are merged into the output stream
    /// (equivalent to `2>&1` in PowerShell pipes).
    pub merge_errors_to_output: bool,
}

impl Command {
    /// Build a command invoking `name` (a cmdlet or function).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments: Vec::new(),
            is_script: false,
            merge_errors_to_output: false,
        }
    }

    /// Build a command that runs a raw script block.
    pub fn script(script: impl Into<String>) -> Self {
        Self {
            name: script.into(),
            arguments: Vec::new(),
            is_script: true,
            merge_errors_to_output: false,
        }
    }

    /// Add a named parameter (builder style).
    #[must_use]
    pub fn with_parameter(mut self, name: impl Into<String>, value: PsValue) -> Self {
        self.arguments.push(Argument::Named {
            name: name.into(),
            value,
        });
        self
    }

    /// Add a positional argument (builder style).
    #[must_use]
    pub fn with_argument(mut self, value: PsValue) -> Self {
        self.arguments.push(Argument::Positional(value));
        self
    }

    /// Add a switch parameter (builder style). Emits `-SwitchName` with no
    /// value, as PowerShell expects for boolean flags.
    #[must_use]
    pub fn with_switch(mut self, name: impl Into<String>) -> Self {
        self.arguments.push(Argument::Switch(name.into()));
        self
    }

    /// Merge the error stream of this command into the output stream,
    /// equivalent to appending `2>&1` in a PowerShell pipe.
    #[must_use]
    pub fn merging_errors_to_output(mut self) -> Self {
        self.merge_errors_to_output = true;
        self
    }
}

/// A pipeline is an ordered list of commands.
#[derive(Debug, Clone)]
pub struct Pipeline {
    commands: Vec<Command>,
    /// When `false`, the pipeline expects the client to stream input
    /// objects via `PipelineInput` messages followed by `EndOfPipelineInput`.
    /// Defaults to `true` (closed input, script runs once).
    pub(crate) no_input: bool,
    /// When `true`, invocation info is included in every record. Default `true`.
    pub(crate) add_invocation_info: bool,
    /// When `true`, the command is added to the server's session history.
    pub(crate) add_to_history: bool,
    /// Test-only override for the pipeline PID. `None` in production (a
    /// fresh v4 UUID is generated). Set via the doc-hidden
    /// `__with_forced_pid_for_test` to allow unit tests to seed mock
    /// inboxes with messages targeting a known PID.
    pub(crate) forced_pid: Option<Uuid>,
}

impl Pipeline {
    /// Create a pipeline running a single raw script block.
    pub fn new(script: impl Into<String>) -> Self {
        Self {
            commands: vec![Command::script(script)],
            no_input: true,
            add_invocation_info: true,
            add_to_history: false,
            forced_pid: None,
        }
    }

    /// Create an empty pipeline (use [`Pipeline::add_command`] to populate).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            commands: Vec::new(),
            no_input: true,
            add_invocation_info: true,
            add_to_history: false,
            forced_pid: None,
        }
    }

    /// Test-only: pin the pipeline's PID to a known value so unit tests
    /// can seed mock inboxes with matching messages. Never call from
    /// production code — the security check that filters incoming
    /// messages by PID relies on the PID being unguessable.
    #[doc(hidden)]
    #[must_use]
    pub fn __with_forced_pid_for_test(mut self, pid: Uuid) -> Self {
        self.forced_pid = Some(pid);
        self
    }

    /// Enable client-to-server input streaming for this pipeline.
    ///
    /// Setting this to `true` (the default for [`start`](Self::start)-based
    /// streaming) signals the server that it should wait for
    /// `PipelineInput` messages before running.
    #[must_use]
    pub fn with_input(mut self, streaming: bool) -> Self {
        self.no_input = !streaming;
        self
    }

    /// Enable or disable `AddToHistory` on the remote side.
    #[must_use]
    pub fn with_history(mut self, add_to_history: bool) -> Self {
        self.add_to_history = add_to_history;
        self
    }

    /// Push a command at the end of the pipeline.
    #[must_use]
    pub fn add_command(mut self, command: Command) -> Self {
        self.commands.push(command);
        self
    }

    /// Number of commands in the pipeline.
    #[must_use]
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// True if there are no commands.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Execute the pipeline and return only its `Output` stream.
    ///
    /// # Errors
    ///
    /// Besides the errors of
    /// [`run_all_streams_with_cancel`](Self::run_all_streams_with_cancel), a
    /// pipeline the server reports `Disconnected` is a
    /// [`PsrpError::BadState`]: it did not complete, and the output read so
    /// far must not pass for the whole of it.
    pub async fn run<T: PsrpTransport>(self, pool: &mut RunspacePool<T>) -> Result<Vec<PsValue>> {
        let result = self.run_all_streams(pool).await?;
        completed_output(result)
    }

    /// Execute the pipeline with a cancellation token. When the token is
    /// cancelled the pipeline is stopped cleanly (`signal_ctrl_c`) and a
    /// [`PsrpError::Cancelled`] is returned. A `Disconnected` pipeline is an
    /// error, as for [`run`](Self::run).
    pub async fn run_with_cancel<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Vec<PsValue>> {
        let result = self.run_all_streams_with_cancel(pool, cancel).await?;
        completed_output(result)
    }

    /// Execute the pipeline and return a fully-decoded [`PipelineResult`].
    pub async fn run_all_streams<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
    ) -> Result<PipelineResult> {
        self.run_all_streams_with_cancel(
            pool,
            tokio_util::sync::CancellationToken::new(), // never cancelled
        )
        .await
    }

    /// Start the pipeline on the server and return a [`PipelineHandle`]
    /// that can be used to stream input objects, then collect the output.
    ///
    /// The handle borrows the pool mutably, so only one pipeline can run
    /// at a time. This is the recommended path when you need to feed
    /// input via [`PipelineHandle::write_input`].
    pub async fn start<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
    ) -> Result<PipelineHandle<'_, T>> {
        if self.commands.is_empty() {
            return Err(PsrpError::protocol("pipeline is empty"));
        }
        let pid = self.forced_pid.unwrap_or_else(Uuid::new_v4);
        let rpid = pool.id();
        let body = self.create_pipeline_xml();
        pool.send_pipeline_message(MessageType::CreatePipeline, pid, body)
            .await?;
        Ok(PipelineHandle {
            pool,
            pid,
            rpid,
            input_closed: self.no_input,
        })
    }

    /// Execute the pipeline with a cancellation token and return a
    /// [`PipelineResult`]. If `cancel` fires, the pipeline is stopped
    /// via `signal_ctrl_c` and [`PsrpError::Cancelled`] is returned after
    /// the server ACKs `Stopped`.
    ///
    /// `Ok` means the pipeline reached a terminal state that is not a
    /// failure, not that it completed: check [`PipelineResult::state`], which
    /// is [`PipelineState::Disconnected`] when the server detached the
    /// pipeline before its end (the streams then hold what was read so far).
    ///
    /// # Errors
    ///
    /// [`PsrpError::PipelineFailed`] and [`PsrpError::Stopped`] for those
    /// terminal states, and whatever ends the read: a transport error, a
    /// message that does not decode, or one that passes the pool's
    /// [`ReceiveLimits`](crate::ReceiveLimits). In the last two cases the
    /// server is asked to stop the command before the error is returned.
    pub async fn run_all_streams_with_cancel<T: PsrpTransport>(
        self,
        pool: &mut RunspacePool<T>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<PipelineResult> {
        if self.commands.is_empty() {
            return Err(PsrpError::protocol("pipeline is empty"));
        }
        let pid = self.forced_pid.unwrap_or_else(Uuid::new_v4);
        let rpid = pool.id();
        let body = self.create_pipeline_xml();
        pool.send_pipeline_message(MessageType::CreatePipeline, pid, body)
            .await?;

        drain_pipeline(pool, pid, rpid, cancel).await
    }

    fn create_pipeline_xml(&self) -> String {
        use crate::clixml::encode::{
            PipelineArgSpec, PipelineCommandSpec, build_create_pipeline_xml,
        };

        let specs: Vec<PipelineCommandSpec<'_>> = self
            .commands
            .iter()
            .map(|c| PipelineCommandSpec {
                name: &c.name,
                is_script: c.is_script,
                merge_errors_to_output: c.merge_errors_to_output,
                args: c
                    .arguments
                    .iter()
                    .map(|a| match a {
                        Argument::Named { name, value } => PipelineArgSpec::Named { name, value },
                        Argument::Positional(v) => PipelineArgSpec::Positional(v),
                        Argument::Switch(name) => PipelineArgSpec::Switch(name),
                    })
                    .collect(),
            })
            .collect();

        build_create_pipeline_xml(
            self.no_input,
            self.add_to_history,
            self.add_invocation_info,
            &specs,
        )
    }

    /// Build the outer `CreatePipeline` XML that wraps the command list.
    #[doc(hidden)]
    pub fn __create_pipeline_xml_for_test(&self) -> String {
        self.create_pipeline_xml()
    }
}

/// Live handle to a running pipeline.
///
/// Created by [`Pipeline::start`]. Lets the caller stream input objects,
/// then drives the receive loop with [`PipelineHandle::collect`] or
/// [`PipelineHandle::collect_with_cancel`].
///
/// The handle borrows the pool mutably, so exactly one pipeline can be
/// alive at a time. Drop the handle without calling `collect` to abort
/// locally (the server will still process the pipeline, but the handle
/// won't drain its output).
pub struct PipelineHandle<'p, T: PsrpTransport> {
    pool: &'p mut RunspacePool<T>,
    pid: Uuid,
    rpid: Uuid,
    input_closed: bool,
}

impl<T: PsrpTransport> std::fmt::Debug for PipelineHandle<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineHandle")
            .field("pid", &self.pid)
            .field("rpid", &self.rpid)
            .field("input_closed", &self.input_closed)
            .finish()
    }
}

impl<T: PsrpTransport> PipelineHandle<'_, T> {
    /// Send one input object to the pipeline.
    ///
    /// Errors if the pipeline was configured with `no_input = true`
    /// (the default) — use [`Pipeline::with_input`] with `true` before
    /// calling `start` to enable streaming.
    pub async fn write_input(&mut self, value: PsValue) -> Result<()> {
        if self.input_closed {
            return Err(PsrpError::protocol(
                "pipeline was created with NoInput=true; cannot stream input",
            ));
        }
        let body = crate::clixml::to_clixml(&value);
        self.pool
            .send_pipeline_message(MessageType::PipelineInput, self.pid, body)
            .await
    }

    /// Close the input stream with an `EndOfPipelineInput` message.
    ///
    /// After this call, further `write_input` calls are rejected.
    pub async fn end_input(&mut self) -> Result<()> {
        if self.input_closed {
            return Ok(());
        }
        self.input_closed = true;
        self.pool
            .send_pipeline_message(MessageType::EndOfPipelineInput, self.pid, String::new())
            .await
    }

    /// Drain every server message until the pipeline reaches a terminal
    /// state and return the collected [`PipelineResult`].
    pub async fn collect(mut self) -> Result<PipelineResult> {
        self.end_input().await?;
        self.drain_loop(tokio_util::sync::CancellationToken::new())
            .await
    }

    /// Drain with cancellation support.
    pub async fn collect_with_cancel(
        mut self,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<PipelineResult> {
        self.end_input().await?;
        self.drain_loop(cancel).await
    }

    /// Ask the server to stop the pipeline. Returns immediately; call
    /// [`collect`](Self::collect) afterwards to drain the `Stopped` ACK.
    pub async fn stop(&mut self) -> Result<()> {
        self.pool.signal_transport_stop().await
    }

    /// Pipeline PID.
    #[must_use]
    pub fn pid(&self) -> Uuid {
        self.pid
    }

    async fn drain_loop(
        &mut self,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<PipelineResult> {
        drain_pipeline(self.pool, self.pid, self.rpid, cancel).await
    }
}

/// Read the messages of pipeline `pid` until it reaches a terminal state:
/// the one receive loop behind [`Pipeline::run_all_streams_with_cancel`] and
/// [`PipelineHandle::collect_with_cancel`].
///
/// What the pipeline returns is held in memory until it ends, and the server
/// decides how much that is, so the values are decoded against the pool's
/// [`ReceiveLimits::max_pipeline_size`](crate::ReceiveLimits::max_pipeline_size),
/// all streams together.
///
/// When the client gives up on a message it has read (malformed, or past a
/// limit), the command is still running on the server: it is asked to stop
/// before the error is returned.
async fn drain_pipeline<T: PsrpTransport>(
    pool: &mut RunspacePool<T>,
    pid: Uuid,
    rpid: Uuid,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<PipelineResult> {
    let mut budget = DecodeBudget::new(pool.receive_limits().max_pipeline_size());
    let mut result = PipelineResult {
        state: PipelineState::Running,
        ..PipelineResult::default()
    };
    let mut cancel_signalled = false;
    loop {
        // If the caller asked to cancel, fire a stop signal (once) then
        // keep draining until the server confirms `Stopped`.
        if !cancel_signalled && cancel.is_cancelled() {
            pool.signal_transport_stop().await?;
            cancel_signalled = true;
        }
        let msg = tokio::select! {
            biased;
            () = cancel.cancelled(), if !cancel_signalled => {
                pool.signal_transport_stop().await?;
                cancel_signalled = true;
                continue;
            }
            msg = pool.next_message() => match msg {
                Ok(msg) => msg,
                // The transport saw the command disappear after the
                // stop signal (WinRM): that is the end of the stop.
                Err(PsrpError::Stopped) if cancel_signalled => {
                    return Err(PsrpError::Cancelled);
                }
                Err(e) => {
                    stop_abandoned_pipeline(pool, cancel_signalled).await;
                    return Err(e);
                }
            },
        };
        // Drop messages that don't belong to this pipeline. A
        // malicious or buggy server can otherwise smuggle output,
        // errors, or terminal-state ACKs from a different pipeline
        // (or a forged PID) into this pipeline's result.
        if msg.pid != pid || msg.rpid != rpid {
            tracing::debug!(
                expected_pid = %pid,
                got_pid = %msg.pid,
                expected_rpid = %rpid,
                got_rpid = %msg.rpid,
                mt = ?msg.message_type,
                "dropping pipeline message with mismatched pid/rpid",
            );
            continue;
        }
        let state = match file_message(&msg, &mut result, &mut budget) {
            Ok(state) => state,
            Err(e) => {
                stop_abandoned_pipeline(pool, cancel_signalled).await;
                return Err(e);
            }
        };
        match state {
            Some(PipelineState::Failed) => {
                return Err(PsrpError::PipelineFailed(failure_message(
                    &msg.data,
                    &result.errors,
                    &budget,
                )));
            }
            Some(PipelineState::Stopped) if cancel_signalled => return Err(PsrpError::Cancelled),
            Some(PipelineState::Stopped) => return Err(PsrpError::Stopped),
            Some(state) if state.is_terminal() => return Ok(result),
            _ => {}
        }
    }
}

/// File one message of the pipeline under its stream in `result`, decoded
/// against `budget`. A `PipelineState` message updates `result.state` and
/// its state is returned; a message of any other type is ignored.
fn file_message(
    msg: &PsrpMessage,
    result: &mut PipelineResult,
    budget: &mut DecodeBudget,
) -> Result<Option<PipelineState>> {
    let stream = match msg.message_type {
        MessageType::PipelineOutput => &mut result.output,
        MessageType::ErrorRecord => &mut result.errors,
        MessageType::WarningRecord => &mut result.warnings,
        MessageType::VerboseRecord => &mut result.verbose,
        MessageType::DebugRecord => &mut result.debug,
        MessageType::InformationRecord => &mut result.information,
        MessageType::ProgressRecord => &mut result.progress,
        MessageType::PipelineState => {
            // Read and dropped: bounded by the pipeline's limit on its own,
            // and not taken from it.
            let state = extract_pipeline_state(&msg.data, budget)?;
            result.state = state;
            return Ok(Some(state));
        }
        _ => return Ok(None),
    };
    stream.extend(parse_clixml_within(&msg.data, budget)?);
    Ok(None)
}

/// Ask the server to stop a pipeline the client has just given up on, best
/// effort: the error that ended the read is the one the caller gets.
///
/// Nothing is sent when a stop was already signalled, or when the read ended
/// on a transport error: the signal would go down the transport that has
/// just failed. Once the stop is asked for, the transport settles what the
/// reader leaves behind ([`PsrpTransport::abandon_pipeline`]): over WinRM a
/// pipeline that was writing output stops only when that output is taken.
pub(crate) async fn stop_abandoned_pipeline<T: PsrpTransport>(
    pool: &mut RunspacePool<T>,
    stop_already_signalled: bool,
) {
    if pool.transport_failing() {
        return;
    }
    if !stop_already_signalled && let Err(e) = pool.signal_transport_stop().await {
        tracing::debug!("stop signal for the abandoned pipeline not sent: {e}");
        return;
    }
    pool.abandon_transport_pipeline().await;
}

/// The output of a pipeline that ran to its end. `Disconnected` is terminal
/// but is not that: a caller that gets the output alone cannot tell that it
/// stops short, so it gets an error instead.
fn completed_output(result: PipelineResult) -> Result<Vec<PsValue>> {
    if result.state == PipelineState::Disconnected {
        return Err(PsrpError::BadState {
            expected: format!("{:?}", PipelineState::Completed),
            actual: format!("{:?}", result.state),
        });
    }
    Ok(result.output)
}

pub(crate) fn extract_pipeline_state(xml: &str, budget: &DecodeBudget) -> Result<PipelineState> {
    let parsed = parse_clixml_transient(xml, budget)?;
    for v in parsed {
        if let PsValue::Object(obj) = v
            && let Some(PsValue::I32(code)) = obj.get("PipelineState")
        {
            return Ok(PipelineState::from_i32(*code));
        }
    }
    Err(PsrpError::protocol("missing PipelineState property"))
}

/// Why a pipeline failed: the exception the server attached to the
/// `PipelineState` message (a terminating error such as `throw` is reported
/// there, not in the error stream), then the errors written to the error
/// stream, whichever there are, the same text not repeated. Everything the
/// server wrote is escaped and bounded.
pub(crate) fn failure_message(
    state_data: &str,
    errors: &[PsValue],
    budget: &DecodeBudget,
) -> String {
    let reason = crate::runspace::state::terminal_state_reason(state_data, budget);
    let (mut parts, more) = describe_parts(errors);
    // Both are trimmed, escaped and cut the same way, so the same error
    // reads the same in each; an error that merely contains the reason
    // (`File not found: foo` and `foo`) is a different error.
    if let Some(reason) = reason
        && !parts.contains(&reason)
    {
        parts.insert(0, reason);
    }
    join_parts(parts, more)
}

/// How many errors of the error stream a failure message quotes.
const MAX_DESCRIBED_ERRORS: usize = 8;

/// One line for each of the first [`MAX_DESCRIBED_ERRORS`] errors, joined
/// with `; `: the exception message of an `ErrorRecord`, else the text of
/// the value. Each is trimmed, escaped and cut at
/// [`MAX_SERVER_MESSAGE_CHARS`]; the rest is counted, not quoted.
#[cfg(any(test, feature = "__internal"))]
pub(crate) fn describe_errors(errors: &[PsValue]) -> String {
    let (parts, more) = describe_parts(errors);
    join_parts(parts, more)
}

fn join_parts(mut parts: Vec<String>, more: usize) -> String {
    if more > 0 {
        parts.push(format!("… and {more} more"));
    }
    if parts.is_empty() {
        return "unknown error".into();
    }
    parts.join("; ")
}

/// The quoted errors, and how many were left out.
fn describe_parts(errors: &[PsValue]) -> (Vec<String>, usize) {
    let parts = errors
        .iter()
        .take(MAX_DESCRIBED_ERRORS)
        .map(|v| escape_remote_text(error_text(v).trim(), MAX_SERVER_MESSAGE_CHARS))
        .collect();
    (parts, errors.len().saturating_sub(MAX_DESCRIBED_ERRORS))
}

/// What to say of one error of the error stream: its exception message,
/// else the identifier of the error, else the value itself.
fn error_text(v: &PsValue) -> String {
    if let PsValue::String(s) = v {
        return s.clone();
    }
    let record = ErrorRecord::from_ps_object(v);
    let message = record
        .as_ref()
        .and_then(|r| r.exception.as_ref()?.message.clone())
        .filter(|m| !m.trim().is_empty());
    let legacy = || match v {
        PsValue::Object(o) => o
            .get("Exception")
            .and_then(PsValue::as_str)
            .or_else(|| o.get("ErrorRecord_Exception").and_then(PsValue::as_str))
            .or_else(|| o.get("Exception_Message").and_then(PsValue::as_str))
            .map(str::to_string),
        _ => None,
    };
    message
        .or_else(legacy)
        .or_else(|| {
            record?
                .fully_qualified_error_id
                .filter(|id| !id.trim().is_empty())
        })
        .unwrap_or_else(|| format!("{v:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clixml::to_clixml;
    use crate::fragment::encode_message;
    use crate::message::{Destination, PsrpMessage};
    use crate::runspace::RunspacePoolState;
    use crate::transport::mock::MockTransport;

    /// `failure_message` with the default budget (shadows the glob import).
    fn failure_message(state_data: &str, errors: &[PsValue]) -> String {
        super::failure_message(state_data, errors, &DecodeBudget::default())
    }

    /// `extract_pipeline_state` with the default budget.
    fn extract_pipeline_state(xml: &str) -> Result<PipelineState> {
        super::extract_pipeline_state(xml, &DecodeBudget::default())
    }

    fn make_state_message<T: Into<i32> + Copy>(
        mt: MessageType,
        prop: &str,
        code: T,
        rpid: Uuid,
        pid: Uuid,
    ) -> Vec<u8> {
        let body = to_clixml(&PsValue::Object(
            PsObject::new().with(prop, PsValue::I32(code.into())),
        ));
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid,
            pid,
            data: body,
        }
        .encode()
    }

    fn make_data_message(mt: MessageType, data: String, rpid: Uuid, pid: Uuid) -> Vec<u8> {
        PsrpMessage {
            destination: Destination::Client,
            message_type: mt,
            rpid,
            pid,
            data,
        }
        .encode()
    }

    /// Seed a MockTransport with an `Opened` state message, open a pool,
    /// then hand the handle back. The transport is cloned so the test can
    /// still queue additional incoming messages afterwards.
    async fn opened_pool_with(t: &MockTransport) -> RunspacePool<MockTransport> {
        let opened = make_state_message(
            MessageType::RunspacePoolState,
            "RunspaceState",
            RunspacePoolState::Opened as i32,
            Uuid::nil(),
            Uuid::nil(),
        );
        // Push Opened at the FRONT so open consumes it first regardless of
        // messages queued by the test before this call.
        t.inbox
            .lock()
            .unwrap()
            .push_front(encode_message(1, &opened));
        RunspacePool::open_with_transport(t.clone()).await.unwrap()
    }

    #[tokio::test]
    async fn pipeline_state_ok() {
        assert!(!PipelineState::Running.is_terminal());
        assert!(PipelineState::Completed.is_terminal());
        assert!(PipelineState::Failed.is_terminal());
        assert!(PipelineState::Stopped.is_terminal());
    }

    #[tokio::test]
    async fn empty_pipeline_errors() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let err = Pipeline::empty().run(&mut pool).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn run_script_collects_output() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        let out1 = make_data_message(
            MessageType::PipelineOutput,
            "<I32>1</I32>".into(),
            rpid,
            pid,
        );
        let out2 = make_data_message(
            MessageType::PipelineOutput,
            "<I32>2</I32>".into(),
            rpid,
            pid,
        );
        let done = make_state_message(
            MessageType::PipelineState,
            "PipelineState",
            PipelineState::Completed as i32,
            rpid,
            pid,
        );
        t.push_incoming(encode_message(10, &out1));
        t.push_incoming(encode_message(11, &out2));
        t.push_incoming(encode_message(12, &done));
        let result = Pipeline::new("1..2")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap();
        assert_eq!(result, vec![PsValue::I32(1), PsValue::I32(2)]);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn run_all_streams_collects_every_stream() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_data_message(MessageType::PipelineOutput, "<S>out</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            2,
            &make_data_message(MessageType::WarningRecord, "<S>warn</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            3,
            &make_data_message(
                MessageType::VerboseRecord,
                "<S>verbose</S>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            4,
            &make_data_message(MessageType::DebugRecord, "<S>debug</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            5,
            &make_data_message(
                MessageType::InformationRecord,
                "<S>info</S>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            6,
            &make_data_message(MessageType::ProgressRecord, "<S>prog</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            7,
            &make_data_message(MessageType::ErrorRecord, "<S>err</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            8,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let result = Pipeline::new("whatever")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.output, vec![PsValue::String("out".into())]);
        assert_eq!(result.warnings, vec![PsValue::String("warn".into())]);
        assert_eq!(result.verbose, vec![PsValue::String("verbose".into())]);
        assert_eq!(result.debug, vec![PsValue::String("debug".into())]);
        assert_eq!(result.information, vec![PsValue::String("info".into())]);
        assert_eq!(result.progress, vec![PsValue::String("prog".into())]);
        assert_eq!(result.errors, vec![PsValue::String("err".into())]);
        assert_eq!(result.state, PipelineState::Completed);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn failed_pipeline_produces_error() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_data_message(MessageType::ErrorRecord, "<S>boom</S>".into(), rpid, pid),
        ));
        t.push_incoming(encode_message(
            2,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Failed as i32,
                rpid,
                pid,
            ),
        ));
        let err = Pipeline::new("fail")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::PipelineFailed(_)));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn stopped_pipeline_produces_stopped_error() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Stopped));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_drops_messages_with_wrong_pid() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        let foreign_pid = Uuid::new_v4();
        // Foreign-pid message must be dropped.
        t.push_incoming(encode_message(
            1,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>666</I32>".into(),
                rpid,
                foreign_pid,
            ),
        ));
        // Wrong-rpid message must also be dropped.
        t.push_incoming(encode_message(
            2,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>777</I32>".into(),
                Uuid::new_v4(),
                pid,
            ),
        ));
        // Real message for our pipeline.
        t.push_incoming(encode_message(
            3,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>42</I32>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            4,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let result = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.output, vec![PsValue::I32(42)]);
        let _ = pool.close().await;
    }

    // ---------- Phase D: PipelineHandle streaming tests ----------

    #[tokio::test]
    async fn pipeline_handle_streams_input() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_data_message(
                MessageType::PipelineOutput,
                "<I32>99</I32>".into(),
                rpid,
                pid,
            ),
        ));
        t.push_incoming(encode_message(
            11,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let mut handle = Pipeline::new("$input | Measure-Object -Sum")
            .__with_forced_pid_for_test(pid)
            .with_input(true)
            .start(&mut pool)
            .await
            .unwrap();

        handle.write_input(PsValue::I32(1)).await.unwrap();
        handle.write_input(PsValue::I32(2)).await.unwrap();
        handle.write_input(PsValue::I32(3)).await.unwrap();

        let result = handle.collect().await.unwrap();
        assert_eq!(result.output, vec![PsValue::I32(99)]);
        assert_eq!(result.state, PipelineState::Completed);

        // Two outgoing frames for open + 1 CreatePipeline + 3 PipelineInput
        // + 1 EndOfPipelineInput = 7.
        assert_eq!(t.sent().len(), 7);
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_handle_write_input_rejected_when_no_input_true() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Completed as i32,
                rpid,
                pid,
            ),
        ));
        let mut handle = Pipeline::new("whatever")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        let err = handle.write_input(PsValue::I32(1)).await.unwrap_err();
        assert!(matches!(err, PsrpError::Protocol(_)));
        // Pipeline identifier is exposed.
        assert_ne!(handle.pid(), Uuid::nil());
        let _result = handle.collect().await.unwrap();
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_handle_cancel_during_collect() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let handle = Pipeline::new("long-running")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = handle.collect_with_cancel(token).await.unwrap_err();
        assert!(matches!(err, PsrpError::Cancelled));
        assert!(*t.stopped.lock().unwrap());
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_handle_explicit_stop() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let mut handle = Pipeline::new("whatever")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        handle.stop().await.unwrap();
        assert!(*t.stopped.lock().unwrap());
        let err = handle.collect().await.unwrap_err();
        assert!(matches!(err, PsrpError::Stopped));
        let _ = pool.close().await;
    }

    #[tokio::test]
    async fn pipeline_run_with_cancel_returns_cancelled() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            10,
            &make_state_message(
                MessageType::PipelineState,
                "PipelineState",
                PipelineState::Stopped as i32,
                rpid,
                pid,
            ),
        ));
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = Pipeline::new("slow")
            .__with_forced_pid_for_test(pid)
            .run_with_cancel(&mut pool, token)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Cancelled));
        let _ = pool.close().await;
    }

    /// Over WinRM the server deletes a stopped command and answers the
    /// Receive in flight with a fault instead of a final `Stopped`: the
    /// transport reports that as `Stopped`, which after our own stop signal
    /// is the cancellation we asked for (#27).
    #[tokio::test]
    async fn a_command_gone_after_the_stop_signal_is_a_cancellation() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        *t.fail_recv.lock().unwrap() = Some(PsrpError::Stopped);
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = Pipeline::new("slow")
            .run_with_cancel(&mut pool, token.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Cancelled), "{err:?}");
        assert!(*t.stopped.lock().unwrap(), "the stop signal was sent");

        let _ = pool.close().await;
    }

    /// The same for the handle's own loop (`start` then `collect_with_cancel`).
    #[tokio::test]
    async fn a_command_gone_after_the_stop_signal_cancels_a_collected_handle() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let handle = Pipeline::new("slow").start(&mut pool).await.unwrap();
        *t.fail_recv.lock().unwrap() = Some(PsrpError::Stopped);
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = handle.collect_with_cancel(token).await.unwrap_err();
        assert!(matches!(err, PsrpError::Cancelled), "{err:?}");
        assert!(*t.stopped.lock().unwrap(), "the stop signal was sent");
        let _ = pool.close().await;
    }

    /// Without a stop signal of ours, `Stopped` stays what it was.
    #[tokio::test]
    async fn stopped_without_our_signal_is_still_stopped() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        *t.fail_recv.lock().unwrap() = Some(PsrpError::Stopped);
        let err = Pipeline::new("slow").run(&mut pool).await.unwrap_err();
        assert!(matches!(err, PsrpError::Stopped), "{err:?}");
        let _ = pool.close().await;
    }

    #[test]
    fn pipeline_handle_debug_format() {
        // Just ensure the Debug impl compiles for the public types.
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_debug::<PipelineResult>();
    }

    #[test]
    fn pipeline_state_from_i32_covers_all_known() {
        for (code, expected) in [
            (0, PipelineState::NotStarted),
            (1, PipelineState::Running),
            (2, PipelineState::Stopping),
            (3, PipelineState::Stopped),
            (4, PipelineState::Completed),
            (5, PipelineState::Failed),
            (6, PipelineState::Disconnected),
            (99, PipelineState::Unknown),
        ] {
            assert_eq!(PipelineState::from_i32(code), expected);
        }
    }

    #[test]
    fn command_builder_named_positional_switch() {
        let c = Command::new("Get-Process")
            .with_parameter("Name", PsValue::String("svchost".into()))
            .with_argument(PsValue::String("explorer".into()))
            .with_switch("FileVersionInfo");
        assert!(!c.is_script);
        assert_eq!(c.arguments.len(), 3);
        match &c.arguments[0] {
            Argument::Named { name, value } => {
                assert_eq!(name, "Name");
                assert_eq!(value, &PsValue::String("svchost".into()));
            }
            _ => panic!(),
        }
        match &c.arguments[1] {
            Argument::Positional(v) => assert_eq!(v, &PsValue::String("explorer".into())),
            _ => panic!(),
        }
        match &c.arguments[2] {
            Argument::Switch(name) => assert_eq!(name, "FileVersionInfo"),
            _ => panic!(),
        }
        let s = Command::script("1+1");
        assert!(s.is_script);
    }

    #[test]
    fn command_merging_errors_to_output() {
        let c = Command::new("Invoke-Foo").merging_errors_to_output();
        assert!(c.merge_errors_to_output);
    }

    #[test]
    fn pipeline_builder() {
        let p = Pipeline::empty()
            .add_command(Command::new("Get-Process"))
            .add_command(Command::new("Select-Object").with_parameter("First", PsValue::I32(5)));
        assert_eq!(p.len(), 2);
        assert!(!p.is_empty());
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("Get-Process"));
        assert!(xml.contains("Select-Object"));
        assert!(xml.contains("First"));
    }

    #[test]
    fn pipeline_xml_emits_switch_as_true_bool() {
        let p = Pipeline::empty()
            .add_command(Command::new("Get-Process").with_switch("FileVersionInfo"));
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<S N=\"N\">FileVersionInfo</S>"));
        assert!(xml.contains("<B N=\"V\">true</B>"));
    }

    #[test]
    fn pipeline_xml_positional_has_nil_name() {
        let p = Pipeline::empty().add_command(
            Command::new("Get-Process").with_argument(PsValue::String("svchost".into())),
        );
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<Nil N=\"N\"/>"));
        assert!(xml.contains("<S N=\"V\">svchost</S>"));
    }

    #[test]
    fn pipeline_with_input_flips_no_input() {
        let p = Pipeline::new("whatever").with_input(true);
        assert!(!p.no_input);
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<B N=\"NoInput\">false</B>"));
    }

    #[test]
    fn pipeline_with_history() {
        let p = Pipeline::new("whatever").with_history(true);
        assert!(p.add_to_history);
        let xml = p.__create_pipeline_xml_for_test();
        assert!(xml.contains("<B N=\"AddToHistory\">true</B>"));
    }

    /// An `ErrorRecord` as PowerShell serializes it: the message is in the
    /// nested `Exception` object, not a string property.
    fn error_record(message: &str) -> PsValue {
        let exception = PsObject::new().with("Message", PsValue::String(message.into()));
        PsValue::Object(PsObject::new().with("Exception", PsValue::Object(exception)))
    }

    /// Live (pwsh 7.6.7, WinRM): the error stream holds `ErrorRecord`
    /// objects, whose message used to be buried in a `{:?}` dump of the
    /// whole record, several KiB long.
    #[test]
    fn describe_errors_reads_the_message_of_an_error_record() {
        assert_eq!(describe_errors(&[error_record("first")]), "first");
        assert_eq!(
            describe_errors(&[error_record("a"), PsValue::String("b".into())]),
            "a; b"
        );
    }

    #[test]
    fn describe_errors_escapes_and_bounds_what_the_server_wrote() {
        let desc = describe_errors(&[
            PsValue::String("bad\u{1b}[2J\r\u{202e}text".into()),
            error_record(&"x".repeat(5000)),
        ]);
        assert!(!desc.contains('\u{1b}') && !desc.contains('\r') && !desc.contains('\u{202e}'));
        assert!(
            desc.starts_with("bad\\u{1b}[2J\\r\\u{202e}text; "),
            "{desc}"
        );
        assert!(desc.chars().count() < 1100, "not bounded: {}", desc.len());
        assert!(desc.ends_with('…'));
    }

    #[test]
    fn describe_errors_quotes_at_most_a_few_errors() {
        let many: Vec<PsValue> = (0..1000)
            .map(|i| PsValue::String(format!("e{i}")))
            .collect();
        let desc = describe_errors(&many);
        assert!(desc.starts_with("e0; e1; "), "{desc}");
        assert!(desc.ends_with("e7; … and 992 more"), "{desc}");
        assert!(!desc.contains("e8;"), "{desc}");
    }

    #[test]
    fn describe_errors_falls_back_to_a_bounded_dump() {
        let weird =
            PsValue::Object(PsObject::new().with("Blob", PsValue::String("y".repeat(5000))));
        let desc = describe_errors(&[weird]);
        assert!(desc.contains("Blob"));
        assert!(desc.chars().count() <= MAX_SERVER_MESSAGE_CHARS + 1);
    }

    fn state_data_with_reason(message: &str) -> String {
        let exception = PsObject::new().with("Message", PsValue::String(message.into()));
        let record = PsObject::new().with("Exception", PsValue::Object(exception));
        to_clixml(&PsValue::Object(
            PsObject::new()
                .with("PipelineState", PsValue::I32(PipelineState::Failed as i32))
                .with("ExceptionAsErrorRecord", PsValue::Object(record)),
        ))
    }

    #[test]
    fn failure_message_prefers_the_state_exception_and_keeps_other_errors() {
        let data = state_data_with_reason("boom");
        assert_eq!(failure_message(&data, &[]), "boom");
        // The same text in the error stream is not repeated.
        assert_eq!(failure_message(&data, &[error_record("boom")]), "boom");
        assert_eq!(
            failure_message(&data, &[error_record("first")]),
            "boom; first"
        );
        let bare = to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(PipelineState::Failed as i32)),
        ));
        assert_eq!(failure_message(&bare, &[error_record("first")]), "first");
        assert_eq!(failure_message(&bare, &[]), "unknown error");
    }

    /// The reason is compared with each error, not searched for in their
    /// text: `File not found: foo` does not say `foo` (review of #28).
    #[test]
    fn failure_message_only_drops_an_identical_error() {
        let data = state_data_with_reason("foo");
        assert_eq!(
            failure_message(&data, &[PsValue::String("File not found: foo".into())]),
            "foo; File not found: foo"
        );
        // Padding does not make the same error two: both sides are trimmed
        // before they are cut at 1024 characters.
        let long = format!("  {}", "x".repeat(1100));
        let data = state_data_with_reason(&long);
        let message = failure_message(&data, &[error_record(&long)]);
        assert_eq!(message.matches('…').count(), 1, "{message}");
        assert!(!message.contains("; "), "{message}");
    }

    /// An `ErrorRecord` with no usable message is named by its error id,
    /// not dumped.
    #[test]
    fn describe_errors_falls_back_to_the_error_id_of_a_record() {
        let record = PsObject::new()
            .with("Exception", PsValue::Object(PsObject::new()))
            .with(
                "FullyQualifiedErrorId",
                PsValue::String("NativeCommandFailed".into()),
            );
        assert_eq!(
            describe_errors(&[PsValue::Object(record)]),
            "NativeCommandFailed"
        );
    }

    /// `ExceptionAsErrorRecord` sent as a bare string still gives the reason.
    #[test]
    fn failure_message_reads_a_bare_string_exception() {
        let data = to_clixml(&PsValue::Object(
            PsObject::new()
                .with("PipelineState", PsValue::I32(PipelineState::Failed as i32))
                .with(
                    "ExceptionAsErrorRecord",
                    PsValue::String("plain \u{1b}reason".into()),
                ),
        ));
        assert_eq!(failure_message(&data, &[]), "plain \\u{1b}reason");
    }

    /// Live (pwsh 7.6.7, WinRM): `throw 'boom'` is reported only in the
    /// `PipelineState` message, and used to come back as "unknown error".
    #[tokio::test]
    async fn failed_pipeline_reports_the_terminating_exception() {
        let t = MockTransport::new();
        let mut pool = opened_pool_with(&t).await;
        let rpid = pool.id();
        let pid = Uuid::new_v4();
        t.push_incoming(encode_message(
            1,
            &make_data_message(
                MessageType::PipelineState,
                state_data_with_reason("bad\u{1b}[31m thing"),
                rpid,
                pid,
            ),
        ));
        let err = Pipeline::new("throw 'boom'")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        let PsrpError::PipelineFailed(message) = &err else {
            panic!("{err:?}");
        };
        assert_eq!(message, "bad\\u{1b}[31m thing");
        let _ = pool.close().await;
    }

    #[test]
    fn describe_errors_formats_variants() {
        assert_eq!(describe_errors(&[]), "unknown error");
        let desc = describe_errors(&[PsValue::String("x".into())]);
        assert_eq!(desc, "x");
        let obj = PsObject::new().with("Exception", PsValue::String("boom".into()));
        let desc = describe_errors(&[PsValue::Object(obj)]);
        assert!(desc.contains("boom"));
    }

    #[test]
    fn pipeline_state_is_terminal() {
        assert!(PipelineState::Completed.is_terminal());
        assert!(PipelineState::Failed.is_terminal());
        assert!(PipelineState::Stopped.is_terminal());
        assert!(PipelineState::Disconnected.is_terminal());
        assert!(!PipelineState::NotStarted.is_terminal());
        assert!(!PipelineState::Running.is_terminal());
        assert!(!PipelineState::Stopping.is_terminal());
        assert!(!PipelineState::Unknown.is_terminal());
    }

    #[test]
    fn typed_errors_parses_error_records() {
        let err_obj = PsObject::new()
            .with(
                "Exception",
                PsValue::Object(PsObject::new().with("Message", PsValue::String("boom".into()))),
            )
            .with("FullyQualifiedErrorId", PsValue::String("Err1".into()));
        let r = PipelineResult {
            errors: vec![
                PsValue::Object(err_obj),
                PsValue::String("not an object".into()),
            ],
            ..Default::default()
        };
        let typed = r.typed_errors();
        assert_eq!(typed.len(), 1);
        assert_eq!(
            typed[0].exception.as_ref().unwrap().message.as_deref(),
            Some("boom")
        );
    }

    #[test]
    fn typed_warnings_parses_warning_records() {
        let warn_obj = PsObject::new().with("Message", PsValue::String("careful".into()));
        let r = PipelineResult {
            warnings: vec![PsValue::Object(warn_obj)],
            ..Default::default()
        };
        let typed = r.typed_warnings();
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].message, "careful");
    }

    #[test]
    fn typed_information_parses() {
        let info_obj = PsObject::new()
            .with("MessageData", PsValue::String("info".into()))
            .with("Source", PsValue::String("src".into()));
        let r = PipelineResult {
            information: vec![PsValue::Object(info_obj)],
            ..Default::default()
        };
        let typed = r.typed_information();
        assert_eq!(typed.len(), 1);
    }

    #[test]
    fn typed_progress_parses() {
        let progress_obj = PsObject::new()
            .with("Activity", PsValue::String("doing".into()))
            .with("PercentComplete", PsValue::I32(50));
        let r = PipelineResult {
            progress: vec![PsValue::Object(progress_obj)],
            ..Default::default()
        };
        let typed = r.typed_progress();
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].percent_complete, Some(50));
    }

    #[test]
    fn typed_verbose_and_debug() {
        let trace_obj = PsObject::new().with("Message", PsValue::String("trace".into()));
        let r = PipelineResult {
            verbose: vec![PsValue::Object(trace_obj.clone())],
            debug: vec![PsValue::Object(trace_obj)],
            ..Default::default()
        };
        assert_eq!(r.typed_verbose().len(), 1);
        assert_eq!(r.typed_debug().len(), 1);
    }

    #[test]
    fn pipeline_empty() {
        let p = Pipeline::empty();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn extract_pipeline_state_errors_when_missing() {
        assert!(extract_pipeline_state("<Obj RefId=\"0\"><MS/></Obj>").is_err());
    }

    #[test]
    fn extract_pipeline_state_ok() {
        let xml = to_clixml(&PsValue::Object(
            PsObject::new().with("PipelineState", PsValue::I32(4)),
        ));
        assert_eq!(
            extract_pipeline_state(&xml).unwrap(),
            PipelineState::Completed
        );
    }

    // ---------- limits, stop after a local error, Disconnected ----------

    /// A pool, a pipeline id, and `messages` queued for that pipeline.
    async fn pool_reading(
        t: &MockTransport,
        messages: &[(MessageType, &str)],
    ) -> (RunspacePool<MockTransport>, Uuid) {
        let pool = opened_pool_with(t).await;
        let pid = Uuid::new_v4();
        for (oid, (mt, data)) in (10u64..).zip(messages) {
            let msg = make_data_message(*mt, (*data).to_string(), pool.id(), pid);
            t.push_incoming(encode_message(oid, &msg));
        }
        (pool, pid)
    }

    const COMPLETED: &str = r#"<Obj RefId="0"><MS><I32 N="PipelineState">4</I32></MS></Obj>"#;
    const DISCONNECTED: &str = r#"<Obj RefId="0"><MS><I32 N="PipelineState">6</I32></MS></Obj>"#;

    fn stopped(t: &MockTransport) -> bool {
        *t.stopped.lock().unwrap()
    }

    /// How many times the transport was told its reader had given up.
    fn abandoned(t: &MockTransport) -> u32 {
        *t.abandoned.lock().unwrap()
    }

    /// Regression: a `PipelineState` message was decoded against the default
    /// gibibyte, whatever `max_pipeline_size` said: with a limit of 64 MiB,
    /// a state message of `<Nil/>` still cost the client a gibibyte.
    #[tokio::test]
    async fn a_state_message_is_bounded_by_max_pipeline_size_too() {
        let node = std::mem::size_of::<PsValue>();
        // A state carrying a thousand values nobody asked for, once
        // `Completed` and once `Failed` (read a second time for its reason).
        let padded = |state: i32| {
            format!(
                r#"<Obj RefId="0"><MS><I32 N="PipelineState">{state}</I32></MS><LST>{}</LST></Obj>"#,
                "<Nil/>".repeat(1000)
            )
        };
        for (state, roomy) in [(4, true), (4, false), (5, true), (5, false)] {
            let body = padded(state);
            let t = MockTransport::new();
            let (mut pool, pid) = pool_reading(&t, &[(MessageType::PipelineState, &body)]).await;
            let limit = if roomy { 2000 * node } else { 500 * node };
            pool.set_receive_limits(pool.receive_limits().with_max_pipeline_size(limit));
            let outcome = Pipeline::new("x")
                .__with_forced_pid_for_test(pid)
                .run_all_streams(&mut pool)
                .await;
            match (state, roomy) {
                (4, true) => assert_eq!(outcome.unwrap().state, PipelineState::Completed),
                (_, true) => {
                    let err = outcome.unwrap_err();
                    assert!(matches!(err, PsrpError::PipelineFailed(_)), "{err:?}");
                }
                (_, false) => {
                    let err = outcome.unwrap_err();
                    assert!(matches!(err, PsrpError::Clixml(_)), "{state}: {err:?}");
                    assert!(stopped(&t), "{state}: the command is stopped");
                }
            }
            let _ = pool.close().await;
        }
    }

    /// The state that ends a pipeline is read even when the output has
    /// filled the budget to the last byte.
    #[tokio::test]
    async fn a_full_budget_does_not_refuse_the_final_state() {
        let values = "<S>0123456789</S>".repeat(40);
        let mut budget = DecodeBudget::new(usize::MAX);
        parse_clixml_within(&values, &mut budget).unwrap();

        let t = MockTransport::new();
        let messages = [
            (MessageType::PipelineOutput, values.as_str()),
            (MessageType::PipelineState, COMPLETED),
        ];
        let (mut pool, pid) = pool_reading(&t, &messages).await;
        pool.set_receive_limits(pool.receive_limits().with_max_pipeline_size(budget.used()));
        let result = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.output.len(), 40);
        assert_eq!(result.state, PipelineState::Completed);
        assert!(!stopped(&t));
        let _ = pool.close().await;
    }

    /// Regression: an error on a message the client had read (here one that
    /// does not decode) returned at once, and the command went on running on
    /// the server with nobody reading it.
    #[tokio::test]
    async fn a_message_that_does_not_decode_stops_the_remote_command() {
        for stream in [
            MessageType::PipelineOutput,
            MessageType::ErrorRecord,
            MessageType::ProgressRecord,
            MessageType::PipelineState,
        ] {
            let t = MockTransport::new();
            let (mut pool, pid) = pool_reading(&t, &[(stream, "<I32>not a number</I32>")]).await;
            let err = Pipeline::new("x")
                .__with_forced_pid_for_test(pid)
                .run_all_streams(&mut pool)
                .await
                .unwrap_err();
            assert!(
                matches!(err, PsrpError::Clixml(_)),
                "{stream:?}: the decode error is the one returned, got {err:?}"
            );
            assert!(stopped(&t), "{stream:?}: the command was left running");
            assert_eq!(abandoned(&t), 1, "{stream:?}: the transport was not told");
            let _ = pool.close().await;
        }
    }

    /// Regression, measured against Windows Server 2025 and 2012 R2: over
    /// WinRM the stop signal alone does not stop a command that is writing
    /// output, the output has to be taken. The reader that gives up tells
    /// the transport (`abandon_pipeline`), once the stop is asked for, also
    /// when it was the caller's cancellation that asked for it.
    #[tokio::test]
    async fn a_reader_that_gives_up_after_a_cancellation_tells_the_transport() {
        let t = MockTransport::new();
        let (mut pool, pid) =
            pool_reading(&t, &[(MessageType::PipelineOutput, "<B>maybe</B>")]).await;
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams_with_cancel(&mut pool, token)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Clixml(_)), "{err:?}");
        assert!(stopped(&t));
        assert_eq!(abandoned(&t), 1);
        let _ = pool.close().await;
    }

    /// Same on the `start` / `collect` path, which shares the loop.
    #[tokio::test]
    async fn collect_stops_the_remote_command_after_a_decode_error() {
        let t = MockTransport::new();
        let (mut pool, pid) =
            pool_reading(&t, &[(MessageType::PipelineOutput, "<B>maybe</B>")]).await;
        let handle = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .start(&mut pool)
            .await
            .unwrap();
        let err = handle.collect().await.unwrap_err();
        assert!(matches!(err, PsrpError::Clixml(_)), "{err:?}");
        assert!(stopped(&t));
        let _ = pool.close().await;
    }

    /// A transport error is not answered with a stop signal: it would go
    /// down the transport that has just failed.
    #[tokio::test]
    async fn a_transport_error_sends_no_stop_signal() {
        let t = MockTransport::new();
        let (mut pool, pid) =
            pool_reading(&t, &[(MessageType::PipelineOutput, "<I32>1</I32>")]).await;
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mock inbox empty"), "{err}");
        assert!(!stopped(&t));
        assert_eq!(abandoned(&t), 0);
        let _ = pool.close().await;
    }

    /// Neither is a pipeline that ended by itself.
    #[tokio::test]
    async fn a_failed_or_completed_pipeline_sends_no_stop_signal() {
        let failed = r#"<Obj RefId="0"><MS><I32 N="PipelineState">5</I32></MS></Obj>"#;
        for (state, ok) in [(COMPLETED, true), (failed, false)] {
            let t = MockTransport::new();
            let (mut pool, pid) = pool_reading(&t, &[(MessageType::PipelineState, state)]).await;
            let got = Pipeline::new("x")
                .__with_forced_pid_for_test(pid)
                .run_all_streams(&mut pool)
                .await;
            assert_eq!(got.is_ok(), ok);
            assert!(!stopped(&t));
            assert_eq!(abandoned(&t), 0);
            let _ = pool.close().await;
        }
    }

    /// Regression: what a pipeline returned was held without any bound, so a
    /// command whose output never stops was read until the process ran out
    /// of memory. The streams now share the pool's `max_pipeline_size`.
    #[tokio::test]
    async fn a_pipeline_is_bounded_by_max_pipeline_size() {
        let node = std::mem::size_of::<PsValue>();
        let messages = [
            (MessageType::PipelineOutput, "<I32>1</I32>"),
            (MessageType::WarningRecord, "<I32>2</I32>"),
            (MessageType::PipelineOutput, "<I32>3</I32>"),
            (MessageType::PipelineState, COMPLETED),
        ];

        // Three values fit in a limit of three.
        let t = MockTransport::new();
        let (mut pool, pid) = pool_reading(&t, &messages).await;
        pool.set_receive_limits(pool.receive_limits().with_max_pipeline_size(3 * node));
        let result = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.output, vec![PsValue::I32(1), PsValue::I32(3)]);
        assert_eq!(result.warnings, vec![PsValue::I32(2)]);
        assert!(!stopped(&t));
        // The limit is per pipeline: the next one starts from nothing.
        let pid = Uuid::new_v4();
        for (oid, (mt, data)) in (20u64..).zip(&messages) {
            let msg = make_data_message(*mt, (*data).to_string(), pool.id(), pid);
            t.push_incoming(encode_message(oid, &msg));
        }
        let again = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap();
        assert_eq!(again.len(), 2);
        let _ = pool.close().await;

        // One byte less: the third value is refused, whatever its stream,
        // and the command is stopped.
        let t = MockTransport::new();
        let (mut pool, pid) = pool_reading(&t, &messages).await;
        pool.set_receive_limits(pool.receive_limits().with_max_pipeline_size(3 * node - 1));
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Clixml(_)), "{err:?}");
        assert!(err.to_string().contains("limit"), "{err}");
        assert!(stopped(&t), "the command was left running");
        let _ = pool.close().await;
    }

    /// A message over `max_message_size` ends the pipeline the same way.
    #[tokio::test]
    async fn a_message_over_the_size_limit_stops_the_remote_command() {
        let t = MockTransport::new();
        let big = format!("<S>{}</S>", "x".repeat(4096));
        let (mut pool, pid) = pool_reading(&t, &[(MessageType::PipelineOutput, &big)]).await;
        pool.set_receive_limits(pool.receive_limits().with_max_message_size(1024));
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)), "{err:?}");
        assert!(stopped(&t), "the command was left running");
        let _ = pool.close().await;
    }

    /// Regression: `Disconnected` is terminal, so `run` returned the output
    /// read so far as if the pipeline had completed.
    #[tokio::test]
    async fn a_disconnected_pipeline_is_not_a_completed_one() {
        let messages = [
            (MessageType::PipelineOutput, "<I32>1</I32>"),
            (MessageType::PipelineState, DISCONNECTED),
        ];
        let expect_bad_state = |err: PsrpError| {
            let PsrpError::BadState { expected, actual } = err else {
                panic!("expected BadState, got {err:?}");
            };
            assert_eq!(
                (expected.as_str(), actual.as_str()),
                ("Completed", "Disconnected")
            );
        };

        let t = MockTransport::new();
        let (mut pool, pid) = pool_reading(&t, &messages).await;
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run(&mut pool)
            .await
            .unwrap_err();
        expect_bad_state(err);
        let _ = pool.close().await;

        let t = MockTransport::new();
        let (mut pool, pid) = pool_reading(&t, &messages).await;
        let err = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_with_cancel(&mut pool, tokio_util::sync::CancellationToken::new())
            .await
            .unwrap_err();
        expect_bad_state(err);
        let _ = pool.close().await;

        // With every stream the caller sees the state, and what was read.
        let t = MockTransport::new();
        let (mut pool, pid) = pool_reading(&t, &messages).await;
        let result = Pipeline::new("x")
            .__with_forced_pid_for_test(pid)
            .run_all_streams(&mut pool)
            .await
            .unwrap();
        assert_eq!(result.state, PipelineState::Disconnected);
        assert_eq!(result.output, vec![PsValue::I32(1)]);
        assert!(!stopped(&t));
        let _ = pool.close().await;
    }

    #[test]
    fn completed_output_passes_every_other_state() {
        for state in [PipelineState::Completed, PipelineState::Running] {
            let result = PipelineResult {
                output: vec![PsValue::I32(1)],
                state,
                ..PipelineResult::default()
            };
            assert_eq!(completed_output(result).unwrap(), vec![PsValue::I32(1)]);
        }
    }

    /// Every stream message type goes to its own stream, and nothing else is
    /// filed.
    #[test]
    fn file_message_routes_each_stream() {
        let streams = [
            MessageType::PipelineOutput,
            MessageType::ErrorRecord,
            MessageType::WarningRecord,
            MessageType::VerboseRecord,
            MessageType::DebugRecord,
            MessageType::InformationRecord,
            MessageType::ProgressRecord,
        ];
        let mut result = PipelineResult::default();
        let mut budget = DecodeBudget::new(usize::MAX);
        let message = |message_type, data: String| PsrpMessage {
            destination: Destination::Client,
            message_type,
            rpid: Uuid::nil(),
            pid: Uuid::nil(),
            data,
        };
        for (n, mt) in (0i32..).zip(streams) {
            let filed = file_message(
                &message(mt, format!("<I32>{n}</I32>")),
                &mut result,
                &mut budget,
            );
            assert_eq!(filed.unwrap(), None);
        }
        let got = [
            &result.output,
            &result.errors,
            &result.warnings,
            &result.verbose,
            &result.debug,
            &result.information,
            &result.progress,
        ];
        for (n, stream) in (0i32..).zip(got) {
            assert_eq!(stream, &vec![PsValue::I32(n)], "stream {n}");
        }

        let filed = file_message(
            &message(MessageType::PipelineState, COMPLETED.into()),
            &mut result,
            &mut budget,
        );
        assert_eq!(filed.unwrap(), Some(PipelineState::Completed));
        assert_eq!(result.state, PipelineState::Completed);

        let ignored = file_message(
            &message(MessageType::ApplicationPrivateData, "<I32>9</I32>".into()),
            &mut result,
            &mut budget,
        );
        assert_eq!(ignored.unwrap(), None);
        assert_eq!(result.output, vec![PsValue::I32(0)]);
    }
}
