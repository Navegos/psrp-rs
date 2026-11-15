//! Thin wrapper around [`winrm_rs::Shell`] that ferries PSRP fragments.
//!
//! This module is the **only** place in the crate that imports
//! `winrm_rs::Shell`. Every higher-level component (runspace pool,
//! pipeline) talks to the transport through the [`PsrpTransport`] trait so
//! it can be mocked in tests without standing up a fake SOAP server.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::{debug, warn};
use winrm_rs::{RESOURCE_URI_PSRP, ReceiveOutput, Shell, SoapError, WinrmClient, WinrmError};

use crate::error::{PsrpError, Result};

/// Abstract transport used by the runspace pool and pipeline.
///
/// `send_fragment` sends the messages addressed to the pool and
/// `send_pipeline_fragment` those addressed to a pipeline, as pre-encoded
/// fragment bytes. How they travel is up to each transport:
/// [`WinrmPsrpTransport`] writes them in a single `send_input` call; the
/// SSH transport (`ssh` feature) writes them in `<Data>` lines of at most
/// 32 KiB, each acknowledged before the next. `recv_chunk` MUST
/// transparently retry an empty long poll (long-polling is expected), MUST
/// NOT wait without bound on client-side timeouts, and propagates every
/// other error — in particular SOAP faults, which usually mean the
/// server-side shell has died and the pool must be recreated.
///
/// A transport that wraps or forwards to another one MUST forward
/// `send_pipeline_fragment` too, not only `send_fragment`. Its default
/// body calls `send_fragment`, which addresses the pool: around the SSH
/// transport, such a wrapper would send every pipeline message on
/// `Guid.Empty` instead of the pipeline's id, with no compile error and
/// no warning.
#[async_trait]
pub trait PsrpTransport: Send {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()>;

    /// Send the fragments of a message addressed to pipeline `pipeline_id`
    /// (`Uuid::nil()` addresses the pool). Transports that multiplex by
    /// pipeline (PowerShell's out-of-process protocol) override it; the
    /// default forwards to `send_fragment`, which keeps WinRM unchanged.
    ///
    /// Takes `&mut self`, like [`PsrpTransport::execute_pipeline`]: with
    /// `&self`, `#[async_trait]` would require `Self: Sync` on a default
    /// body, which this trait does not promise.
    async fn send_pipeline_fragment(
        &mut self,
        bytes: &[u8],
        pipeline_id: uuid::Uuid,
    ) -> Result<()> {
        let _ = pipeline_id;
        self.send_fragment(bytes).await
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>>;
    /// Ask the server to stop the pipeline being read.
    ///
    /// The stop is over when the pipeline's terminal state has been read,
    /// not when this returns: a transport may return with the request still
    /// in flight (WinRM does, for a pipeline that has output to deliver),
    /// and then finishes it in [`recv_chunk`](Self::recv_chunk).
    async fn signal_stop(&self) -> Result<()>;
    async fn close_shell(&mut self) -> Result<()>;

    /// Start a pipeline by executing a WS-Man Command with the first
    /// PSRP fragment as an argument and the pipeline's UUID as the
    /// CommandId. Subsequent Send/Receive use this CommandId.
    /// Default: sends via `send_fragment` (mock transport behavior).
    async fn execute_pipeline(
        &mut self,
        fragment_bytes: &[u8],
        _pipeline_id: uuid::Uuid,
    ) -> Result<()> {
        self.send_fragment(fragment_bytes).await
    }

    /// Whether the bytes [`recv_chunk`](Self::recv_chunk) returns after
    /// [`execute_pipeline`](Self::execute_pipeline) come from a stream of
    /// their own, which continues nothing of what was read before. True
    /// over WinRM, where each pipeline is a WS-Man command read by its own
    /// Receives; false, the default, for a transport that carries the pool
    /// and its pipelines in one stream (`OutOfProc`).
    ///
    /// When it is true the pool forgets the fragments it holds half
    /// received as the pipeline starts: what an abandoned pipeline left
    /// behind (a message cut short, the rest of a fragment refused for its
    /// size) would otherwise be taken for the start of the next one. A
    /// wrapper transport must forward it.
    fn pipeline_has_its_own_stream(&self) -> bool {
        false
    }

    /// The reader of the pipeline has given up before its end, after
    /// [`signal_stop`](Self::signal_stop): settle what that leaves behind,
    /// best effort and within a bound of the transport's own.
    ///
    /// Nothing to do, the default, for a transport that carries the pool
    /// and its pipelines in one stream: that stream goes on being read.
    /// Over WinRM the pipeline's stream is read by nobody from now on, and a
    /// pipeline that was writing output stops only once that output is
    /// taken: the transport reads it to its end, dropping it, and releases
    /// the stop request still in flight. A wrapper transport must forward
    /// it.
    async fn abandon_pipeline(&mut self) {}

    /// Disconnect the underlying transport while leaving the server-side
    /// resources alive. Returns an opaque handle that the caller can pass
    /// back to the transport-specific reconnect path. For
    /// [`WinrmPsrpTransport`] this is the WinRM `shell_id`.
    ///
    /// Default implementation returns an error so that transports that
    /// don't support disconnect (e.g. mocks) don't have to implement it.
    async fn disconnect_shell(&mut self) -> Result<String> {
        Err(PsrpError::protocol(
            "this transport does not implement disconnect_shell",
        ))
    }
}

/// One future that survives its caller giving up.
///
/// A WS-Man Receive is a long poll: the server holds the request until it has
/// output, and the response, once the server has produced it, is lost if the
/// client drops the request (hyper closes the connection). `recv_chunk` is
/// dropped by `select!` when a pipeline is cancelled, so the Receive it was
/// polling is kept here instead and resumed by the next call.
struct Parked<'c, T> {
    /// In a `Mutex` only to make the transport `Sync` (the trait's `&self`
    /// methods need it, a boxed future is not): it is only ever reached
    /// through `&mut self`, with `get_mut`.
    in_flight: std::sync::Mutex<Option<Pin<Box<dyn Future<Output = T> + Send + 'c>>>>,
}

impl<'c, T> Parked<'c, T> {
    const fn new() -> Self {
        Self {
            in_flight: std::sync::Mutex::new(None),
        }
    }

    fn slot(&mut self) -> &mut Option<Pin<Box<dyn Future<Output = T> + Send + 'c>>> {
        self.in_flight
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drive the parked future, starting `start()` first if there is none.
    ///
    /// Cancel-safe: dropping this call leaves the future parked, and the next
    /// call polls the same one. It is forgotten only once it has completed.
    async fn drive<F>(&mut self, start: impl FnOnce() -> F) -> T
    where
        F: Future<Output = T> + Send + 'c,
    {
        let in_flight = self.slot().get_or_insert_with(|| Box::pin(start()));
        let output = in_flight.as_mut().await;
        *self.slot() = None;
        output
    }

    /// Give up the parked future (its response, if any, is lost).
    fn discard(&mut self) {
        *self.slot() = None;
    }

    /// Park a future already under way, in place of the one parked (which
    /// is dropped). Through `&self`: `signal_stop` has no more.
    fn park(&self, in_flight: Pin<Box<dyn Future<Output = T> + Send + 'c>>) {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(in_flight);
    }

    /// Drive the parked future to its end and forget it. With nothing
    /// parked this never returns: it is one branch of a `select!`.
    ///
    /// Cancel-safe, like [`drive`](Self::drive).
    async fn finish(&mut self) -> T {
        let Some(in_flight) = self.slot() else {
            return std::future::pending().await;
        };
        let output = in_flight.as_mut().await;
        *self.slot() = None;
        output
    }
}

/// How long `signal_stop` waits for the server to answer the stop signal
/// before it leaves the request in flight.
///
/// The server answers a stop signal once the pipeline *has* stopped, and a
/// pipeline with output to deliver stops only when a Receive takes that
/// output: waiting for the answer without reading is a deadlock that ends
/// with the server's `w:TimedOut` (measured against Windows Server 2025:
/// `operation_timeout_secs` later, the pipeline still running). A pipeline
/// with nothing to deliver answers within a round trip, and a refused signal
/// does too: those are still reported by `signal_stop` itself.
const STOP_SIGNAL_GRACE: Duration = Duration::from_millis(500);

/// How long the start of a command waits for the command stopped before it
/// to end, when its reader left before the end (see
/// [`WinrmPsrpTransport::finish_stopped_command`]).
const STOPPED_COMMAND_DRAIN: Duration = Duration::from_secs(5);

/// The stop signal of a command: answered within `grace`, its answer; left
/// in flight in `stop` otherwise (`None`), for the Receives to finish.
async fn signal_within<'c, T>(
    stop: &Parked<'c, T>,
    grace: Duration,
    mut signal: Pin<Box<dyn Future<Output = T> + Send + 'c>>,
) -> Option<T> {
    if let Ok(answer) = tokio::time::timeout(grace, signal.as_mut()).await {
        return Some(answer);
    }
    stop.park(signal);
    None
}

/// Drive the Receive to its answer, and with it the stop signal left in
/// flight, if there is one: the server answers that signal only once a
/// Receive has taken what the pipeline had to deliver.
///
/// `stop_answer` judges the answer to the signal: an error ends the call
/// (the Receive stays parked). Cancel-safe: both requests stay parked.
async fn receive_while_stopping<'c, T, S, F>(
    receive: &mut Parked<'c, T>,
    stop: &mut Parked<'c, S>,
    start: impl FnOnce() -> F,
    stop_answer: impl Fn(S) -> Result<()>,
) -> Result<T>
where
    F: Future<Output = T> + Send + 'c,
{
    let receive = receive.drive(start);
    tokio::pin!(receive);
    loop {
        tokio::select! {
            biased;
            polled = &mut receive => return Ok(polled),
            answer = stop.finish() => stop_answer(answer)?,
        }
    }
}

/// Whether `err` is the server tired of waiting for the pipeline to stop:
/// the `w:TimedOut` fault that answers a stop signal after
/// `operation_timeout_secs`. `recv_chunk` returns that fault only for a stop
/// signal left in flight (a Receive's own is an empty poll, see
/// [`classify_receive`]).
///
/// It is not a refusal: the stop stays asked for, and the pipeline stops
/// when it can (when its output is taken, or when the cmdlet it runs
/// returns). The client's own `WinrmError::Timeout` is another matter: the
/// request ran out of time before an answer, on a connection slot or a
/// handshake, and may never have left.
fn still_stopping(err: &PsrpError) -> bool {
    matches!(
        err,
        PsrpError::Winrm(WinrmError::Soap(SoapError::Fault { code, .. }))
            if code.contains("TimedOut")
    )
}

/// Transport backed by a live `winrm_rs::Shell`.
///
/// `recv_chunk` retries an empty long poll without limit, and a
/// client-side `WinrmError::Timeout` at most twice in a row: the third is
/// returned, after at most 3 × (`operation_timeout_secs` + 10 s), 210 s
/// with the default settings. A server that answers its Receives at once
/// with nothing is polled at most once a second, not as fast as it answers.
pub struct WinrmPsrpTransport<'c> {
    shell: Option<Arc<Shell<'c>>>,
    /// The Receive in flight for `command_id`, if a `recv_chunk` was dropped.
    receive: Parked<'c, std::result::Result<ReceiveOutput, WinrmError>>,
    /// The stop signal sent for `command_id` and not answered yet (see
    /// [`STOP_SIGNAL_GRACE`]): `recv_chunk` drives it along with its Receives.
    stop: Parked<'c, std::result::Result<(), WinrmError>>,
    command_id: String,
    /// A stop signal was sent for `command_id` (accepted, or still in
    /// flight in `stop`). The server then deletes the command, and answers
    /// the Receive in flight with `InvalidSelectors` instead of a final
    /// `PipelineState`: that fault means "stopped".
    stop_signalled: std::sync::atomic::AtomicBool,
    /// `command_id` has ended: the server said so (`CommandState/Done`), or
    /// the command was gone after a stop. Starts over with each command.
    done: bool,
    /// The end of `command_id` was waited for once after its stop (see
    /// [`finish_stopped_command`](Self::finish_stopped_command)): it is not
    /// waited for again.
    end_awaited: bool,
    /// True after a pipeline command has been started via Execute.
    /// Before this, Receive/Send use the PSRP-no-commandid path.
    has_command: bool,
    /// The empty polls answered at once so far, and when the next Receive
    /// may be sent (see [`PollPacer`]). Both outlive a `recv_chunk`: a wait
    /// dropped by `select!` is finished by the next call, and the pool calls
    /// again after an empty chunk.
    pacer: PollPacer,
    resume_at: Option<tokio::time::Instant>,
}

impl std::fmt::Debug for WinrmPsrpTransport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinrmPsrpTransport")
            .field("command_id", &self.command_id)
            .field("has_shell", &self.shell.is_some())
            .field("done", &self.done)
            .finish()
    }
}

impl<'c> WinrmPsrpTransport<'c> {
    /// Open a PSRP shell embedding the opening fragments in `<creationXml>`.
    ///
    /// `creation_fragments` are the raw bytes of the
    /// `SessionCapability + InitRunspacePool` PSRP messages, already
    /// fragment-encoded. They get base64-wrapped and embedded in the
    /// WS-Man Create Shell body.
    ///
    /// `host` is bare and canonical: a host name, a dotted-quad IPv4 address
    /// or a bracketed IPv6 literal in RFC 5952 form, with no scheme,
    /// `user@`, path or port. The port, TLS and authentication come from the
    /// `client`'s [`WinrmConfig`](winrm_rs::WinrmConfig). Any other form
    /// (`host:5985`, `10.1`, ...) is refused before a request is sent, with
    /// [`PsrpError::Winrm`] ([`WinrmError::Config`]).
    pub async fn open(
        client: &'c WinrmClient,
        host: &str,
        creation_fragments: &[u8],
    ) -> Result<Self> {
        let creation_b64 = crate::clixml::encode::base64_encode(creation_fragments);
        let shell = client
            .open_psrp_shell(host, &creation_b64, RESOURCE_URI_PSRP)
            .await?;
        // PSRP shells do NOT use Execute Command — the shell IS the PS
        // process. Receive/Send operate directly on the shell, using
        // the shell_id as the "command_id" in the WS-Man envelope.
        let command_id = shell.shell_id().to_string();
        debug!(command_id, "PSRP transport started (no command yet)");
        Ok(Self {
            shell: Some(Arc::new(shell)),
            receive: Parked::new(),
            stop: Parked::new(),
            stop_signalled: std::sync::atomic::AtomicBool::new(false),
            command_id,
            done: false,
            end_awaited: false,
            has_command: false,
            pacer: PollPacer::default(),
            resume_at: None,
        })
    }

    /// Reconnect to a previously-disconnected PSRP shell. `host` takes the
    /// same bare form as in [`Self::open`].
    pub async fn reconnect(client: &'c WinrmClient, host: &str, shell_id: &str) -> Result<Self> {
        let shell = client
            .reconnect_shell(host, shell_id, RESOURCE_URI_PSRP)
            .await?;
        let command_id = shell.shell_id().to_string();
        debug!(command_id, "PSRP transport reconnected");
        Ok(Self {
            shell: Some(Arc::new(shell)),
            receive: Parked::new(),
            stop: Parked::new(),
            stop_signalled: std::sync::atomic::AtomicBool::new(false),
            command_id,
            done: false,
            end_awaited: false,
            has_command: false,
            pacer: PollPacer::default(),
            resume_at: None,
        })
    }

    /// Execute an empty command inside the PSRP shell to obtain a
    /// `command_id` for Send/Receive. Called by the pool after the
    /// opening handshake completes. After this, `send_fragment` and
    /// `recv_chunk` include `CommandId` in their SOAP envelopes.
    pub async fn start_pipeline_command(&mut self) -> Result<()> {
        self.finish_stopped_command().await;
        let shell = self.shell()?;
        let cmd_id = shell.start_command("", &[]).await?;
        debug!(cmd_id, "PSRP pipeline command started");
        self.command_started(cmd_id);
        Ok(())
    }

    /// `command_id` is the command read from now on: what was in flight
    /// for the one before (a Receive, a stop signal) is given up.
    fn command_started(&mut self, command_id: String) {
        self.receive.discard();
        self.stop.discard();
        self.stop_signalled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.command_id = command_id;
        self.has_command = true;
        self.done = false;
        self.end_awaited = false;
        // The pace is earned by the answers of one command: the first
        // Receive of this one waits for nothing.
        self.pacer = PollPacer::default();
        self.resume_at = None;
    }

    /// Read the command a stop was signalled for to its end, when its
    /// reader has not (it gave up on a message, or was dropped): called
    /// when the reader gives up ([`abandon_pipeline`]) and, for a reader
    /// that left without a word, before the next command starts.
    ///
    /// A pipeline with output to deliver stops only once that output is
    /// taken (see [`STOP_SIGNAL_GRACE`]). Left unread, it keeps its
    /// runspace, and the pipeline started next waits for one: for ever on a
    /// pool of one runspace, as far as the client can tell. What is read
    /// here is dropped: the pipeline was given up. The stop request still
    /// in flight is driven along, then given up too: left parked in a pool
    /// that reads nothing, it would keep its connection and its place among
    /// the client's requests for as long.
    ///
    /// Best effort, once per command, and bounded by
    /// [`STOPPED_COMMAND_DRAIN`]: a command that does not end in time (a
    /// server that never stops it, a cmdlet that cannot be interrupted) is
    /// left as it is, and so is one that answers with an error.
    ///
    /// [`abandon_pipeline`]: PsrpTransport::abandon_pipeline
    async fn finish_stopped_command(&mut self) {
        let stopping = self.has_command
            && !self.done
            && !self.end_awaited
            && self
                .stop_signalled
                .load(std::sync::atomic::Ordering::SeqCst);
        if stopping {
            self.end_awaited = true;
            let drain = async {
                while !self.done {
                    match self.recv_chunk().await {
                        Ok(bytes) if bytes.is_empty() => break,
                        Ok(_) => {}
                        // The server stopped waiting for the pipeline to
                        // stop while nobody was reading it: reading is what
                        // it takes.
                        Err(e) if still_stopping(&e) => {}
                        Err(_) => {
                            debug!("PSRP stopped command: its stream ended with an error");
                            break;
                        }
                    }
                }
            };
            if tokio::time::timeout(STOPPED_COMMAND_DRAIN, drain)
                .await
                .is_err()
            {
                debug!("PSRP stopped command: still running, left as it is");
            }
        }
        self.stop.discard();
    }

    fn shell(&self) -> Result<&Shell<'c>> {
        self.shell
            .as_deref()
            .ok_or_else(|| PsrpError::protocol("transport closed"))
    }

    /// Take the shell out to consume it (`close`, `disconnect`). A Receive
    /// still parked holds a second handle on it: it is dropped first.
    fn take_shell(&mut self) -> Result<Option<Shell<'c>>> {
        self.receive.discard();
        self.stop.discard();
        let Some(shell) = self.shell.take() else {
            return Ok(None);
        };
        Arc::try_unwrap(shell)
            .map(Some)
            .map_err(|_| PsrpError::protocol("transport busy: the shell is still shared"))
    }
}

/// What one finished Receive means for `recv_chunk`.
enum Poll {
    /// The server's `w:TimedOut` fault: nothing to read yet, ask again.
    /// winrm-rs (from 1.4) normally folds that fault into an empty
    /// [`Poll::Chunk`] before psrp-rs sees it (`Shell::receive_next`); this
    /// arm is kept for a fault that reaches us anyway.
    Retry,
    /// The client gave up waiting for this Receive (`WinrmError::Timeout`):
    /// ask again, at most [`MAX_CONSECUTIVE_TIMEOUTS`] times in a row.
    TimedOut(WinrmError),
    Chunk(ReceiveOutput),
}

/// How many `WinrmError::Timeout` in a row `recv_chunk` absorbs before it
/// returns the last one.
///
/// winrm-rs raises it when the request budget (`operation_timeout_secs`
/// plus 10 s) runs out before an answer: while waiting for a connection
/// slot, during an authentication handshake, or for a Kerberos KDC. A long
/// poll that ends normally never raises it (the server answers `TimedOut`
/// first, an empty poll), so one in a row is a slow server and three is a
/// stuck one: an unreachable KDC, or a handshake that never completes,
/// which `recv_chunk` used to retry forever. The wait before giving up is
/// therefore at most 3 × (`operation_timeout_secs` + 10 s), 210 s with the
/// defaults.
///
/// With winrm-rs's `credssp` feature, a CredSSP exchange that runs out of
/// time is a `Timeout` too, and the last one of its handshake may have
/// left the Receive running on the server: the retry then cannot get that
/// answer back, and the pool fails on the next message instead.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 3;

/// The client-side timeouts `recv_chunk` met in a row.
#[derive(Debug, Default)]
struct TimeoutStreak(u32);

impl TimeoutStreak {
    /// Count one more timeout: the streak so far while it stays under
    /// [`MAX_CONSECUTIVE_TIMEOUTS`], the error itself once it reaches it.
    fn record(&mut self, err: WinrmError) -> Result<u32> {
        self.0 = self.0.saturating_add(1);
        if self.0 >= MAX_CONSECUTIVE_TIMEOUTS {
            return Err(PsrpError::Winrm(err));
        }
        Ok(self.0)
    }

    /// An answer arrived: the server is alive, the streak starts over.
    fn reset(&mut self) {
        self.0 = 0;
    }
}

/// Paces `recv_chunk` against a server that answers at once with nothing.
///
/// A Receive is a long poll: a server with nothing to say holds it for
/// `operation_timeout_secs`. One that answers at once, empty, every time (a
/// broken or hostile one) made `recv_chunk` send the next Receive at once
/// too, for ever: a request loop as fast as the network, with no data and no
/// error, which no timeout ends. `Shell::receive_next` sends one Receive and
/// never waits; its documentation leaves the pace to the caller and gives the
/// figures of winrm-rs's own `run_command`, used here: the first two quick
/// empty polls in a row cost nothing, the third is followed by 50 ms, then
/// twice as long each time up to one second.
#[derive(Debug, Default)]
struct PollPacer {
    quick_empty: u32,
}

impl PollPacer {
    /// A poll that came back sooner than this with nothing is a quick empty
    /// poll: a long poll that timed out on the server took far longer.
    const QUICK: Duration = Duration::from_millis(250);
    /// Quick empty polls in a row that are not delayed.
    const FREE: u32 = 2;
    /// The first delay.
    const FIRST: Duration = Duration::from_millis(50);
    /// The longest delay.
    const MAX: Duration = Duration::from_secs(1);

    /// How long to wait before the next Receive, after one that took
    /// `elapsed` and `progressed` (brought bytes) or not. A poll that
    /// progressed, or took [`QUICK`](Self::QUICK) or longer, starts the
    /// count over.
    fn delay_after(&mut self, elapsed: Duration, progressed: bool) -> Option<Duration> {
        if progressed || elapsed >= Self::QUICK {
            self.quick_empty = 0;
            return None;
        }
        self.quick_empty = self.quick_empty.saturating_add(1);
        let over = self.quick_empty.checked_sub(Self::FREE.saturating_add(1))?;
        let doublings = 2u32.saturating_pow(over.min(16));
        Some(Self::FIRST.saturating_mul(doublings).min(Self::MAX))
    }
}

/// What `recv_chunk` does after one Receive.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Nothing for the caller yet: send the next Receive.
    Again,
    /// Return these bytes (possibly empty, once the command is done).
    Deliver(Vec<u8>),
}

/// One turn of the `recv_chunk` loop without the I/O: sort the outcome of a
/// Receive, keep the timeout streak and the command's `done` flag, and say
/// whether to ask again. Every server answer resets the streak, an empty
/// long poll included (that is how winrm-rs delivers `w:TimedOut`).
fn receive_step(
    polled: std::result::Result<ReceiveOutput, WinrmError>,
    stop_signalled: bool,
    timeouts: &mut TimeoutStreak,
    done: &mut bool,
) -> Result<Step> {
    let poll = match classify_receive(polled, stop_signalled) {
        Ok(poll) => poll,
        Err(e) => {
            // The command is gone: nothing more will come from it.
            if matches!(e, PsrpError::Stopped) {
                *done = true;
            }
            return Err(e);
        }
    };
    match poll {
        Poll::Retry => {
            timeouts.reset();
            Ok(Step::Again)
        }
        Poll::TimedOut(e) => {
            let reason = e.to_string();
            let streak = timeouts.record(e)?;
            warn!(
                %reason,
                streak,
                limit = MAX_CONSECUTIVE_TIMEOUTS,
                "PSRP recv_chunk: client-side timeout, sending the Receive again"
            );
            Ok(Step::Again)
        }
        Poll::Chunk(out) => {
            timeouts.reset();
            if out.done {
                *done = true;
            }
            if out.stdout.is_empty() && !*done {
                return Ok(Step::Again);
            }
            Ok(Step::Deliver(out.stdout))
        }
    }
}

/// Sort the outcome of one Receive.
///
/// `stop_signalled`: a stop signal was sent for the command (accepted, or
/// still in flight). The server
/// then deletes the command and answers the Receive with `InvalidSelectors`
/// instead of a final `PipelineState`, so that fault, and only then, is the
/// end of the stop: `Err(Stopped)`. It is the same fault as "the shell is
/// gone" (WinRM has one code for an unknown resource), so a shell reaped
/// right after a stop also reads as stopped; the next command then fails
/// with the real error.
fn classify_receive(
    polled: std::result::Result<ReceiveOutput, WinrmError>,
    stop_signalled: bool,
) -> Result<Poll> {
    match polled {
        Ok(out) => Ok(Poll::Chunk(out)),
        Err(e @ WinrmError::Timeout(_)) => Ok(Poll::TimedOut(e)),
        Err(WinrmError::Soap(SoapError::Fault {
            ref code,
            ref reason,
            ..
        })) if code.contains("TimedOut") => {
            // PSRP long-polling: the WinRM server returns a SOAP fault with
            // code `w:TimedOut` when there's nothing to read yet, and it MUST
            // be retried (briefing §5 P7). winrm-rs turns it into an empty
            // poll first; this is the fallback for one that gets through.
            // Only fatal SOAP faults (e.g. shell died, access denied) should
            // propagate.
            debug!(%code, %reason, "PSRP recv_chunk: w:TimedOut — retrying");
            Ok(Poll::Retry)
        }
        Err(WinrmError::Soap(SoapError::Fault { ref code, .. }))
            if stop_signalled && code.contains("InvalidSelectors") =>
        {
            debug!(%code, "PSRP recv_chunk: command gone after the stop signal");
            Err(PsrpError::Stopped)
        }
        Err(e) => {
            if let WinrmError::Soap(SoapError::Fault { code, reason, .. }) = &e {
                warn!(%code, %reason, "PSRP transport SOAP fault — shell likely dead");
            }
            Err(PsrpError::Winrm(e))
        }
    }
}

#[async_trait]
impl PsrpTransport for WinrmPsrpTransport<'_> {
    async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
        self.shell()?
            .send_input(&self.command_id, bytes, false)
            .await?;
        Ok(())
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
        let mut timeouts = TimeoutStreak::default();
        loop {
            // The wait the last empty polls earned (see `PollPacer`). Kept
            // in `self`: dropped half-way, it is finished by the next call.
            if let Some(resume_at) = self.resume_at {
                tokio::time::sleep_until(resume_at).await;
                self.resume_at = None;
            }
            // Timed from this call: a Receive parked by a dropped call and
            // answered since looks quick. At worst that is one step of the
            // pacer too many, undone by the next held poll.
            let started = Instant::now();
            let polled = {
                let shell = self
                    .shell
                    .as_ref()
                    .ok_or_else(|| PsrpError::protocol("transport closed"))?;
                let (shell, command_id) = (Arc::clone(shell), self.command_id.clone());
                // Cancel-safe: a dropped call leaves this Receive parked for
                // the next one (see `Parked`), and the stop signal in
                // flight, if any, too.
                let driven = receive_while_stopping(
                    &mut self.receive,
                    &mut self.stop,
                    move || async move { shell.receive_next(&command_id).await },
                    |answer| answer.map_err(PsrpError::Winrm),
                )
                .await;
                match driven {
                    Ok(polled) => polled,
                    // The stop signal left in flight failed, and that is
                    // the error of this read, as it would have been
                    // `signal_stop`'s had the answer come in time. Unless
                    // the server is only slow to stop the pipeline, no stop
                    // was signalled after all (refused, or never sent).
                    Err(e) => {
                        if !still_stopping(&e) {
                            self.stop_signalled
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                        }
                        return Err(e);
                    }
                }
            };
            let elapsed = started.elapsed();
            let stop_signalled = self
                .stop_signalled
                .load(std::sync::atomic::Ordering::SeqCst);
            let step = receive_step(polled, stop_signalled, &mut timeouts, &mut self.done)?;
            let progressed = matches!(&step, Step::Deliver(bytes) if !bytes.is_empty());
            self.resume_at = self
                .pacer
                .delay_after(elapsed, progressed)
                .and_then(|delay| tokio::time::Instant::now().checked_add(delay));
            if let Step::Deliver(bytes) = step {
                return Ok(bytes);
            }
        }
    }

    async fn execute_pipeline(
        &mut self,
        fragment_bytes: &[u8],
        pipeline_id: uuid::Uuid,
    ) -> Result<()> {
        self.finish_stopped_command().await;
        let shell = self.shell()?;
        let b64 = crate::clixml::encode::base64_encode(fragment_bytes);
        // pypsrp sends: command("", arguments=[b64_first_frag], command_id=pipeline_id)
        // The WS-Man Execute carries the first fragment as the sole argument
        // and uses the pipeline UUID as the CommandId.
        let cmd_id = shell
            .start_command_with_id("", &[&b64], &pipeline_id.hyphenated().to_string())
            .await?;
        debug!(cmd_id, "PSRP pipeline Execute started");
        self.command_started(cmd_id);
        Ok(())
    }

    fn pipeline_has_its_own_stream(&self) -> bool {
        true
    }

    async fn abandon_pipeline(&mut self) {
        self.finish_stopped_command().await;
    }

    /// Returns once the server has answered the signal, or after half a
    /// second (`STOP_SIGNAL_GRACE`) with the request left in flight:
    /// `recv_chunk` then drives it along with its Receives, and a failure
    /// that arrives while the pipeline is still read is the error of that
    /// read.
    async fn signal_stop(&self) -> Result<()> {
        let shell = self
            .shell
            .as_ref()
            .ok_or_else(|| PsrpError::protocol("transport closed"))?;
        let (shell, command_id) = (Arc::clone(shell), self.command_id.clone());
        let signal = Box::pin(async move { shell.signal_ctrl_c(&command_id).await });
        if let Some(answer) = signal_within(&self.stop, STOP_SIGNAL_GRACE, signal).await {
            answer?;
        }
        self.stop_signalled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn close_shell(&mut self) -> Result<()> {
        if let Some(shell) = self.take_shell()? {
            shell.close().await?;
        }
        Ok(())
    }

    async fn disconnect_shell(&mut self) -> Result<String> {
        let shell = self
            .take_shell()?
            .ok_or_else(|| PsrpError::protocol("transport closed"))?;
        let id = shell.disconnect().await?;
        Ok(id)
    }
}

impl Drop for WinrmPsrpTransport<'_> {
    fn drop(&mut self) {
        if self.shell.is_some() {
            warn!("WinrmPsrpTransport dropped without close — shell leaked server-side");
        }
    }
}

#[cfg(any(test, feature = "__internal"))]
#[doc(hidden)]
pub mod mock {
    use super::{PsrpError, PsrpTransport, Result, async_trait};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, PoisonError};
    use uuid::Uuid;

    /// In-memory transport used by the test suite.
    #[derive(Clone, Default, Debug)]
    pub struct MockTransport {
        pub inbox: Arc<Mutex<VecDeque<Vec<u8>>>>, // bytes to hand out of recv_chunk
        pub outbox: Arc<Mutex<Vec<Vec<u8>>>>,     // bytes captured from send_fragment
        pub stopped: Arc<Mutex<bool>>,
        pub closed: Arc<Mutex<bool>>,
        pub fail_send: Arc<Mutex<bool>>,
        pub fail_recv: Arc<Mutex<Option<PsrpError>>>,
        /// Pipeline ids passed to `send_pipeline_fragment`, in call order.
        pub pipeline_sends: Arc<Mutex<Vec<Uuid>>>,
        /// Pipeline ids passed to `execute_pipeline`, in call order.
        pub pipeline_starts: Arc<Mutex<Vec<Uuid>>>,
        /// How many times `abandon_pipeline` was called.
        pub abandoned: Arc<Mutex<u32>>,
        /// What `pipeline_has_its_own_stream` answers (false by default,
        /// like a transport with one stream).
        pub own_stream_per_pipeline: Arc<Mutex<bool>>,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn push_incoming(&self, bytes: Vec<u8>) {
            self.inbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(bytes);
        }

        pub fn sent(&self) -> Vec<Vec<u8>> {
            self.outbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        pub fn pipeline_sends(&self) -> Vec<Uuid> {
            self.pipeline_sends
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        pub fn pipeline_starts(&self) -> Vec<Uuid> {
            self.pipeline_starts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl PsrpTransport for MockTransport {
        async fn send_fragment(&self, bytes: &[u8]) -> Result<()> {
            if *self
                .fail_send
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                return Err(PsrpError::protocol("mock send failure"));
            }
            self.outbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(bytes.to_vec());
            Ok(())
        }

        async fn send_pipeline_fragment(&mut self, bytes: &[u8], pipeline_id: Uuid) -> Result<()> {
            self.send_fragment(bytes).await?;
            self.pipeline_sends
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(pipeline_id);
            Ok(())
        }

        async fn execute_pipeline(&mut self, bytes: &[u8], pipeline_id: Uuid) -> Result<()> {
            self.send_fragment(bytes).await?;
            self.pipeline_starts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(pipeline_id);
            Ok(())
        }

        async fn recv_chunk(&mut self) -> Result<Vec<u8>> {
            if let Some(e) = self
                .fail_recv
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return Err(e);
            }
            let mut inbox = self.inbox.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(bytes) = inbox.pop_front() {
                Ok(bytes)
            } else {
                Err(PsrpError::protocol("mock inbox empty"))
            }
        }

        fn pipeline_has_its_own_stream(&self) -> bool {
            *self
                .own_stream_per_pipeline
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        }

        async fn signal_stop(&self) -> Result<()> {
            *self.stopped.lock().unwrap_or_else(PoisonError::into_inner) = true;
            Ok(())
        }

        async fn abandon_pipeline(&mut self) {
            let mut abandoned = self
                .abandoned
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *abandoned = abandoned.saturating_add(1);
        }

        async fn close_shell(&mut self) -> Result<()> {
            *self.closed.lock().unwrap_or_else(PoisonError::into_inner) = true;
            Ok(())
        }

        async fn disconnect_shell(&mut self) -> Result<String> {
            *self.closed.lock().unwrap_or_else(PoisonError::into_inner) = true;
            Ok("MOCK-SHELL-ID".into())
        }
    }

    #[tokio::test]
    async fn mock_roundtrip() {
        let mut t = MockTransport::new();
        t.send_fragment(b"hello").await.unwrap();
        assert_eq!(t.sent(), vec![b"hello".to_vec()]);

        t.push_incoming(b"world".to_vec());
        let got = t.recv_chunk().await.unwrap();
        assert_eq!(got, b"world");

        t.signal_stop().await.unwrap();
        t.close_shell().await.unwrap();
        assert!(*t.stopped.lock().unwrap());
        assert!(*t.closed.lock().unwrap());
    }

    #[tokio::test]
    async fn mock_recv_failure() {
        let mut t = MockTransport::new();
        *t.fail_recv.lock().unwrap() = Some(PsrpError::protocol("boom"));
        assert!(t.recv_chunk().await.is_err());
    }

    #[tokio::test]
    async fn mock_send_failure() {
        let t = MockTransport::new();
        *t.fail_send.lock().unwrap() = true;
        assert!(t.send_fragment(b"x").await.is_err());
    }
}

#[cfg(test)]
mod parked_tests {
    use super::{Parked, receive_while_stopping, signal_within};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;

    /// Sets a flag when it is dropped, to tell a parked future that was kept
    /// from one that was dropped.
    struct DropFlag(Arc<AtomicUsize>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The point of `Parked` (#27): a call dropped while its Receive is in
    /// flight, as `select!` does when a pipeline is cancelled, must not drop
    /// the Receive. The next call resumes it, and the response is not lost.
    #[tokio::test]
    async fn a_dropped_call_leaves_the_future_parked_and_the_next_resumes_it() {
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let mut parked: Parked<'_, &'static str> = Parked::new();

        let start = || {
            started.fetch_add(1, Ordering::SeqCst);
            let (gate, flag) = (Arc::clone(&gate), DropFlag(Arc::clone(&dropped)));
            async move {
                let _flag = flag;
                gate.notified().await;
                "response"
            }
        };

        // The caller gives up while the Receive is still waiting.
        tokio::select! {
            _ = parked.drive(start) => panic!("nothing was ready"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "the Receive was dropped");

        // The server answers meanwhile; the next call gets that answer and
        // does not start a second Receive.
        gate.notify_one();
        assert_eq!(parked.drive(start).await, "response");
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "a second Receive was sent"
        );
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "a finished future is released"
        );
    }

    /// Once a future has completed, the next call starts a new one.
    #[tokio::test]
    async fn a_completed_future_is_not_replayed() {
        let started = Arc::new(AtomicUsize::new(0));
        let mut parked: Parked<'_, usize> = Parked::new();
        for expected in 1..=3 {
            let n = parked
                .drive(|| {
                    let n = started.fetch_add(1, Ordering::SeqCst) + 1;
                    async move { n }
                })
                .await;
            assert_eq!(n, expected);
        }
    }

    /// A new command makes the parked Receive of the old one meaningless:
    /// `discard` drops it.
    #[tokio::test]
    async fn discard_drops_the_parked_future() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut parked: Parked<'_, ()> = Parked::new();
        tokio::select! {
            () = parked.drive(|| {
                let flag = DropFlag(Arc::clone(&dropped));
                async move {
                    let _flag = flag;
                    std::future::pending::<()>().await;
                }
            }) => panic!("never ready"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        parked.discard();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    /// A stop signal the server answers in time is reported by the call
    /// itself, and nothing stays in flight.
    #[tokio::test(start_paused = true)]
    async fn a_signal_answered_within_the_grace_is_returned() {
        let mut stop: Parked<'_, &'static str> = Parked::new();
        let answer = signal_within(
            &stop,
            Duration::from_millis(500),
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(499)).await;
                "accepted"
            }),
        )
        .await;
        assert_eq!(answer, Some("accepted"));
        assert!(stop.slot().is_none());
    }

    /// Regression, measured against Windows Server 2025: the server answers
    /// a stop signal once the pipeline has stopped, and a pipeline with
    /// output to deliver stops only when a Receive takes it. `signal_stop`
    /// waited for the answer without reading: 20 s later the server gave up
    /// (`w:TimedOut`), the cancellation failed with that fault and the
    /// pipeline kept its runspace. After the grace the signal is left in
    /// flight, not dropped, and its answer is still to come.
    #[tokio::test(start_paused = true)]
    async fn a_signal_not_answered_within_the_grace_stays_in_flight() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let mut stop: Parked<'_, &'static str> = Parked::new();
        let (held, flag) = (Arc::clone(&gate), DropFlag(Arc::clone(&dropped)));
        let started = tokio::time::Instant::now();
        let answer = signal_within(
            &stop,
            Duration::from_millis(500),
            Box::pin(async move {
                let _flag = flag;
                held.notified().await;
                "accepted"
            }),
        )
        .await;
        assert_eq!(answer, None);
        assert_eq!(started.elapsed(), Duration::from_millis(500));
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "the signal was dropped");

        // The pipeline stops (a Receive took its output): the same request
        // is answered.
        gate.notify_one();
        assert_eq!(stop.finish().await, "accepted");
        assert!(stop.slot().is_none());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    /// With no signal in flight, `finish` never returns: it must not end
    /// the `select!` it is a branch of.
    #[tokio::test(start_paused = true)]
    async fn finish_with_nothing_parked_never_returns() {
        let mut stop: Parked<'_, ()> = Parked::new();
        let waited = tokio::time::timeout(Duration::from_secs(3600), stop.finish()).await;
        assert!(waited.is_err());
    }

    /// The Receive is driven with the signal in flight: the signal's answer
    /// arrives first (the pipeline stopped), then the Receive's, and the
    /// call returns the Receive's.
    #[tokio::test]
    async fn the_signal_in_flight_is_finished_by_the_receive() {
        let answered = Arc::new(AtomicUsize::new(0));
        let (signal_gate, receive_gate) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        let mut receive: Parked<'_, &'static str> = Parked::new();
        let mut stop: Parked<'_, u32> = Parked::new();
        let held = Arc::clone(&signal_gate);
        stop.park(Box::pin(async move {
            held.notified().await;
            7
        }));

        signal_gate.notify_one();
        let (seen, release) = (Arc::clone(&answered), Arc::clone(&receive_gate));
        let held = Arc::clone(&receive_gate);
        let polled = receive_while_stopping(
            &mut receive,
            &mut stop,
            move || async move {
                held.notified().await;
                "output"
            },
            move |answer| {
                assert_eq!(answer, 7);
                seen.fetch_add(1, Ordering::SeqCst);
                // The server sends the rest only now.
                release.notify_one();
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(polled, "output");
        assert_eq!(answered.load(Ordering::SeqCst), 1);
        assert!(stop.slot().is_none(), "an answered signal is forgotten");
    }

    /// A Receive that is ready is returned at once: the signal stays in
    /// flight for the next call.
    #[tokio::test]
    async fn a_ready_receive_does_not_wait_for_the_signal() {
        let mut receive: Parked<'_, &'static str> = Parked::new();
        let mut stop: Parked<'_, ()> = Parked::new();
        stop.park(Box::pin(std::future::pending()));
        let polled = receive_while_stopping(
            &mut receive,
            &mut stop,
            || async { "output" },
            |()| panic!("the signal was not answered"),
        )
        .await
        .unwrap();
        assert_eq!(polled, "output");
        assert!(stop.slot().is_some());
    }

    /// A signal the server refuses ends the read with that error, and the
    /// Receive stays parked: the next call resumes it.
    #[tokio::test]
    async fn a_refused_signal_ends_the_read_and_keeps_the_receive() {
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let mut receive: Parked<'_, &'static str> = Parked::new();
        let mut stop: Parked<'_, &'static str> = Parked::new();
        stop.park(Box::pin(async { "refused" }));

        let start = || {
            started.fetch_add(1, Ordering::SeqCst);
            let gate = Arc::clone(&gate);
            async move {
                gate.notified().await;
                "output"
            }
        };
        let err = receive_while_stopping(&mut receive, &mut stop, start, |answer| {
            Err(crate::error::PsrpError::protocol(answer))
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
        assert!(stop.slot().is_none());

        gate.notify_one();
        let polled = receive_while_stopping(&mut receive, &mut stop, start, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(polled, "output");
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "a second Receive was sent"
        );
    }
}

#[cfg(test)]
mod classify_tests {
    use super::{
        MAX_CONSECUTIVE_TIMEOUTS, Poll, PollPacer, Step, TimeoutStreak, classify_receive,
        receive_step, still_stopping,
    };
    use std::time::Duration;

    /// Regression: `recv_chunk` sent the next Receive as soon as an empty
    /// one came back, so a server answering at once with nothing was polled
    /// in a tight loop for ever. The third quick empty poll in a row is now
    /// followed by 50 ms, doubling up to one second.
    #[test]
    fn quick_empty_polls_are_paced() {
        let ms = Duration::from_millis;
        let mut pacer = PollPacer::default();
        let delays: Vec<_> = (0..10).map(|_| pacer.delay_after(ms(1), false)).collect();
        assert_eq!(
            delays,
            [
                None,
                None,
                Some(ms(50)),
                Some(ms(100)),
                Some(ms(200)),
                Some(ms(400)),
                Some(ms(800)),
                Some(ms(1000)),
                Some(ms(1000)),
                Some(ms(1000)),
            ]
        );
        // It stays at one second however long the server keeps at it.
        for _ in 0..100 {
            assert_eq!(pacer.delay_after(ms(0), false), Some(ms(1000)));
        }
        pacer.quick_empty = u32::MAX;
        assert_eq!(pacer.delay_after(ms(0), false), Some(ms(1000)));
        assert_eq!(pacer.quick_empty, u32::MAX);
    }

    /// Data, or a poll the server held (a real long poll), starts the count
    /// over: neither is ever delayed.
    #[test]
    fn progress_or_a_slow_poll_resets_the_pace() {
        let ms = Duration::from_millis;
        // From a fresh count, six quick empty polls: the sixth earns 400 ms.
        let spin = |pacer: &mut PollPacer| {
            pacer.quick_empty = 0;
            for _ in 0..5 {
                pacer.delay_after(ms(1), false);
            }
            assert_eq!(pacer.delay_after(ms(1), false), Some(ms(400)));
        };

        let mut pacer = PollPacer::default();
        spin(&mut pacer);
        assert_eq!(pacer.delay_after(ms(1), true), None, "bytes arrived");
        assert_eq!(
            pacer.delay_after(ms(1), false),
            None,
            "counted from one again"
        );
        assert_eq!(pacer.delay_after(ms(1), false), None);
        assert_eq!(pacer.delay_after(ms(1), false), Some(ms(50)));

        spin(&mut pacer);
        assert_eq!(
            pacer.delay_after(ms(250), false),
            None,
            "held by the server"
        );
        assert_eq!(pacer.quick_empty, 0);
        // Just under the threshold is still a quick one.
        assert_eq!(pacer.delay_after(ms(249), false), None);
        assert_eq!(pacer.quick_empty, 1);
        // A long poll that times out on the server is never delayed.
        for _ in 0..10 {
            assert_eq!(pacer.delay_after(Duration::from_secs(60), false), None);
        }
    }
    use crate::error::PsrpError;
    use std::io::{Read, Write};
    use winrm_rs::{
        AuthMethod, EncryptionMode, ReceiveOutput, SoapError, WinrmClient, WinrmConfig,
        WinrmCredentials, WinrmError,
    };

    /// The SOAP fault of code `code`, as winrm-rs returns it.
    ///
    /// Only winrm-rs can build a `SoapError::Fault` (the variant is
    /// `#[non_exhaustive]` from 3.0): this one is read by a real client from
    /// a server on the loopback, which answers its one request with the
    /// fault Windows writes (the shape of the `w:TimedOut` one captured from
    /// Server 2012 R2). What the read loop tells apart by the code is thus
    /// checked on the code winrm-rs reads, not on one the test made up.
    fn fault(code: &str) -> WinrmError {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = format!(
            r#"<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action><a:MessageID>uuid:7DC2CBFC-F0A0-4678-A5B5-FF211DCF5F2D</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>{code}</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="en-US">r</s:Text></s:Reason><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858793" Machine="127.0.0.1"><f:Message>r</f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>"#
        );
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // A client that connects and says nothing fails the test.
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 500 Internal Server Error\r\n\
                 Content-Type: application/soap+xml;charset=UTF-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        // On a thread of its own: a test that already runs on a Tokio
        // runtime cannot start another one.
        let request = std::thread::spawn(move || {
            let client = WinrmClient::new(
                WinrmConfig {
                    port: Some(port),
                    auth_method: AuthMethod::Basic,
                    encryption: EncryptionMode::Never,
                    max_retries: 0,
                    ..WinrmConfig::http()
                },
                WinrmCredentials::new("user".to_string(), "password".to_string(), ""),
            )
            .unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(client.create_shell("127.0.0.1"))
                .unwrap_err()
        });
        let err = request.join().unwrap();
        // Checked before the server is joined: a client that failed without
        // connecting leaves it waiting in `accept`, and the test must fail,
        // not hang. A fault of this code proves the server has answered.
        assert!(
            matches!(&err, WinrmError::Soap(SoapError::Fault { code: read, .. }) if read == code),
            "winrm-rs read the fault as {err:?}"
        );
        server.join().unwrap();
        err
    }

    /// Read one HTTP request to the end of its body.
    fn read_request(stream: &mut std::net::TcpStream) {
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "the client closed before the end of its request");
            request.extend_from_slice(&buf[..n]);
            let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let length = String::from_utf8_lossy(&request[..head])
                .to_ascii_lowercase()
                .lines()
                .find_map(|line| line.strip_prefix("content-length:")?.trim().parse().ok())
                .unwrap_or(0usize);
            if request.len() >= head + 4 + length {
                return;
            }
        }
    }

    fn output() -> ReceiveOutput {
        ReceiveOutput {
            stdout: b"x".to_vec(),
            stderr: Vec::new(),
            exit_code: None,
            done: false,
        }
    }

    #[test]
    fn data_and_long_poll_timeouts() {
        assert!(matches!(
            classify_receive(Ok(output()), false),
            Ok(Poll::Chunk(c)) if c.stdout == b"x"
        ));
        assert!(matches!(
            classify_receive(Err(fault("w:TimedOut")), false),
            Ok(Poll::Retry)
        ));
        assert!(matches!(
            classify_receive(Err(fault("w:TimedOut")), true),
            Ok(Poll::Retry)
        ));
    }

    /// A client-side timeout is kept, so that `recv_chunk` can return it
    /// once the streak is over.
    #[test]
    fn client_timeout_is_classified_apart_from_the_long_poll() {
        for stop_signalled in [false, true] {
            assert!(matches!(
                classify_receive(Err(WinrmError::Timeout(70)), stop_signalled),
                Ok(Poll::TimedOut(WinrmError::Timeout(70)))
            ));
        }
    }

    /// The third timeout in a row is returned, as itself; the first two
    /// are absorbed.
    #[test]
    fn timeout_streak_gives_up_at_the_limit() {
        assert_eq!(MAX_CONSECUTIVE_TIMEOUTS, 3);
        let mut streak = TimeoutStreak::default();
        assert!(streak.record(WinrmError::Timeout(1)).is_ok());
        assert!(streak.record(WinrmError::Timeout(2)).is_ok());
        assert!(matches!(
            streak.record(WinrmError::Timeout(3)),
            Err(PsrpError::Winrm(WinrmError::Timeout(3)))
        ));
    }

    /// Any answer in between starts the count over: a slow server that
    /// keeps answering is never given up on.
    #[test]
    fn timeout_streak_resets_on_an_answer() {
        let mut streak = TimeoutStreak::default();
        for _ in 0..10 {
            assert!(matches!(streak.record(WinrmError::Timeout(1)), Ok(1)));
            assert!(matches!(streak.record(WinrmError::Timeout(1)), Ok(2)));
            streak.reset();
        }
        assert!(matches!(streak.record(WinrmError::Timeout(1)), Ok(1)));
    }

    fn empty(done: bool) -> ReceiveOutput {
        ReceiveOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            done,
        }
    }

    type Answer = std::result::Result<ReceiveOutput, WinrmError>;

    /// Feed `answers` to `receive_step` one after the other, as
    /// `recv_chunk` does with its Receives, until it delivers or fails.
    /// Returns the outcome and how many answers it took.
    fn drive(answers: Vec<Answer>) -> (crate::error::Result<Vec<u8>>, usize) {
        let mut timeouts = TimeoutStreak::default();
        let mut done = false;
        for (taken, polled) in (1..).zip(answers) {
            match receive_step(polled, false, &mut timeouts, &mut done) {
                Ok(Step::Again) => {}
                Ok(Step::Deliver(bytes)) => return (Ok(bytes), taken),
                Err(e) => return (Err(e), taken),
            }
        }
        panic!("receive_step asked for more Receives than the script holds");
    }

    /// The third client-side timeout in a row ends the call with that
    /// error; nothing after it is read.
    #[test]
    fn third_timeout_in_a_row_ends_recv_chunk() {
        let (got, taken) = drive(vec![
            Err(WinrmError::Timeout(1)),
            Err(WinrmError::Timeout(2)),
            Err(WinrmError::Timeout(3)),
            Ok(output()),
        ]);
        assert!(matches!(got, Err(PsrpError::Winrm(WinrmError::Timeout(3)))));
        assert_eq!(taken, 3);
    }

    /// An empty long poll is how winrm-rs delivers the server's
    /// `w:TimedOut`: it is an answer, so it starts the count over.
    #[test]
    fn empty_poll_between_timeouts_resets_the_streak() {
        let (got, taken) = drive(vec![
            Err(WinrmError::Timeout(1)),
            Err(WinrmError::Timeout(1)),
            Ok(empty(false)),
            Err(WinrmError::Timeout(1)),
            Err(WinrmError::Timeout(1)),
            Ok(output()),
        ]);
        assert_eq!(got.unwrap(), b"x");
        assert_eq!(taken, 6);
    }

    /// The same with a `w:TimedOut` fault that winrm-rs did not fold.
    #[test]
    fn long_poll_fault_between_timeouts_resets_the_streak() {
        let (got, taken) = drive(vec![
            Err(WinrmError::Timeout(1)),
            Err(WinrmError::Timeout(1)),
            Err(fault("w:TimedOut")),
            Err(WinrmError::Timeout(1)),
            Err(WinrmError::Timeout(1)),
            Ok(output()),
        ]);
        assert_eq!(got.unwrap(), b"x");
        assert_eq!(taken, 6);
    }

    /// Empty polls are retried while the command runs; once it is done, the
    /// call returns, with no bytes if the last answer carried none.
    #[test]
    fn empty_polls_wait_until_data_or_done() {
        let (got, taken) = drive(vec![Ok(empty(false)), Ok(empty(false)), Ok(output())]);
        assert_eq!(got.unwrap(), b"x");
        assert_eq!(taken, 3);

        let mut timeouts = TimeoutStreak::default();
        let mut done = false;
        assert_eq!(
            receive_step(Ok(empty(true)), false, &mut timeouts, &mut done).unwrap(),
            Step::Deliver(Vec::new())
        );
        assert!(done);
        // Done stays done: a later empty answer is delivered too.
        assert_eq!(
            receive_step(Ok(empty(false)), false, &mut timeouts, &mut done).unwrap(),
            Step::Deliver(Vec::new())
        );
    }

    /// The fault that follows an accepted stop signal is the stop (#27); the
    /// same fault with no signal of ours is a dead shell, and any other
    /// fault stays fatal either way.
    #[test]
    fn invalid_selectors_means_stopped_only_after_our_stop_signal() {
        assert!(matches!(
            classify_receive(Err(fault("w:InvalidSelectors")), true),
            Err(PsrpError::Stopped)
        ));
        assert!(matches!(
            classify_receive(Err(fault("w:InvalidSelectors")), false),
            Err(PsrpError::Winrm(WinrmError::Soap(SoapError::Fault { .. })))
        ));
        assert!(matches!(
            classify_receive(Err(fault("w:AccessDenied")), true),
            Err(PsrpError::Winrm(WinrmError::Soap(SoapError::Fault { .. })))
        ));
    }

    /// The command gone after a stop is a command that has ended: the
    /// start of the next one must not wait for it (`finish_stopped_command`).
    /// Any other error says nothing about the command.
    #[test]
    fn a_command_gone_after_the_stop_has_ended() {
        let mut timeouts = TimeoutStreak::default();
        let mut done = false;
        let step = receive_step(
            Err(fault("w:InvalidSelectors")),
            true,
            &mut timeouts,
            &mut done,
        );
        assert!(matches!(step, Err(PsrpError::Stopped)));
        assert!(done);

        let mut done = false;
        let step = receive_step(Err(fault("w:AccessDenied")), true, &mut timeouts, &mut done);
        assert!(matches!(step, Err(PsrpError::Winrm(_))));
        assert!(!done);
    }

    /// The late answer to a stop signal that `recv_chunk` returns as an
    /// error: the server's `w:TimedOut` says the pipeline has not stopped
    /// yet, and the stop stays asked for. The client's own timeout (the
    /// request may never have left) and a refusal say no stop was
    /// signalled: taken for "still stopping", they left a cancellation
    /// waiting for a `Stopped` that could not come.
    #[test]
    fn only_the_servers_timeout_means_the_stop_is_still_under_way() {
        let late = |e: WinrmError| PsrpError::Winrm(e);
        assert!(still_stopping(&late(fault("w:TimedOut"))));
        assert!(!still_stopping(&late(WinrmError::Timeout(30))));
        assert!(!still_stopping(&late(fault("w:InvalidSelectors"))));
        assert!(!still_stopping(&late(fault("w:AccessDenied"))));
        assert!(!still_stopping(&PsrpError::Stopped));
    }
}
