use core::slice;
use std::{
    cell::OnceCell, collections::HashSet, ffi::{c_void, OsStr, OsString}, fmt::{self, Write}, iter, mem::size_of, os::windows::prelude::{OsStrExt, OsStringExt}, panic::{self, AssertUnwindSafe}, path::{Path, PathBuf}, sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    }, thread::{self, JoinHandle}, time::{Duration, SystemTime}
};

use windows::{
    core::{GUID, HRESULT, PWSTR},
    Win32::{
        Foundation::{ERROR_CTX_CLOSE_PENDING, FILETIME},
        System::Diagnostics::Etw::{
            CloseTrace, OpenTraceW, ProcessTrace, EVENT_HEADER, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
            PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        },
    },
};

use crate::{
    error::TraceError, provider::Provider, schema::cache::EventInfo, trace_session::TraceSession, values::event::Event
};

const INVALID_PROCESSTRACE_HANDLE: PROCESSTRACE_HANDLE = PROCESSTRACE_HANDLE {
    Value: usize::MAX as u64,
};
const EVENT_TRACE_GUID: GUID = GUID::from_u128(0x68FDD900_4A3E_11D1_84F4_0000F80464E3);

#[derive(Default)]
pub struct EventTraceLogfile {
    data: Box<EVENT_TRACE_LOGFILEW>,
    log_file_name: Vec<u16>,
    logger_name: Vec<u16>,
}

unsafe impl Send for EventTraceLogfile {}

impl fmt::Debug for EventTraceLogfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let logger_name_len = self.logger_name.iter().take_while(|x| **x != 0).count();
        let log_file_name_len = self.log_file_name.iter().take_while(|x| **x != 0).count();
        f.debug_struct("EventTraceLogfile")
            .field(
                "data.LogFileName",
                &OsString::from_wide(&self.log_file_name[..log_file_name_len]),
            )
            .field(
                "data.LoggerName",
                &OsString::from_wide(&self.logger_name[..logger_name_len]),
            )
            .field("data.Anonymous1.LogFileMode", &unsafe {
                self.data.Anonymous1.LogFileMode
            })
            .finish_non_exhaustive()
    }
}

impl EventTraceLogfile {
    pub fn new() -> Self {
        EventTraceLogfile {
            ..Default::default()
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_LOGFILEW {
        self.data.as_mut() as *mut _
    }

    pub fn set_log_file_name<S: AsRef<OsStr>>(&mut self, log_file_name: S) {
        let mut log_file_name = log_file_name
            .as_ref()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        self.data.LogFileName = PWSTR::from_raw(log_file_name.as_mut_ptr());
        self.log_file_name = log_file_name;
    }

    pub fn set_logger_name<S: AsRef<OsStr>>(&mut self, logger_name: S) {
        let mut logger_name = logger_name
            .as_ref()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        self.data.LoggerName = PWSTR::from_raw(logger_name.as_mut_ptr());
        self.logger_name = logger_name;
    }
}

pub type HandlerFn = dyn FnMut(& EVENT_RECORD) + Send;
pub type ProvidersEvents = Vec<(Provider, Vec<u16>)>;

pub struct HandlerData {
    stop_trace: AtomicBool,
    handler: Mutex<Box<HandlerFn>>,
}

#[derive(Default)]
pub struct TraceBuilder {
    handler: OnceCell<Box<HandlerFn>>,
    providers: HashSet<GUID>,
    file: Option<PathBuf>,
    session: Option<TraceSession>,
}

impl fmt::Debug for TraceBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceBuilder")
            .field("providers", &self.providers)
            .field("file", &self.file)
            .field("session", &self.session)
            .finish()
    }
}

impl TraceBuilder {
    pub fn new() -> TraceBuilder {
        TraceBuilder {
            ..Default::default()
        }
    }

    pub fn set_handler(
        self,
        mut handler: impl FnMut(Event, Arc<EventInfo>, &EVENT_RECORD) + Send + 'static,
    ) -> Result<Self, TraceError> {

        let handler: Box<dyn FnMut(&EVENT_RECORD) + Send + 'static> = Box::new(move |event_record: &EVENT_RECORD| {
            if event_record.EventHeader.ProviderId == EVENT_TRACE_GUID {
                return;
            }
            log::trace!("Event record handler called: activity: {:?} GUID {:?} descriptor: {:?} version: {} userdata_len: {}", event_record.EventHeader.ActivityId, event_record.EventHeader.ProviderId, event_record.EventHeader.EventDescriptor, event_record.EventHeader.EventDescriptor.Version, event_record.UserDataLength);
            let event_data = unsafe {
                slice::from_raw_parts(
                    event_record.UserData as *const u8,
                    event_record.UserDataLength as usize,
                )
            };
            let event_data = event_data.iter().fold(String::new(), |mut output, b| {
                let _ = write!(output, "{b:02x}");
                output
            });
            log::trace!("Event record userdata: {}", event_data);
            match Event::parse(event_record) {
                Ok((schema, event)) => handler(event, schema, event_record),
                Err(err) => {
                    log::warn!(
                        "failed to parse provider {:?} event {} record: {}",
                        event_record.EventHeader.ProviderId,
                        event_record.EventHeader.EventDescriptor.Id,
                        err
                    );
                    if log::log_enabled!(log::Level::Info) {
                        let header = unsafe {
                            slice::from_raw_parts(
                                &event_record.EventHeader as *const _ as *const u8,
                                size_of::<EVENT_HEADER>(),
                            )
                        };
                        let header = header.iter().fold(String::new(), |mut output, b| {
                            let _ = write!(output, "{b:02x}");
                            output
                        });
                        let userdata = unsafe {
                            slice::from_raw_parts(
                                event_record.UserData as *const u8,
                                event_record.UserDataLength as usize,
                            )
                        };
                        let userdata = userdata.iter().fold(String::new(), |mut output, b| {
                            let _ = write!(output, "{b:02x}");
                            output
                        });
                        log::info!(
                            "Failed to parse provider {:?} event {} header: {} userdata: {}",
                            event_record.EventHeader.ProviderId,
                            event_record.EventHeader.EventDescriptor.Id,
                            header,
                            userdata
                        );
                    }
                }
            };
        });

        self.handler.set(handler).map_err(|_| TraceError::Configuration(
            "Tried to set a handler when a handler was already present"
                .to_string(),
        ))?;

        Ok(self)
    }

    pub fn set_raw_handler(
        self,
        handler: impl FnMut(&EVENT_RECORD) + Send + 'static,
    ) -> Result<Self, TraceError> {
        let handler = Box::new(handler);
        self.handler.set(handler).map_err(|_| TraceError::Configuration(
            "Tried to set a compound handler when a compound handler was already present"
                .to_string(),
        ))?;
        Ok(self)
    }

    pub fn file<P: AsRef<Path>>(mut self, file: P) -> Result<Self, TraceError> {
        if self.session.is_some() {
            Err(TraceError::Configuration(
                "Tried to set a filename when a session was already present".to_string(),
            ))
        } else {
            self.file = Some(file.as_ref().to_path_buf());
            Ok(self)
        }
    }

    pub fn session(mut self, session: TraceSession) -> Result<Self, TraceError> {
        if self.file.is_some() {
            Err(TraceError::Configuration(
                "Tried to set a session when a filename was already present".to_string(),
            ))
        } else {
            self.session = Some(session);
            Ok(self)
        }
    }

    pub fn open(mut self) -> Result<Trace, TraceError> {
        log::debug!("TraceBuilder::open() called: {:?}", self);
        assert!(self.file.is_none() || self.session.is_none());
        let mut event_trace_logfile = EventTraceLogfile::new();

        let controller = if let Some(session) = self.session.take() {
            event_trace_logfile.set_logger_name(session.name());

            unsafe {
                event_trace_logfile.data.Anonymous1.ProcessTraceMode |=
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            }
            event_trace_logfile.data.BufferCallback = Some(buffer_handler);

            if let Some(_) = self.handler.get() {
                Some(TraceController::RealtimeTraceSession(session))
            }
            else {
                return Err(TraceError::Configuration("No handler set".to_string()));
            }
        } else if let Some(file) = &self.file {
            unsafe {
                event_trace_logfile.data.Anonymous1.ProcessTraceMode |=
                    PROCESS_TRACE_MODE_EVENT_RECORD;
            }
            event_trace_logfile.set_log_file_name(file);
            None
        } else {
            return Err(TraceError::Configuration(
                "No session or file set".to_string(),
            ));
        };

        // Set up handlers
        let handler_data = if let Some(handler) = self.handler.take() {
            #[allow(clippy::arc_with_non_send_sync)]
            let handler_data = Arc::new(HandlerData {
                handler: Mutex::new(handler),
                stop_trace: AtomicBool::new(false),
            });

            event_trace_logfile.data.Context =
                Arc::into_raw(Arc::clone(&handler_data)) as *mut c_void;
            event_trace_logfile.data.Anonymous2.EventRecordCallback =
                Some(event_record_handler);
            handler_data
        } else {
            return Err(TraceError::Configuration("No handlers set".to_string()));
        };

        unsafe {
            log::trace!("OpenTraceW({:?})", &event_trace_logfile);
            let handle = OpenTraceW(event_trace_logfile.as_mut_ptr());
            if handle == INVALID_PROCESSTRACE_HANDLE {
                let err: TraceError = windows::core::Error::from_win32().into();
                log::warn!("OpenTraceW returned error: {:?}", err);
                return Err(err);
            }

            log::trace!("OpenTraceW returned OK");

            Ok(Trace {
                handle,
                _event_trace_logfile: event_trace_logfile,
                thread: None,
                _handler_data: handler_data,
                _controller: controller,
            })
        }
    }
}

pub enum TraceController {
    RealtimeTraceSession(TraceSession),
}

pub struct Trace {
    _controller: Option<TraceController>,
    handle: PROCESSTRACE_HANDLE,
    _event_trace_logfile: EventTraceLogfile,
    thread: Option<JoinHandle<Result<(), TraceError>>>,
    _handler_data: Arc<HandlerData>,
}

impl Drop for Trace {
    fn drop(&mut self) {
        log::trace!("Trace::drop called");
        if let Err(err) = self.close() {
            log::error!("Failed to close trace: {:?}", err);
        }
    }
}

const WINDOWS_TO_UNIX_EPOCH_OFFSET: Duration = Duration::from_secs(11644473600);

fn system_time_to_filetime(time: SystemTime) -> FILETIME {
    let time = time
        .duration_since(SystemTime::UNIX_EPOCH - WINDOWS_TO_UNIX_EPOCH_OFFSET)
        .unwrap();
    let ticks = time.as_nanos() / 100;
    let low = (ticks & u128::from(u32::MAX)) as u32;
    let high = u32::try_from(ticks >> 32).unwrap();
    FILETIME {
        dwLowDateTime: low,
        dwHighDateTime: high,
    }
}

fn process_trace<FN: FnOnce() + Send>(
    handle: PROCESSTRACE_HANDLE,
    start: Option<SystemTime>,
    end: Option<SystemTime>,
    notify: Option<FN>,
) -> Result<(), TraceError> {
    log::trace!("Trace::process_trace({:?}, {:?}, {:?})", handle, start, end);
    let start: Option<FILETIME> = start.map(system_time_to_filetime);
    let end = end.map(system_time_to_filetime);
    let handlearray = &[handle];
    let starttime = start.as_ref().map(|x| x as *const _);
    let endtime = end.as_ref().map(|x| x as *const _);
    unsafe {
        log::trace!(
            "Calling ProcessTrace({:?}, {:?}, {:?})",
            handlearray,
            starttime,
            endtime
        );
        match ProcessTrace(handlearray, starttime, endtime).ok() {
            Ok(()) => {
                log::trace!("process_trace returned without error");
                if let Some(notify) = notify {
                    notify();
                }
                Ok(())
            }
            Err(err) => {
                log::warn!("process_trace returned with error: {:?}", err);
                if let Some(notify) = notify {
                    notify();
                }
                Err(err.into())
            }
        }
    }
}

impl Trace {
    /// Start thread to process the trace
    ///
    /// # Arguments
    /// - 'start' - The start time of the trace
    /// - 'end' - The end time of the trace
    /// - 'notify' - A function to call when the trace is finished
    pub fn start_processing<FN: FnOnce() + Send + 'static>(
        &mut self,
        start: Option<SystemTime>,
        end: Option<SystemTime>,
        notify: Option<FN>,
    ) {
        let handle = self.handle;
        self.thread = Some(thread::spawn(move || {
            process_trace(handle, start, end, notify)
        }));
    }

    pub fn close(&self) -> Result<(), TraceError> {
        //TODO: signal stop
        unsafe {
            match CloseTrace(self.handle).ok() {
                Ok(()) => Ok(()),
                Err(err) if err.code() == HRESULT::from(ERROR_CTX_CLOSE_PENDING) => Ok(()),
                Err(err) => Err(TraceError::from(err)),
            }
        }
    }

    pub fn wait(&mut self) -> Result<(), TraceError> {
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| TraceError::ThreadJoin)??;
        }

        Ok(())
    }

    pub fn is_finished(&self) -> bool {
        if let Some(thread) = &self.thread {
            thread.is_finished()
        } else {
            true
        }
    }
}

unsafe extern "system" fn event_record_handler(event_record: *mut EVENT_RECORD) {
    let unwinding_code = || {
        log::trace!("compound_event_record_handler called");
        let Some(event_record) = event_record.as_ref() else {
            log::error!("event_record was a null pointer");
            return;
        };

        let context = event_record.UserContext as *const HandlerData;
        Arc::increment_strong_count(context);
        let data = Arc::from_raw(context);

        match data.handler.lock() {
            Ok(mut handler) => handler(event_record),
            Err(err) => {
                log::error!("event record handler lock poisoned: {:?}", err);
            }
        };
    };
    match panic::catch_unwind(AssertUnwindSafe(unwinding_code)) {
        Ok(..) => (),
        Err(err) => {
            log::error!("event record handler panicked: {:?}", err);
            if log::log_enabled!(log::Level::Info) {
                let header = unsafe {
                    slice::from_raw_parts(
                        &(*event_record).EventHeader as *const _ as *const u8,
                        size_of::<EVENT_HEADER>(),
                    )
                };
                let header = header.iter().fold(String::new(), |mut output, b| {
                    let _ = write!(output, "{b:02x}");
                    output
                });
                let userdata = unsafe {
                    slice::from_raw_parts(
                        (*event_record).UserData as *const u8,
                        (*event_record).UserDataLength as usize,
                    )
                };
                let userdata = userdata.iter().fold(String::new(), |mut output, b| {
                    let _ = write!(output, "{b:02x}");
                    output
                });

                log::info!(
                    "event hander panic when parsing event record header: {} userdata: {}",
                    header,
                    userdata
                );
            }
        }
    }
}

unsafe extern "system" fn buffer_handler(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    let Some(logfile) = logfile.as_mut() else {
        log::error!("logfile was null");
        return false.into();
    };

    log::trace!("buffer_handler called");
    let context = logfile.Context as *const HandlerData;
    Arc::increment_strong_count(context);
    let context = Arc::from_raw(context);
    if context.stop_trace.load(Ordering::Acquire) {
        return false.into();
    }

    u32::from(true)
}
