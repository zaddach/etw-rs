use std::{
    ffi::{OsStr, OsString},
    fmt, iter, mem,
    os::windows::prelude::{OsStrExt, OsStringExt},
    time::Duration,
};

use windows::{
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::ERROR_ALREADY_EXISTS,
        System::{
            Diagnostics::Etw::{
                ControlTraceW, EnableTraceEx2, StartTraceW, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_DISABLE_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_EVENT_ID, EVENT_FILTER_TYPE_EVENT_ID, EVENT_TRACE_ADDTO_TRIAGE_DUMP, EVENT_TRACE_ADD_HEADER_MODE, EVENT_TRACE_BUFFERING_MODE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_DELAY_OPEN_FILE_MODE, EVENT_TRACE_FILE_MODE_APPEND, EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_NEWFILE, EVENT_TRACE_FILE_MODE_NONE, EVENT_TRACE_FILE_MODE_PREALLOCATE, EVENT_TRACE_FILE_MODE_SEQUENTIAL, EVENT_TRACE_FLAG, EVENT_TRACE_FLAG_ALPC, EVENT_TRACE_FLAG_CSWITCH, EVENT_TRACE_FLAG_DBGPRINT, EVENT_TRACE_FLAG_DISK_FILE_IO, EVENT_TRACE_FLAG_DISK_IO, EVENT_TRACE_FLAG_DISK_IO_INIT, EVENT_TRACE_FLAG_DISPATCHER, EVENT_TRACE_FLAG_DPC, EVENT_TRACE_FLAG_DRIVER, EVENT_TRACE_FLAG_FILE_IO, EVENT_TRACE_FLAG_FILE_IO_INIT, EVENT_TRACE_FLAG_IMAGE_LOAD, EVENT_TRACE_FLAG_INTERRUPT, EVENT_TRACE_FLAG_JOB, EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS, EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS, EVENT_TRACE_FLAG_NETWORK_TCPIP, EVENT_TRACE_FLAG_NO_SYSCONFIG, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_FLAG_PROCESS_COUNTERS, EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_FLAG_REGISTRY, EVENT_TRACE_FLAG_SPLIT_IO, EVENT_TRACE_FLAG_SYSTEMCALL, EVENT_TRACE_FLAG_THREAD, EVENT_TRACE_FLAG_VAMAP, EVENT_TRACE_FLAG_VIRTUAL_ALLOC, EVENT_TRACE_INDEPENDENT_SESSION_MODE, EVENT_TRACE_MODE_RESERVED, EVENT_TRACE_NONSTOPPABLE_MODE, EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING, EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN, EVENT_TRACE_PRIVATE_IN_PROC, EVENT_TRACE_PRIVATE_LOGGER_MODE, EVENT_TRACE_PROPERTIES, EVENT_TRACE_PROPERTIES_V2, EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_RELOG_MODE, EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN, EVENT_TRACE_SYSTEM_LOGGER_MODE, EVENT_TRACE_USE_GLOBAL_SEQUENCE, EVENT_TRACE_USE_KBYTES_FOR_SIZE, EVENT_TRACE_USE_LOCAL_SEQUENCE, EVENT_TRACE_USE_PAGED_MEMORY, WNODE_FLAG_ALL_DATA, WNODE_FLAG_ANSI_INSTANCENAMES, WNODE_FLAG_EVENT_ITEM, WNODE_FLAG_EVENT_REFERENCE, WNODE_FLAG_FIXED_INSTANCE_SIZE, WNODE_FLAG_INSTANCES_SAME, WNODE_FLAG_INTERNAL, WNODE_FLAG_LOG_WNODE, WNODE_FLAG_METHOD_ITEM, WNODE_FLAG_NO_HEADER, WNODE_FLAG_PDO_INSTANCE_NAMES, WNODE_FLAG_PERSIST_EVENT, WNODE_FLAG_SEND_DATA_BLOCK, WNODE_FLAG_SEVERITY_MASK, WNODE_FLAG_SINGLE_INSTANCE, WNODE_FLAG_SINGLE_ITEM, WNODE_FLAG_STATIC_INSTANCE_NAMES, WNODE_FLAG_TOO_SMALL, WNODE_FLAG_TRACED_GUID, WNODE_FLAG_USE_GUID_PTR, WNODE_FLAG_USE_MOF_PTR, WNODE_FLAG_USE_TIMESTAMP, WNODE_FLAG_VERSIONED_PROPERTIES, WNODE_HEADER
            },
            Threading::INFINITE,
        },
    },
};

use crate::{error::TraceError, provider::Provider};

const TRACE_NAME_MAX_LEN: usize = 200;
const LOG_FILE_NAME_MAX_LEN: usize = 1024;

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct LogFileMode: u32 {
        const FILE_MODE_NONE = EVENT_TRACE_FILE_MODE_NONE;
        const FILE_MODE_SEQUENTIAL = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        const FILE_MODE_CIRCULAR = EVENT_TRACE_FILE_MODE_CIRCULAR;
        const FILE_MODE_APPEND = EVENT_TRACE_FILE_MODE_APPEND;
        const FILE_MODE_NEWFILE = EVENT_TRACE_FILE_MODE_NEWFILE;
        const FILE_MODE_PREALLOCATE = EVENT_TRACE_FILE_MODE_PREALLOCATE;
        const NONSTOPPABLE_MODE = EVENT_TRACE_NONSTOPPABLE_MODE;
        const REAL_TIME_MODE = EVENT_TRACE_REAL_TIME_MODE;
        const DELAY_OPEN_FILE_MODE = EVENT_TRACE_DELAY_OPEN_FILE_MODE;
        const BUFFERING_MODE = EVENT_TRACE_BUFFERING_MODE;
        const PRIVATE_LOGGER_MODE = EVENT_TRACE_PRIVATE_LOGGER_MODE;
        const ADD_HEADER_MODE = EVENT_TRACE_ADD_HEADER_MODE;
        const USE_KBYTES_FOR_SIZE = EVENT_TRACE_USE_KBYTES_FOR_SIZE;
        const USE_GLOBAL_SEQUENCE = EVENT_TRACE_USE_GLOBAL_SEQUENCE;
        const USE_LOCAL_SEQUENCE = EVENT_TRACE_USE_LOCAL_SEQUENCE;
        const RELOG_MODE = EVENT_TRACE_RELOG_MODE;
        const PRIVATE_IN_PROC = EVENT_TRACE_PRIVATE_IN_PROC;
        const MODE_RESERVED = EVENT_TRACE_MODE_RESERVED;
        const STOP_ON_HYBRID_SHUTDOWN = EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN;
        const PERSIST_ON_HYBRID_SHUTDOWN = EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN;
        const USE_PAGED_MEMORY = EVENT_TRACE_USE_PAGED_MEMORY;
        const SYSTEM_LOGGER_MODE = EVENT_TRACE_SYSTEM_LOGGER_MODE;
        const INDEPENDENT_SESSION_MODE = EVENT_TRACE_INDEPENDENT_SESSION_MODE;
        const NO_PER_PROCESSOR_BUFFERING = EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        const ADDTO_TRIAGE_DUMP = EVENT_TRACE_ADDTO_TRIAGE_DUMP;
    }
}

impl Default for LogFileMode {
    fn default() -> Self {
        LogFileMode::FILE_MODE_NONE
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for LogFileMode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "LogFileMode".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "oneOf": [
                {
                    "type": "integer",
                },
                {
                    "type": "string",
                    "pattern": r"^(FILE_MODE_NONE|FILE_MODE_SEQUENTIAL|FILE_MODE_CIRCULAR|FILE_MODE_APPEND|FILE_MODE_NEWFILE|FILE_MODE_PREALLOCATE|NONSTOPPABLE_MODE|REAL_TIME_MODE|DELAY_OPEN_FILE_MODE|BUFFERING_MODE|PRIVATE_LOGGER_MODE|ADD_HEADER_MODE|USE_KBYTES_FOR_SIZE|USE_GLOBAL_SEQUENCE|USE_LOCAL_SEQUENCE|RELOG_MODE|PRIVATE_IN_PROC|MODE_RESERVED|STOP_ON_HYBRID_SHUTDOWN|PERSIST_ON_HYBRID_SHUTDOWN|USE_PAGED_MEMORY|SYSTEM_LOGGER_MODE|INDEPENDENT_SESSION_MODE|NO_PER_PROCESSOR_BUFFERING|ADDTO_TRIAGE_DUMP)(\s*\|\s*(FILE_MODE_NONE|FILE_MODE_SEQUENTIAL|FILE_MODE_CIRCULAR|FILE_MODE_APPEND|FILE_MODE_NEWFILE|FILE_MODE_PREALLOCATE|NONSTOPPABLE_MODE|REAL_TIME_MODE|DELAY_OPEN_FILE_MODE|BUFFERING_MODE|PRIVATE_LOGGER_MODE|ADD_HEADER_MODE|USE_KBYTES_FOR_SIZE|USE_GLOBAL_SEQUENCE|USE_LOCAL_SEQUENCE|RELOG_MODE|PRIVATE_IN_PROC|MODE_RESERVED|STOP_ON_HYBRID_SHUTDOWN|PERSIST_ON_HYBRID_SHUTDOWN|USE_PAGED_MEMORY|SYSTEM_LOGGER_MODE|INDEPENDENT_SESSION_MODE|NO_PER_PROCESSOR_BUFFERING|ADDTO_TRIAGE_DUMP))$",
                },
            ]
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct WnodeFlag: u32 {
        const ALL_DATA = WNODE_FLAG_ALL_DATA;
        const ANSI_INSTANCENAMES = WNODE_FLAG_ANSI_INSTANCENAMES;
        const EVENT_ITEM = WNODE_FLAG_EVENT_ITEM;
        const EVENT_REFERENCE = WNODE_FLAG_EVENT_REFERENCE;
        const FIXED_INSTANCE_SIZE = WNODE_FLAG_FIXED_INSTANCE_SIZE;
        const INSTANCES_SAME = WNODE_FLAG_INSTANCES_SAME;
        const INTERNAL = WNODE_FLAG_INTERNAL;
        const LOG_WNODE = WNODE_FLAG_LOG_WNODE;
        const METHOD_ITEM = WNODE_FLAG_METHOD_ITEM;
        const NO_HEADER = WNODE_FLAG_NO_HEADER;
        const PDO_INSTANCE_NAMES = WNODE_FLAG_PDO_INSTANCE_NAMES;
        const PERSIST_EVENT = WNODE_FLAG_PERSIST_EVENT;
        const SEND_DATA_BLOCK = WNODE_FLAG_SEND_DATA_BLOCK;
        const SEVERITY_MASK = WNODE_FLAG_SEVERITY_MASK;
        const SINGLE_INSTANCE = WNODE_FLAG_SINGLE_INSTANCE;
        const SINGLE_ITEM = WNODE_FLAG_SINGLE_ITEM;
        const STATIC_INSTANCE_NAMES = WNODE_FLAG_STATIC_INSTANCE_NAMES;
        const TOO_SMALL = WNODE_FLAG_TOO_SMALL;
        const TRACED_GUID = WNODE_FLAG_TRACED_GUID;
        const USE_GUID_PTR = WNODE_FLAG_USE_GUID_PTR;
        const USE_MOF_PTR = WNODE_FLAG_USE_MOF_PTR;
        const USE_TIMESTAMP = WNODE_FLAG_USE_TIMESTAMP;
        const VERSIONED_PROPERTIES = WNODE_FLAG_VERSIONED_PROPERTIES;
    }
}

impl Default for WnodeFlag {
    fn default() -> Self {
        WnodeFlag::TRACED_GUID
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for WnodeFlag {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "WnodeFlag".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "oneOf": [
                {
                    "type": "integer",
                },
                {
                    "type": "string",
                    "pattern": r"^(ALL_DATA|ANSI_INSTANCENAMES|EVENT_ITEM|EVENT_REFERENCE|FIXED_INSTANCE_SIZE|INSTANCES_SAME|INTERNAL|LOG_WNODE|METHOD_ITEM|NO_HEADER|PDO_INSTANCE_NAMES|PERSIST_EVENT|SEND_DATA_BLOCK|SEVERITY_MASK|SINGLE_INSTANCE|SINGLE_ITEM|STATIC_INSTANCE_NAMES|TOO_SMALL|TRACED_GUID|USE_GUID_PTR|USE_MOF_PTR|USE_TIMESTAMP|VERSIONED_PROPERTIES)(\s*\|\s*(ALL_DATA|ANSI_INSTANCENAMES|EVENT_ITEM|EVENT_REFERENCE|FIXED_INSTANCE_SIZE|INSTANCES_SAME|INTERNAL|LOG_WNODE|METHOD_ITEM|NO_HEADER|PDO_INSTANCE_NAMES|PERSIST_EVENT|SEND_DATA_BLOCK|SEVERITY_MASK|SINGLE_INSTANCE|SINGLE_ITEM|STATIC_INSTANCE_NAMES|TOO_SMALL|TRACED_GUID|USE_GUID_PTR|USE_MOF_PTR|USE_TIMESTAMP|VERSIONED_PROPERTIES))$",
                },
            ]
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum ClockResolution {
    QueryPerformanceCounter = 1,
    SystemTime = 2,
    CpuCycleCounter = 3,
}

const DEFAULT_BUFFER_SIZE_KB: u32 = 32;
const DEFAULT_LOG_FILE_MODE: LogFileMode =
    LogFileMode::REAL_TIME_MODE.union(LogFileMode::NO_PER_PROCESSOR_BUFFERING);
const DEFAULT_WNODE_FLAGS: WnodeFlag =
    WnodeFlag::TRACED_GUID.union(WnodeFlag::VERSIONED_PROPERTIES);
const DEFAULT_CLOCK_RESOLUTION: ClockResolution = ClockResolution::QueryPerformanceCounter;
const DEFAULT_MINIMUM_BUFFERS: u32 = 0;
const DEFAULT_MAXIMUM_BUFFERS: u32 = 0;
const DEFAULT_FLUSH_TIMER: u32 = 1;

#[derive(Debug, Default)]
pub struct EventTraceProperties(Box<EventTracePropertiesInner>);

#[repr(C)]
pub struct EventTracePropertiesInner {
    data: EVENT_TRACE_PROPERTIES_V2,
    logger_name: [u16; TRACE_NAME_MAX_LEN + 1],
    log_file_name: [u16; LOG_FILE_NAME_MAX_LEN + 1],
}

unsafe impl Send for EventTracePropertiesInner {}

impl fmt::Debug for EventTracePropertiesInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let logger_name_len = self.logger_name.iter().take_while(|x| **x != 0).count();
        let log_file_name_len = self.log_file_name.iter().take_while(|x| **x != 0).count();
        f.debug_struct("EventTracePropertiesInner")
            .field("data.Wnode.BufferSize", &self.data.Wnode.BufferSize)
            .field("data.Wnode.ProviderId", &self.data.Wnode.ProviderId)
            .field("data.Wnode.Guid", &self.data.Wnode.Guid)
            .field("data.Wnode.ClientContext", &self.data.Wnode.ClientContext)
            .field("data.Wnode.Flags", &self.data.Wnode.Flags)
            .field("data.BufferSize", &self.data.BufferSize)
            .field("data.MinimumBuffers", &self.data.MinimumBuffers)
            .field("data.MaximumBuffers", &self.data.MaximumBuffers)
            .field("data.FlushTimer", &self.data.FlushTimer)
            .field("data.LoggerNameOffset", &self.data.LoggerNameOffset)
            .field("data.LogFileNameOffset", &self.data.LogFileNameOffset)
            .field("data.EnableFlags", &self.data.EnableFlags)
            .field(
                "logger_name",
                &OsString::from_wide(&self.logger_name[..logger_name_len]),
            )
            .field(
                "log_file_name",
                &OsString::from_wide(&self.log_file_name[..log_file_name_len]),
            )
            .finish_non_exhaustive()
    }
}

impl Default for EventTracePropertiesInner {
    fn default() -> Self {
        Self {
            data: EVENT_TRACE_PROPERTIES_V2 {
                Wnode: WNODE_HEADER {
                    BufferSize: u32::try_from(mem::size_of::<EventTracePropertiesInner>()).unwrap(),
                    ..Default::default()
                },
                ..Default::default()
            },
            logger_name: [0u16; TRACE_NAME_MAX_LEN + 1],
            log_file_name: [0u16; LOG_FILE_NAME_MAX_LEN + 1],
        }
    }
}

impl EventTraceProperties {
    pub fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.0.as_mut() as *mut _ as *mut EVENT_TRACE_PROPERTIES
    }

    pub fn set_log_file_name(&mut self, name: &OsStr) {
        let name = name.encode_wide().chain(iter::once(0)).collect::<Vec<_>>();
        self.0.log_file_name[0..name.len()].copy_from_slice(&name);
        self.0.data.LogFileNameOffset = u32::try_from(memoffset::offset_of!(
            EventTracePropertiesInner,
            log_file_name
        ))
        .unwrap();
    }

    pub fn set_logger_name(&mut self, name: &OsStr) {
        let name = name.encode_wide().chain(iter::once(0)).collect::<Vec<_>>();
        self.0.logger_name[0..name.len()].copy_from_slice(&name);
        self.0.data.LoggerNameOffset = u32::try_from(memoffset::offset_of!(
            EventTracePropertiesInner,
            logger_name
        ))
        .unwrap();
    }
}

#[derive(Debug, Default)]
pub struct EventTracePropertiesBuilder(EventTraceProperties);

impl EventTracePropertiesBuilder {
    pub fn new() -> EventTracePropertiesBuilder {
        let mut event_trace_properties = EventTraceProperties::default();
        event_trace_properties.0.data.Wnode.Guid =
            windows::core::GUID::new().unwrap_or(windows::core::GUID::zeroed());
        event_trace_properties.0.data.BufferSize = DEFAULT_BUFFER_SIZE_KB;
        event_trace_properties.0.data.MinimumBuffers = DEFAULT_MINIMUM_BUFFERS;
        event_trace_properties.0.data.MaximumBuffers = DEFAULT_MAXIMUM_BUFFERS;
        event_trace_properties.0.data.FlushTimer = DEFAULT_FLUSH_TIMER;
        event_trace_properties.0.data.LogFileMode = DEFAULT_LOG_FILE_MODE.bits();
        event_trace_properties.0.data.Wnode.Flags = DEFAULT_WNODE_FLAGS.bits();
        event_trace_properties.0.data.Wnode.ClientContext = DEFAULT_CLOCK_RESOLUTION as u32;
        EventTracePropertiesBuilder(event_trace_properties)
    }

    pub fn buffer_size(mut self, size: u32) -> EventTracePropertiesBuilder {
        self.0 .0.data.BufferSize = size;
        self
    }

    pub fn minimum_buffers(mut self, num: u32) -> EventTracePropertiesBuilder {
        self.0 .0.data.MinimumBuffers = num;
        self
    }

    pub fn maximum_buffers(mut self, num: u32) -> EventTracePropertiesBuilder {
        self.0 .0.data.MaximumBuffers = num;
        self
    }

    pub fn flush_timer(mut self, period: Duration) -> EventTracePropertiesBuilder {
        self.0 .0.data.FlushTimer =
            u32::try_from(period.as_secs().clamp(1, u64::from(u32::MAX))).unwrap();
        self
    }

    pub fn log_file_mode(mut self, log_file_mode: LogFileMode) -> EventTracePropertiesBuilder {
        self.0 .0.data.LogFileMode = log_file_mode.bits();
        self
    }

    pub fn wnode_flags(mut self, wnode_flags: WnodeFlag) -> EventTracePropertiesBuilder {
        self.0 .0.data.Wnode.Flags = wnode_flags.bits();
        self
    }

    pub fn clock_resolution(
        mut self,
        clock_resolution: ClockResolution,
    ) -> EventTracePropertiesBuilder {
        self.0 .0.data.Wnode.ClientContext = clock_resolution as u32;
        self
    }

    pub fn log_file_name(mut self, name: &OsStr) -> EventTracePropertiesBuilder {
        self.0.set_log_file_name(name);
        self
    }

    pub fn logger_name(mut self, name: &OsStr) -> EventTracePropertiesBuilder {
        self.0.set_logger_name(name);
        self
    }

    pub fn guid(mut self, guid: windows::core::GUID) -> EventTracePropertiesBuilder {
        self.0 .0.data.Wnode.Guid = guid;
        self
    }

    pub fn enable_flags(mut self, flags: EnableFlags) -> EventTracePropertiesBuilder {
        self.0 .0.data.EnableFlags = EVENT_TRACE_FLAG(flags.bits());
        self
    }

    pub fn build(self) -> EventTraceProperties {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct TraceSessionBuilder {
    name: OsString,
    event_trace_properties: EventTracePropertiesBuilder,
    close_on_drop: bool,
    close_previous: bool,
}

impl TraceSessionBuilder {
    pub fn new<S: AsRef<OsStr>>(name: S) -> TraceSessionBuilder {
        let name = name.as_ref().to_os_string();
        TraceSessionBuilder {
            name,
            close_on_drop: true,
            event_trace_properties: EventTracePropertiesBuilder::new(),
            ..Default::default()
        }
    }

    pub fn buffer_size(mut self, size: u32) -> TraceSessionBuilder {
        self.event_trace_properties = self.event_trace_properties.buffer_size(size);
        self
    }

    pub fn close_previous(mut self) -> TraceSessionBuilder {
        self.close_previous = true;
        self
    }

    pub fn log_file_mode(mut self, log_file_mode: LogFileMode) -> TraceSessionBuilder {
        self.event_trace_properties = self.event_trace_properties.log_file_mode(log_file_mode);
        self
    }

    pub fn wnode_flags(mut self, wnode_flags: WnodeFlag) -> TraceSessionBuilder {
        self.event_trace_properties = self
            .event_trace_properties
            .wnode_flags(wnode_flags | WnodeFlag::TRACED_GUID | WnodeFlag::VERSIONED_PROPERTIES);
        self
    }

    pub fn clock_resolution(mut self, clock_resolution: ClockResolution) -> TraceSessionBuilder {
        self.event_trace_properties = self
            .event_trace_properties
            .clock_resolution(clock_resolution);
        self
    }

    pub fn minimum_buffers(mut self, num: u32) -> TraceSessionBuilder {
        self.event_trace_properties = self.event_trace_properties.minimum_buffers(num);
        self
    }

    pub fn maximum_buffers(mut self, num: u32) -> TraceSessionBuilder {
        self.event_trace_properties = self.event_trace_properties.maximum_buffers(num);
        self
    }

    pub fn flush_timer(mut self, period: Duration) -> TraceSessionBuilder {
        self.event_trace_properties = self.event_trace_properties.flush_timer(period);
        self
    }

    pub fn no_close_on_drop(mut self) -> TraceSessionBuilder {
        self.close_on_drop = false;
        self
    }

    pub fn start(self) -> Result<TraceSession, TraceError> {
        log::trace!("TraceSessionBuilder::start: {:?}", self);
        let mut handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE::default();
        let mut properties = self.event_trace_properties.build();
        properties.set_logger_name(&self.name);
        let name = self
            .name
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        //TODO: log file
        unsafe {
            match StartTraceW(
                &mut handle,
                PCWSTR::from_raw(name.as_ptr()),
                properties.as_mut_ptr(),
            )
            .ok()
            {
                Ok(()) => {
                    log::trace!("StartTraceW returned OK");
                    Ok(TraceSession {
                        handle,
                        name: self.name.clone(),
                        properties,
                        close_on_drop: self.close_on_drop,
                    })
                }
                Err(err) if err.code() == HRESULT::from(ERROR_ALREADY_EXISTS) => {
                    if !self.close_previous {
                        return Err(err.into());
                    }
                    log::debug!("Trace session {:?} already exists, closing it", &self.name);
                    let mut control_properties = EventTraceProperties::default();
                    control_properties.0.data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                    match ControlTraceW(
                        CONTROLTRACE_HANDLE::default(),
                        PCWSTR::from_raw(name.as_ptr()),
                        control_properties.as_mut_ptr(),
                        EVENT_TRACE_CONTROL_STOP,
                    )
                    .ok()
                    {
                        Ok(()) => {
                            log::debug!("Calling StartTraceW again");
                            match StartTraceW(
                                &mut handle,
                                PCWSTR::from_raw(name.as_ptr()),
                                properties.as_mut_ptr(),
                            )
                            .ok()
                            {
                                Ok(()) => {
                                    log::debug!("StartTraceW returned OK");
                                    Ok(TraceSession {
                                        handle,
                                        name: self.name.clone(),
                                        properties,
                                        close_on_drop: self.close_on_drop,
                                    })
                                }
                                Err(err) => {
                                    log::warn!("StartTraceW returned error: {:?}", err);
                                    Err(err.into())
                                }
                            }
                        }
                        Err(err) => {
                            log::warn!("ControlTraceW returned error: {:?}", err);
                            Err(err.into())
                        }
                    }
                }
                Err(err) => {
                    log::warn!("StartTraceW returned error: {:?}", err);
                    Err(err.into())
                }
            }
        }
    }
}

pub struct TraceSession {
    handle: CONTROLTRACE_HANDLE,
    name: OsString,
    properties: EventTraceProperties,
    close_on_drop: bool,
}

impl fmt::Debug for TraceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceSession")
            .field("handle", &self.handle)
            .field("name", &self.name)
            .field("properties", &self.properties)
            .field("close_on_drop", &self.close_on_drop)
            .finish()
    }
}

impl TraceSession {
    pub fn open_existing<S: Into<OsString>>(name: S) -> TraceSession {
        TraceSession {
            handle: CONTROLTRACE_HANDLE::default(),
            name: name.into(),
            properties: EventTraceProperties::default(),
            close_on_drop: false,
        }
    }

    pub fn name(&self) -> &OsStr {
        &self.name
    }
}

#[derive(Debug)]
pub enum EnableProviderTimeout {
    Asynchronous,
    Timeout(Duration),
    Infinite,
}

impl From<EnableProviderTimeout> for u32 {
    fn from(value: EnableProviderTimeout) -> Self {
        match value {
            EnableProviderTimeout::Asynchronous => 0,
            EnableProviderTimeout::Timeout(duration) => duration.as_millis().try_into().unwrap(),
            EnableProviderTimeout::Infinite => INFINITE,
        }
    }
}

pub struct EventFilterEventId {
    data: Vec<u8>,
}

impl fmt::Debug for EventFilterEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let event_ids = (0..self.as_ref().Count)
            .map(|idx| 
                unsafe {
                    self.as_ref()
                    .Events
                    .as_ptr()
                    .add(usize::from(idx))
                    .as_ref()
                    .unwrap()
                }
            )
            .collect::<Vec<_>>();
        f.debug_struct("EventFilterEventId")
            .field("FilterIn", &bool::from(self.as_ref().FilterIn))
            .field("Events", &event_ids)
            .finish()
    }
}

impl EventFilterEventId {
    pub fn new(event_ids: &[u16]) -> EventFilterEventId {
        let data = vec![
            0;
            mem::size_of::<EVENT_FILTER_EVENT_ID>()
                + (event_ids.len() - 1) * mem::size_of::<u16>()
        ];
        let mut event_filter = EventFilterEventId { data };
        event_filter.as_mut().Count = u16::try_from(event_ids.len()).unwrap();
        for (idx, event_id) in event_ids.iter().enumerate() {
            unsafe {
                *(
                    event_filter.as_mut()
                    .Events
                    .as_mut_ptr()
                    .add(idx)
                    .as_mut()
                    .unwrap()
                ) = *event_id;
            }
        }
        event_filter.as_mut().FilterIn = true.into();
        event_filter
    }

    pub fn as_ptr(&self) -> *const EVENT_FILTER_EVENT_ID {
        self.data.as_ptr() as *const EVENT_FILTER_EVENT_ID
    }

    pub fn size(&self) -> u32 {
        u32::try_from(self.data.len()).unwrap()
    }
}

impl AsMut<EVENT_FILTER_EVENT_ID> for EventFilterEventId {
    fn as_mut(&mut self) -> &mut EVENT_FILTER_EVENT_ID {
        unsafe {
            (self.data.as_mut_ptr() as *mut EVENT_FILTER_EVENT_ID)
                .as_mut()
                .unwrap()
        }
    }
}

impl AsRef<EVENT_FILTER_EVENT_ID> for EventFilterEventId {
    fn as_ref(&self) -> &EVENT_FILTER_EVENT_ID {
        unsafe {
            (self.data.as_ptr() as *const EVENT_FILTER_EVENT_ID)
                .as_ref()
                .unwrap()
        }
    }
}

#[derive(Debug)]
pub enum EventFilter {
    EventId(EventFilterEventId),
}

impl EventFilter {
    pub fn as_ptr(&self) -> u64 {
        match self {
            EventFilter::EventId(filter) => filter.as_ptr() as u64,
        }
    }

    pub fn size(&self) -> u32 {
        match self {
            EventFilter::EventId(filter) => filter.size(),
        }
    }

    pub fn kind(&self) -> u32 {
        match self {
            EventFilter::EventId(_) => EVENT_FILTER_TYPE_EVENT_ID,
        }
    }

    pub fn event_ids(events: &[u16]) -> EventFilter {
        EventFilter::EventId(EventFilterEventId::new(events))
    }
}

#[derive(Default)]
pub struct EventFilters {
    descriptors: Vec<EVENT_FILTER_DESCRIPTOR>,
    filters: Vec<EventFilter>,
}

impl fmt::Debug for EventFilters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventFilters")
            .field("filters", &self.filters)
            .finish()
    }
}

impl EventFilters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, filter: EventFilter) {
        self.descriptors.push(EVENT_FILTER_DESCRIPTOR {
            Ptr: filter.as_ptr(),
            Size: filter.size(),
            Type: filter.kind(),
        });
        self.filters.push(filter);
    }

    pub fn as_mut_ptr(&mut self) -> *mut EVENT_FILTER_DESCRIPTOR {
        self.descriptors.as_mut_ptr()
    }

    pub fn size(&self) -> u32 {
        u32::try_from(self.descriptors.len()).unwrap()
    }
}

impl From<Vec<EventFilter>> for EventFilters {
    fn from(filters: Vec<EventFilter>) -> Self {
        let mut event_filters = Self::new();

        for filter in filters {
            event_filters.add(filter);
        }

        event_filters
    }
}

impl From<EventFilterEventId> for EventFilters {
    fn from(filter: EventFilterEventId) -> Self {
        let mut event_filters = Self::new();

        event_filters.add(EventFilter::EventId(filter));

        event_filters
    }
}

#[derive(Default)]
pub struct EnableParameters {
    data: Box<ENABLE_TRACE_PARAMETERS>,
    event_filters: Option<EventFilters>,
}

impl EnableParameters {
    pub fn new() -> EnableParameters {
        EnableParameters {
            data: Box::new(ENABLE_TRACE_PARAMETERS {
                Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn as_ptr(&self) -> *const ENABLE_TRACE_PARAMETERS {
        self.data.as_ref() as *const _
    }
}

impl TraceSession {
    pub fn enable_provider(
        &mut self,
        provider: &Provider,
        state: bool,
        timeout: EnableProviderTimeout,
        mut event_filters: Option<EventFilters>,
    ) -> Result<(), TraceError> {
        log::debug!(
            "TraceSession::enable_provider({:?}, {:?}, {:?}, {:?})",
            provider,
            state,
            &timeout,
            &event_filters
        );
        unsafe {
            let control_code = match state {
                false => EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                true => EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            };
            let mut parameters = EnableParameters::new();

            parameters.data.SourceId = *provider.id();

            if let Some(event_filters) = &mut event_filters {
                parameters.data.EnableFilterDesc = event_filters.as_mut_ptr();
                parameters.data.FilterDescCount = event_filters.size();
            }

            parameters.event_filters = event_filters;

            match EnableTraceEx2(
                self.handle,
                provider.id(),
                control_code.0,
                provider.level().into(),
                provider.any(),
                provider.all(),
                timeout.into(),
                Some(parameters.as_ptr()),
            )
            .ok()
            {
                Ok(()) => {
                    log::trace!("EnableTraceEx2 returned OK");
                    Ok(())
                }
                Err(err) => {
                    log::warn!("EnableTraceEx2 returned error: {:?}", err);
                    Err(err.into())
                }
            }
        }
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        unsafe {
            if self.close_on_drop {
                if let Err(err) = ControlTraceW(
                    self.handle,
                    None,
                    self.properties.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                )
                .ok()
                {
                    log::warn!(
                        "ControlTraceW(_, _, _, EVENT_CONTROL_TRACE_STOP) returned error: {:?}",
                        err
                    );
                }
            }
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct EnableFlags: u32 {
        const NETWORK_TCPIP = EVENT_TRACE_FLAG_NETWORK_TCPIP.0;
        const ALPC = EVENT_TRACE_FLAG_ALPC.0;
        const CSWITCH = EVENT_TRACE_FLAG_CSWITCH.0;
        const DBGPRINT = EVENT_TRACE_FLAG_DBGPRINT.0;
        const DISK_FILE_IO = EVENT_TRACE_FLAG_DISK_FILE_IO.0;
        const DISK_IO = EVENT_TRACE_FLAG_DISK_IO.0;
        const DISK_IO_INIT = EVENT_TRACE_FLAG_DISK_IO_INIT.0;
        const DISPATCHER = EVENT_TRACE_FLAG_DISPATCHER.0;
        const DPC = EVENT_TRACE_FLAG_DPC.0;
        const DRIVER = EVENT_TRACE_FLAG_DRIVER.0;
        const FILE_IO = EVENT_TRACE_FLAG_FILE_IO.0;
        const FILE_IO_INIT = EVENT_TRACE_FLAG_FILE_IO_INIT.0;
        const IMAGE_LOAD = EVENT_TRACE_FLAG_IMAGE_LOAD.0;
        const INTERRUPT = EVENT_TRACE_FLAG_INTERRUPT.0;
        const JOB = EVENT_TRACE_FLAG_JOB.0;
        const MEMORY_HARD_FAULTS = EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS.0;
        const MEMORY_PAGE_FAULTS = EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS.0;
        const NO_SYSCONFIG = EVENT_TRACE_FLAG_NO_SYSCONFIG.0;
        const PROCESS = EVENT_TRACE_FLAG_PROCESS.0;
        const PROCESS_COUNTERS = EVENT_TRACE_FLAG_PROCESS_COUNTERS.0;
        const PROFILE = EVENT_TRACE_FLAG_PROFILE.0;
        const REGISTRY = EVENT_TRACE_FLAG_REGISTRY.0;
        const SPLIT_IO = EVENT_TRACE_FLAG_SPLIT_IO.0;
        const SYSTEMCALL = EVENT_TRACE_FLAG_SYSTEMCALL.0;
        const THREAD = EVENT_TRACE_FLAG_THREAD.0;
        const VAMAP = EVENT_TRACE_FLAG_VAMAP.0;
        const VIRTUAL_ALLOC = EVENT_TRACE_FLAG_VIRTUAL_ALLOC.0;
    }
}

impl EnableFlags {
    pub fn value(&self) -> EVENT_TRACE_FLAG {
        EVENT_TRACE_FLAG(self.bits())
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for EnableFlags {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EnableFlags".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "oneOf": [
                {
                    "type": "integer",
                },
                {
                    "type": "string",
                    "pattern": r"^(NETWORK_TCPIP|ALPC|CSWITCH|DBGPRINT|DISK_FILE_IO|DISK_IO|DISK_IO_INIT|DISPATCHER|DPC|DRIVER|FILE_IO|FILE_IO_INIT|IMAGE_LOAD|INTERRUPT|JOB|MEMORY_HARD_FAULTS|MEMORY_PAGE_FAULTS|NO_SYSCONFIG|PROCESS|PROCESS_COUNTERS|PROFILE|REGISTRY|SPLIT_IO|SYSTEMCALL|THREAD|VAMAP|VIRTUAL_ALLOC)(\s*\|\s*(NETWORK_TCPIP|ALPC|CSWITCH|DBGPRINT|DISK_FILE_IO|DISK_IO|DISK_IO_INIT|DISPATCHER|DPC|DRIVER|FILE_IO|FILE_IO_INIT|IMAGE_LOAD|INTERRUPT|JOB|MEMORY_HARD_FAULTS|MEMORY_PAGE_FAULTS|NO_SYSCONFIG|PROCESS|PROCESS_COUNTERS|PROFILE|REGISTRY|SPLIT_IO|SYSTEMCALL|THREAD|VAMAP|VIRTUAL_ALLOC))$",
                },
            ]
        })
    }
}
