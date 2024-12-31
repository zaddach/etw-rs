use std::{
    fmt, mem::size_of, slice, sync::Arc
};

use once_cell::sync::Lazy;
use windows::{
    core::GUID,
    Win32::System::Diagnostics::Etw::{
        EVENT_DESCRIPTOR, EVENT_HEADER, EVENT_HEADER_FLAG_PRIVATE_SESSION, EVENT_RECORD,
        EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER,
        EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_HEADER_FLAG_EXTENDED_INFO,
        EVENT_HEADER_FLAG_NO_CPUTIME,
        EVENT_HEADER_FLAG_STRING_ONLY, EVENT_HEADER_FLAG_TRACE_MESSAGE,
    },
};

use crate::{error::{ParseError, TraceError}, schema::cache::{EventInfo, SchemaCache}, values::compound::StringOrStruct};

#[repr(transparent)]
pub struct EventDescriptor<'a>(&'a EVENT_DESCRIPTOR);

impl EventDescriptor<'_> {
    pub fn id(&self) -> u16 {
        self.0.Id
    }

    pub fn version(&self) -> u8 {
        self.0.Version
    }

    pub fn channel(&self) -> u8 {
        self.0.Channel
    }

    pub fn level(&self) -> u8 {
        self.0.Level
    }

    pub fn opcode(&self) -> u8 {
        self.0.Opcode
    }

    pub fn task(&self) -> u16 {
        self.0.Task
    }

    pub fn keyword(&self) -> u64 {
        self.0.Keyword
    }
}

impl<'a> From<&'a EVENT_DESCRIPTOR> for EventDescriptor<'a> {
    fn from(value: &'a EVENT_DESCRIPTOR) -> Self {
        EventDescriptor(value)
    }
}

impl fmt::Debug for EventDescriptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventDescriptor")
            .field("Id", &self.id())
            .field("Version", &self.version())
            .field("Channel", &self.channel())
            .field("Level", &self.level())
            .field("Opcode", &self.opcode())
            .field("Task", &self.task())
            .field("Keyword", &self.keyword())
            .finish()
    }
}

#[repr(transparent)]
pub struct Header<'a>(&'a EVENT_HEADER);

impl<'a> Header<'a> {
    pub fn size(&self) -> u16 {
        self.0.Size
    }

    pub fn header_type(&self) -> u16 {
        self.0.HeaderType
    }

    pub fn flags(&self) -> u16 {
        self.0.Flags
    }

    pub fn event_property(&self) -> u16 {
        self.0.EventProperty
    }

    pub fn thread_id(&self) -> u32 {
        self.0.ThreadId
    }

    pub fn process_id(&self) -> u32 {
        self.0.ProcessId
    }

    pub fn timestamp(&self) -> i64 {
        self.0.TimeStamp
    }

    pub fn provider_id(&self) -> &::windows::core::GUID {
        &self.0.ProviderId
    }

    pub fn event_descriptor(&self) -> EventDescriptor {
        EventDescriptor(&self.0.EventDescriptor)
    }

    pub fn elapsed_execution_time(&self) -> ElapsedExecutionTime {
        unsafe {
            if (u32::from(self.flags()) & EVENT_HEADER_FLAG_PRIVATE_SESSION) != 0 {
                ElapsedExecutionTime::Processor(self.0.Anonymous.ProcessorTime)
            } else {
                ElapsedExecutionTime::UserKernel {
                    user: self.0.Anonymous.Anonymous.UserTime,
                    kernel: self.0.Anonymous.Anonymous.KernelTime,
                }
            }
        }
    }

    pub fn activity_id(&self) -> &::windows::core::GUID {
        &self.0.ActivityId
    }
}

impl<'a> From<&'a EVENT_HEADER> for Header<'a> {
    fn from(value: &'a EVENT_HEADER) -> Self {
        Header::<'a>(value)
    }
}

impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("Size", &self.size())
            .field("HeaderType", &self.header_type())
            .field("Flags", &self.flags())
            .field("EventProperty", &self.event_property())
            .field("ThreadId", &self.thread_id())
            .field("ProcessId", &self.process_id())
            .field("TimeStamp", &self.timestamp())
            .field("ProviderId", &self.provider_id())
            .field("EventDescriptor", &self.event_descriptor())
            .field("ActivityId", &self.activity_id())
            .finish()
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, Copy, Clone)]
pub enum ElapsedExecutionTime {
    UserKernel { user: u32, kernel: u32 },
    Processor(u64),
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, Copy, Clone)]
pub struct EventDescriptorOwned {
    pub id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
}

impl From<EventDescriptor<'_>> for EventDescriptorOwned {
    fn from(value: EventDescriptor) -> Self {
        Self {
            id: value.id(),
            version: value.version(),
            channel: value.channel(),
            level: value.level(),
            opcode: value.opcode(),
            task: value.task(),
            keyword: value.keyword(),
        }
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(remote = "::windows::core::GUID"))]
struct GUIDDef {
    #[cfg_attr(feature = "serde", serde(getter = "::windows::core::GUID::to_u128"))]
    value: u128,
}

impl From<GUIDDef> for GUID {
    fn from(value: GUIDDef) -> Self {
        GUID::from_u128(value.value)
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, Copy, Clone)]
pub struct HeaderOwned {
    pub size: u16,
    pub header_type: u16,
    pub flags: u16,
    pub event_property: u16,
    pub thread_id: u32,
    pub process_id: u32,
    pub timestamp: i64,
    #[cfg_attr(feature = "serde", serde(with = "GUIDDef"))]
    pub provider_id: ::windows::core::GUID,
    pub event_descriptor: EventDescriptorOwned,
    pub elapsed_execution_time: ElapsedExecutionTime,
    #[cfg_attr(feature = "serde", serde(with = "GUIDDef"))]
    pub activity_id: ::windows::core::GUID,
}

impl From<&Header<'_>> for HeaderOwned {
    fn from(value: &Header) -> Self {
        Self {
            size: value.size(),
            header_type: value.header_type(),
            flags: value.flags(),
            event_property: value.event_property(),
            thread_id: value.thread_id(),
            process_id: value.process_id(),
            timestamp: value.timestamp(),
            provider_id: *value.provider_id(),
            event_descriptor: value.event_descriptor().into(),
            elapsed_execution_time: value.elapsed_execution_time(),
            activity_id: *value.activity_id(),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct EventHeaderFlags: u16 {
        const EXTENDED_INFO = EVENT_HEADER_FLAG_EXTENDED_INFO as u16;
        const PRIVATE_SESSION = EVENT_HEADER_FLAG_PRIVATE_SESSION as u16;
        const STRING_ONLY = EVENT_HEADER_FLAG_STRING_ONLY as u16;
        const TRACE_MESSAGE = EVENT_HEADER_FLAG_TRACE_MESSAGE as u16;
        const NO_CPUTIME = EVENT_HEADER_FLAG_NO_CPUTIME as u16;
        const HEADER_64_BIT = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;
        const HEADER_32_BIT = EVENT_HEADER_FLAG_32_BIT_HEADER as u16;
        const CLASSIC_HEADER = EVENT_HEADER_FLAG_CLASSIC_HEADER as u16;
    }
}

pub struct EventHeader<'a> {
    pub data: &'a EVENT_HEADER,
}

impl<'a> EventHeader<'a> {
    #[inline]
    pub fn thread_id(&self) -> u32 {
        self.data.ThreadId
    }

    #[inline]
    pub fn process_id(&self) -> u32 {
        self.data.ProcessId
    }

    #[inline]
    pub fn timestamp(&self) -> i64 {
        self.data.TimeStamp
    }

    #[inline]
    pub fn flags(&self) -> EventHeaderFlags {
        EventHeaderFlags::from_bits_truncate(self.data.Flags)
    }

    #[inline]
    pub fn provider_id(&self) -> GUID {
        self.data.ProviderId
    }
}

#[derive(Debug)]
pub struct Event<'a> {
    pub header: Header<'a>,
    pub data: StringOrStruct<'a>,
}

impl<'a> Event<'a> {
    pub fn parse(event_record: &EVENT_RECORD) -> Result<(Arc<EventInfo>, Event), TraceError> {
        let event = EventRecord(event_record);

        if event.is_wpp_event() {
            Self::parse_wpp_event(event_record)
        }
        else {
            Self::parse_non_wpp_event(event_record)
        }
    }

    fn parse_wpp_event(_event_record: &EVENT_RECORD) -> Result<(Arc<EventInfo>, Event), TraceError> {
        todo!()
    }

    fn parse_non_wpp_event(event_record: &EVENT_RECORD) -> Result<(Arc<EventInfo>, Event), TraceError> {
        let event = EventRecord(event_record);

        if event.is_string_event() {
            let string = unsafe {
                slice::from_raw_parts(event_record.UserData as *const u8, event_record.UserDataLength.into())
            };
            let chunks = string.chunks_exact(2);
            let remainder = chunks.remainder();
            let string = chunks.map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap())).collect::<Vec<_>>();
            let _string = String::from_utf16(&string).map_err(|e| ParseError::from(e))?;
            if !remainder.is_empty() {
                Err(ParseError::DataLeftAfterDecoding.into())
            }
            else {
                todo!()
            }
        }
        else {
            Self::parse_properties(event_record)
        }
    }
    fn parse_properties<'b, 'c>(event_record: &'b EVENT_RECORD) -> Result<(Arc<EventInfo>, Event<'c>), TraceError> where 'b: 'c {
        static EVENT_SCHEMAS: Lazy<SchemaCache> = Lazy::new(|| SchemaCache::new());

        // Get event description from cache if we have already fetched it, otherwise fetch it and add it to the cache
        let schema = EVENT_SCHEMAS.get_from_event_record(event_record)?;

        let struc = schema.decode(event_record)?;
        Ok((schema, struc))
    }
}

#[repr(transparent)]
pub struct EventRecord<'a>(pub &'a EVENT_RECORD);

impl<'a> EventRecord<'a> {
    #[inline]
    pub fn pointer_size(&self) -> usize {
        if (u32::from(self.0.EventHeader.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER) == EVENT_HEADER_FLAG_32_BIT_HEADER {
            size_of::<u32>()
        }
        else if (u32::from(self.0.EventHeader.Flags) & EVENT_HEADER_FLAG_64_BIT_HEADER) == EVENT_HEADER_FLAG_64_BIT_HEADER {
            size_of::<u64>()
        }
        else {
            log::warn!("Unknown pointer size");
            size_of::<usize>()
        }
    }

    #[inline]
    pub fn is_wpp_event(&self) -> bool {
        (u32::from(self.0.EventHeader.Flags) & EVENT_HEADER_FLAG_TRACE_MESSAGE) == EVENT_HEADER_FLAG_TRACE_MESSAGE
    }

    #[inline]
    pub fn is_string_event(&self) -> bool {
        (u32::from(self.0.EventHeader.Flags) & EVENT_HEADER_FLAG_STRING_ONLY) == EVENT_HEADER_FLAG_STRING_ONLY
    }

    #[inline]
    pub fn provider_guid(&self) -> GUID {
        self.0.EventHeader.ProviderId
    }

    #[inline]
    pub fn event_id(&self) -> u16 {
        self.0.EventHeader.EventDescriptor.Id
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Version
    }

    #[inline]
    pub fn userdata(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.0.UserData as *const u8, self.0.UserDataLength.into())
        }
    }
}
