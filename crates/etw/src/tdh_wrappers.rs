pub use windows::core::GUID;
use windows::{
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, WIN32_ERROR},
        System::Diagnostics::Etw::{
            DecodingSourceTlg, DecodingSourceWPP, DecodingSourceWbem, DecodingSourceXMLFile, EventChannelInformation, EventKeywordInformation, EventLevelInformation, EventOpcodeInformation, EventTaskInformation, TdhEnumerateManifestProviderEvents, TdhEnumerateProviderFieldInformation, TdhEnumerateProviders, TdhGetEventInformation, TdhGetEventMapInformation, TdhGetManifestEventInformation, DECODING_SOURCE, EVENT_DESCRIPTOR, EVENT_FIELD_TYPE, EVENT_MAP_ENTRY, EVENT_MAP_INFO, EVENT_PROPERTY_INFO, EVENT_RECORD, PROVIDER_ENUMERATION_INFO, PROVIDER_EVENT_INFO, PROVIDER_FIELD_INFO, PROVIDER_FIELD_INFOARRAY, TRACE_EVENT_INFO, TRACE_PROVIDER_INFO
        },
    },
};

use std::{fmt, mem, slice};
use std::os::windows::ffi::OsStringExt;
use std::{ffi, mem::size_of};

use crate::schema::{in_type::InType, out_type::OutType};

// So that we can use usize::try_from(val).unwrap() and be sure it doesn't
// panic at runtime.
static_assertions::const_assert!(size_of::<usize>() >= size_of::<u32>());

const ERROR_NOT_SUPPORTED: WIN32_ERROR = WIN32_ERROR(50);

pub struct Providers {
    buffer: Vec<u8>,
}

impl Providers {
    pub fn new() -> windows::core::Result<Providers> {
        let mut buffer_size = 0;

        unsafe {
            let status = TdhEnumerateProviders(None, &mut buffer_size);
            if WIN32_ERROR(status) != ERROR_INSUFFICIENT_BUFFER {
                return Err(WIN32_ERROR(status).into());
            }

            let mut buffer = vec![0u8; usize::try_from(buffer_size).unwrap()];
            HRESULT::from_win32(TdhEnumerateProviders(
                Some(buffer.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO),
                &mut buffer_size,
            ))
            .ok()?;

            Ok(Providers { buffer })
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = Provider> {
        (0..self.data().NumberOfProviders).map(|idx| Provider {
            providers: self,
            info: unsafe {
                // Have to jump through some hoops to get around the
                // "fixed array of size one" that's actually a variable-sized array
                self.data()
                .TraceProviderInfoArray
                .as_ptr()
                .add(usize::try_from(idx).unwrap())
                .as_ref()
                .unwrap() },
        })
    }

    pub fn data(&self) -> &PROVIDER_ENUMERATION_INFO {
        unsafe {
            (self.buffer.as_ptr() as *const PROVIDER_ENUMERATION_INFO)
                .as_ref()
                .unwrap()
        }
    }

    pub fn len(&self) -> usize {
        usize::try_from(self.data().NumberOfProviders).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&TRACE_PROVIDER_INFO> {
        self.data().TraceProviderInfoArray.get(index)
    }
}

pub struct Provider<'a> {
    providers: &'a Providers,
    info: &'a TRACE_PROVIDER_INFO,
}

#[derive(Debug)]
pub enum SchemaSource {
    Xml,
    WmiMof,
    Unknown(u32),
}

impl From<u32> for SchemaSource {
    fn from(val: u32) -> Self {
        match val {
            0 => Self::Xml,
            1 => Self::WmiMof,
            _ => Self::Unknown(val),
        }
    }
}

impl From<SchemaSource> for u32 {
    fn from(value: SchemaSource) -> Self {
        match value {
            SchemaSource::Xml => 0,
            SchemaSource::WmiMof => 1,
            SchemaSource::Unknown(val) => val,
        }
    }
}

impl Provider<'_> {
    pub fn guid(&self) -> GUID {
        self.info.ProviderGuid
    }

    pub fn name(&self) -> ffi::OsString {
        unsafe {
            let name_ptr = self
                .providers
                .buffer
                .as_ptr()
                .offset(self.info.ProviderNameOffset.try_into().unwrap())
                as *const u16;
            let bytes = (0..)
                .map(|offset| *name_ptr.offset(offset))
                .take_while(|c| *c != 0)
                .collect::<Vec<_>>();
            ffi::OsString::from_wide(&bytes)
        }
    }

    pub fn schema_source(&self) -> SchemaSource {
        SchemaSource::from(self.info.SchemaSource)
    }

    pub fn event_descriptors(&self) -> windows::core::Result<ProviderEventDescriptors>  {
        ProviderEventDescriptors::new(&self.guid())
    }
}

impl fmt::Debug for Provider<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider")
            .field("guid", &self.guid())
            .field("name", &self.name())
            .field("schema_source", &self.schema_source())
            .finish()
    }
}

pub struct ProviderEventDescriptors {
    buffer: Vec<u8>,
    guid: GUID,
}

impl ProviderEventDescriptors {
    pub fn new(provider: &GUID) -> windows::core::Result<ProviderEventDescriptors> {
        unsafe {
            let mut buffer_size = 0;
            let status = WIN32_ERROR(TdhEnumerateManifestProviderEvents(provider, None, &mut buffer_size));
            if status != ERROR_INSUFFICIENT_BUFFER {
                return Err(status.into());
            }

            let mut buffer = vec![0u8; buffer_size.try_into().unwrap()];

            WIN32_ERROR(TdhEnumerateManifestProviderEvents(
                provider,
                Some(buffer.as_mut_ptr() as *mut PROVIDER_EVENT_INFO),
                &mut buffer_size,
            )).ok()?;
            Ok(ProviderEventDescriptors {
                buffer,
                guid: *provider,
            })
        }
    }

    pub fn data(&self) -> &PROVIDER_EVENT_INFO {
        unsafe {
            (self.buffer.as_ptr() as *const PROVIDER_EVENT_INFO)
                .as_ref()
                .unwrap()
        }
    }

    pub fn len(&self) -> usize {
        self.data().NumberOfEvents.try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&EVENT_DESCRIPTOR> {
        self.data().EventDescriptorsArray.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = EventDescriptor> {
        (0..self.len()).map(|idx| EventDescriptor {
            events: self,
            info: unsafe {
                self.data()
                .EventDescriptorsArray
                .as_ptr()
                .add(idx)
                .as_ref()
                .unwrap()},
        })
    }

    pub fn get_id_version(&self, event_id: u16, version: u8) -> Option<EventDescriptor> {
        self.iter()
            .find(|evt_desc| evt_desc.id() == event_id && evt_desc.version() == version)
    }
}

pub struct EventDescriptor<'a> {
    info: &'a EVENT_DESCRIPTOR,
    events: &'a ProviderEventDescriptors,
}

impl<'a> EventDescriptor<'a> {
    pub fn id(&self) -> u16 {
        self.info.Id
    }

    pub fn version(&self) -> u8 {
        self.info.Version
    }

    pub fn channel(&self) -> u8 {
        self.info.Channel
    }

    pub fn level(&self) -> u8 {
        self.info.Level
    }

    pub fn opcode(&self) -> u8 {
        self.info.Opcode
    }

    pub fn task(&self) -> u16 {
        self.info.Task
    }

    pub fn keyword(&self) -> u64 {
        self.info.Keyword
    }

    pub fn manifest_information(&self) -> windows::core::Result<TraceEventInfo> {
        TraceEventInfo::from_provider_guid(&self.events.guid, self.info)
    }

    pub fn data(&self) -> &EVENT_DESCRIPTOR {
        self.info
    }
}

impl fmt::Debug for EventDescriptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventDescriptor")
            .field("id", &self.id())
            .field("version", &self.version())
            .field("channel", &self.channel())
            .field("level", &self.level())
            .field("opcode", &self.opcode())
            .field("task", &self.task())
            .field("keyword", &self.keyword())
            .field("manifest_information", &self.manifest_information())
            .finish()
    }
}

#[derive(Debug)]
pub enum ValueSource {
    Constant(u64),
    Reference(Box<EventPropertyInfo>),
}

pub struct TraceEventInfo {
    buffer: Vec<u8>,
}

impl TraceEventInfo {
    pub fn from_event(event: &EVENT_RECORD) -> windows::core::Result<TraceEventInfo> {
        unsafe {
            let mut buffersize = 0;
            let status = TdhGetEventInformation(event, None, None, &mut buffersize);
            if WIN32_ERROR(status) != ERROR_SUCCESS
                && WIN32_ERROR(status) != ERROR_INSUFFICIENT_BUFFER
            {
                return Err(WIN32_ERROR(status).into());
            }

            let mut buffer = vec![0u8; buffersize.try_into().unwrap()];
            HRESULT::from_win32(TdhGetEventInformation(
                event,
                None,
                Some(buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO),
                &mut buffersize,
            ))
            .ok()?;

            Ok(TraceEventInfo { buffer })
        }
    }

    pub fn from_provider_guid(provider_guid: &GUID, event_descriptor: &EVENT_DESCRIPTOR) -> windows::core::Result<TraceEventInfo> {
        unsafe {
            let mut buffer_size = 0;
            match HRESULT::from_win32(TdhGetManifestEventInformation(
                provider_guid,
                event_descriptor,
                None,
                &mut buffer_size,
            ))
            {
                err if err == HRESULT::from(ERROR_SUCCESS) => (),
                err if err == HRESULT::from(ERROR_INSUFFICIENT_BUFFER) => (),
                err => return Err(err.into()),
            }

            let mut buffer = vec![0u8; buffer_size.try_into().unwrap()];

            HRESULT::from_win32(TdhGetManifestEventInformation(
                provider_guid,
                event_descriptor,
                Some(buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO),
                &mut buffer_size,
            )).ok()?;
            Ok(TraceEventInfo { buffer })
        }
    }

    #[inline]
    pub fn data(&self) -> &TRACE_EVENT_INFO {
        unsafe {
            (self.buffer.as_ptr() as *const TRACE_EVENT_INFO)
                .as_ref()
                .unwrap()
        }
    }

    pub(crate) unsafe fn offset_string(&self, offset: u32, with_null_terminator: bool) -> Option<&[u16]> {
        // Unwrap is safe because we have a compile-time assert that size(u32) >= size(usize)
        let offset = usize::try_from(offset).unwrap();
        if offset == 0 {
            None
        } else {
            let string = &self.buffer[offset..];
            let mut end = string.chunks_exact(2).position(|chunk| chunk == [0, 0]);
            if with_null_terminator {
                end = end.map(|val| val + 1);
            }
            let end = end.map(|val| val * 2);
            let end = end.unwrap_or(string.len());

            let data = &string[ .. end];
            if mem::size_of_val(data) % mem::size_of::<u16>() != 0 {
                return None;
            }
            #[cfg(not(feature = "unchecked_cast"))]
            if mem::align_of_val(data) < mem::align_of::<u16>() {
                return None;
            }
            unsafe {
                return Some(slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / mem::size_of::<u16>()))
            }
        }
    }

    pub fn provider_guid(&self) -> GUID {
        self.data().ProviderGuid
    }

    pub fn event_guid(&self) -> GUID {
        self.data().EventGuid
    }

    pub fn event_id(&self) -> u16 {
        self.data().EventDescriptor.Id
    }

    pub fn event_version(&self) -> u8 {
        self.data().EventDescriptor.Version
    }

    pub fn event_descriptor(&self) -> crate::values::event::EventDescriptor {
        crate::values::event::EventDescriptor::from(&self.data().EventDescriptor)
    }

    pub fn decoding_source(&self) -> DecodingSource {
        DecodingSource::from(self.data().DecodingSource)
    }

    pub fn provider_name(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().ProviderNameOffset, with_null_terminator) }
    }

    pub fn level_name(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().LevelNameOffset, with_null_terminator) }
    }

    pub fn channel_name(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().ChannelNameOffset, with_null_terminator) }
    }

    pub fn keyword_name(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().KeywordsNameOffset, with_null_terminator) }
    }

    pub fn task_name(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().TaskNameOffset, with_null_terminator) }
    }

    pub fn event_name(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().Anonymous1.EventNameOffset, with_null_terminator) }
    }

    pub fn event_message(&self, with_null_terminator: bool) -> Option<&[u16]> {
        unsafe { self.offset_string(self.data().EventMessageOffset, with_null_terminator) }
    }

    pub fn property_count(&self) -> usize {
        self.data().PropertyCount.try_into().unwrap()
    }

    pub fn top_level_property_count(&self) -> usize {
        self.data().TopLevelPropertyCount.try_into().unwrap()
    }

    pub fn get_raw_property(&self, index: usize) -> Option<&EVENT_PROPERTY_INFO> {
        if index < self.property_count() {
            unsafe {
                Some(
                    self.data()
                    .EventPropertyInfoArray
                    .as_ptr()
                    .add(index)
                    .as_ref()
                    .unwrap()
                )
            }
        } else {
            None
        }
    }
}

impl fmt::Debug for TraceEventInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventManifestInformation")
            .field("provider_guid", &self.provider_guid())
            .field("event_guid", &self.event_guid())
            .field("decoding_source", &self.decoding_source())
            .field("provider_name", &self.provider_name(false))
            .field("level_name", &self.level_name(false))
            .field("channel_name", &self.channel_name(false))
            .field("keyword_name", &self.keyword_name(false))
            .field("task_name", &self.task_name(false))
            .field("event_name", &self.event_name(false))
            .field("event_message", &self.event_message(false))
            .finish()
    }
}

#[derive(Debug)]
pub enum DecodingSource {
    XMLFile,
    Wbem,
    WPP,
    Tlg,
}

impl From<DECODING_SOURCE> for DecodingSource {
    fn from(val: DECODING_SOURCE) -> Self {
        #[allow(non_upper_case_globals)]
        match val {
            DecodingSourceXMLFile => DecodingSource::XMLFile,
            DecodingSourceWbem => DecodingSource::Wbem,
            DecodingSourceWPP => DecodingSource::WPP,
            DecodingSourceTlg => DecodingSource::Tlg,
            _ => panic!("Unknown decoding source {}", val.0),
        }
    }
}

#[derive(Debug)]
pub enum EventPropertyInfo {
    StructType(Vec<EventPropertyInfo>),
    NonStructType {
        name: String,
        in_type: InType,
        out_type: OutType,
        map_name: Option<String>,
        length: ValueSource,
        count: ValueSource,
        is_array: bool,
    },
    CustomSchemaType {
        in_type: InType,
        out_type: OutType,
        custom_schema: Vec<u8>,
    },
}

#[derive(Debug, Copy, Clone)]
pub enum EventFieldType {
    KeywordInformation,
    LevelInformation,
    ChannelInformation,
    TaskInformation,
    OpcodeInformation,
}

impl EventFieldType {
    pub fn value(&self) -> EVENT_FIELD_TYPE {
        match self {
            EventFieldType::KeywordInformation => EventKeywordInformation,
            EventFieldType::LevelInformation => EventLevelInformation,
            EventFieldType::ChannelInformation => EventChannelInformation,
            EventFieldType::TaskInformation => EventTaskInformation,
            EventFieldType::OpcodeInformation => EventOpcodeInformation,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderFieldInformationError {
    #[error("Not Supported")]
    NotSupported,
}

pub struct ProviderFieldInformation {
    buffer: Vec<u8>,
}

impl ProviderFieldInformation {
    pub fn new(
        provider: &GUID,
        field_type: &EventFieldType,
    ) -> Result<ProviderFieldInformation, ProviderFieldInformationError> {
        unsafe {
            let mut buffer_size = 0;
            let status = TdhEnumerateProviderFieldInformation(
                provider,
                field_type.value(),
                None,
                &mut buffer_size,
            );
            let status = WIN32_ERROR(status);
            if status == ERROR_NOT_SUPPORTED {
                return Err(ProviderFieldInformationError::NotSupported);
            }
            assert_eq!(status, ERROR_INSUFFICIENT_BUFFER);
            let mut buffer = vec![0u8; buffer_size.try_into().unwrap()];

            let status = TdhEnumerateProviderFieldInformation(
                provider,
                field_type.value(),
                Some(buffer.as_mut_ptr() as *mut PROVIDER_FIELD_INFOARRAY),
                &mut buffer_size,
            );
            assert_eq!(WIN32_ERROR(status), ERROR_SUCCESS);
            Ok(ProviderFieldInformation { buffer })
        }
    }

    pub fn data(&self) -> &PROVIDER_FIELD_INFOARRAY {
        unsafe {
            (self.buffer.as_ptr() as *const PROVIDER_FIELD_INFOARRAY)
                .as_ref()
                .unwrap()
        }
    }

    pub fn len(&self) -> usize {
        self.data().NumberOfElements.try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, index: usize) -> Option<&PROVIDER_FIELD_INFO> {
        if index < self.len() {
            unsafe {
                Some(
                    self.data()
                    .FieldInfoArray
                    .as_ptr()
                    .add(index)
                    .as_ref()
                    .unwrap()
                )
            }
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = ProviderFieldInfo> {
        (0..self.len()).map(|idx| ProviderFieldInfo {
            field_info: self,
            info: self.data().FieldInfoArray.get(idx).unwrap(),
        })
    }
}

pub struct ProviderFieldInfo<'a> {
    info: &'a PROVIDER_FIELD_INFO,
    field_info: &'a ProviderFieldInformation,
}

impl ProviderFieldInfo<'_> {
    pub fn name(&self) -> ffi::OsString {
        unsafe {
            let name_ptr =
                self.field_info
                    .buffer
                    .as_ptr()
                    .offset(self.info.NameOffset.try_into().unwrap()) as *const u16;
            let bytes = (0..)
                .map(|offset| *name_ptr.offset(offset))
                .take_while(|c| *c != 0)
                .collect::<Vec<_>>();
            ffi::OsString::from_wide(&bytes)
        }
    }

    pub fn description(&self) -> ffi::OsString {
        unsafe {
            let name_ptr = self
                .field_info
                .buffer
                .as_ptr()
                .offset(self.info.DescriptionOffset.try_into().unwrap())
                as *const u16;
            let bytes = (0..)
                .map(|offset| *name_ptr.offset(offset))
                .take_while(|c| *c != 0)
                .collect::<Vec<_>>();
            ffi::OsString::from_wide(&bytes)
        }
    }

    pub fn value(&self) -> u64 {
        self.info.Value
    }
}

impl fmt::Debug for ProviderFieldInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderFieldInfo")
            .field("name", &self.name())
            .field("description", &self.description())
            .field("value", &self.value())
            .finish()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "GUID")]
struct GUIDDef {
    #[serde(getter = "GUID::to_u128")]
    value: u128,
}

impl From<GUIDDef> for GUID {
    fn from(d: GUIDDef) -> Self {
        GUID::from_u128(d.value)
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct EventInformation {
    #[serde(with = "GUIDDef")]
    pub provider_id: GUID,
    pub event_id: u16,
    pub opcode: u8,
    pub version: u8,
    pub level: u8,
    pub event_flags: u16,
    pub process_id: u32,
    pub thread_id: u32,
    #[serde(with = "GUIDDef")]
    pub activity_id: GUID,
    pub raw_timestamp: i64,
}

pub struct EventMapInfo {
    pub buffer: Vec<u8>,
}

impl EventMapInfo {
    pub fn from(map_name: &[u16], event_record: &EVENT_RECORD) -> windows::core::Result<EventMapInfo> {
        unsafe {
            let mut buffer_size = 0;
            match HRESULT::from_win32(TdhGetEventMapInformation(
                event_record,
                PCWSTR(map_name.as_ptr()),
                None,
                &mut buffer_size,
            ))
            {
                err if err == HRESULT::from(ERROR_SUCCESS) => (),
                err if err == HRESULT::from(ERROR_INSUFFICIENT_BUFFER) => (),
                err => return Err(err.into()),
            }

            let mut buffer = vec![0u8; buffer_size.try_into()?];
            HRESULT::from_win32(TdhGetEventMapInformation(
                event_record,
                PCWSTR(map_name.as_ptr()),
                Some(buffer.as_mut_ptr() as *mut _),
                &mut buffer_size,
            ))
            .ok()?;

            Ok(EventMapInfo { buffer })
        }
    }

    pub fn data(&self) -> &EVENT_MAP_INFO {
        unsafe {
            (self.buffer.as_ptr() as *const EVENT_MAP_INFO)
                .as_ref()
                .unwrap()
        }
    }

    pub fn get(&self, idx: usize) -> Option<&EVENT_MAP_ENTRY> {
        self.data().MapEntryArray.get(idx)
    }

    pub fn len(&self) -> usize {
        self.data().EntryCount.try_into().unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn offset_string(&self, offset: usize, with_null_terminator: bool) -> Option<&[u16]> {
        if offset == 0 {
            return None;
        }
        let data = &self.buffer[offset .. ];
        let mut size = data.chunks_exact(2).position(|chunk| chunk == [0, 0]);
        if with_null_terminator {
            size = size.map(|val| val + 1);
        };
        size = size.map(|val| val * 2);
        let size = size.unwrap_or(data.len() / 2 * 2);

        let data = &data[..size];

        #[cfg(not(feature = "unchecked_cast"))]
        if mem::align_of_val(data) < mem::align_of::<u16>() {
            return None;
        }

        unsafe {
            Some(slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / mem::size_of::<u16>()))
        }
    }
}

#[cfg(test)]
mod tests {
    use windows::core::GUID;

    use super::ProviderEventDescriptors;

    #[test] 
    fn test_microsoft_windows_dns_client_event_descriptor_3019_first_attribute_name() {
        let provider_guid = GUID::try_from("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D").unwrap();
        let event_descriptors = ProviderEventDescriptors::new(& provider_guid).unwrap();

        for event_descriptor in event_descriptors.iter() {
            if event_descriptor.id() != 3019 || event_descriptor.version() != 0 {
                continue;
            }

            todo!("Fix test")
            //if let Some(EventPropertyInfo::NonStructType{name, .. }) = event_descriptor.manifest_information().property_info().next() {
            //    assert_eq!(name, "QueryName");
            //}
            //else {
            //    assert!(false);
            //}
        }
    }
}