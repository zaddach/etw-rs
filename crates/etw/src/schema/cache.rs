use std::{collections::{hash_map::Entry, HashMap, HashSet}, slice, sync::{Arc, RwLock}};

use windows::{
    core::GUID,
    Win32::System::Diagnostics::Etw::{
        PropertyHasCustomSchema, PropertyParamCount, PropertyParamFixedCount, PropertyParamLength, PropertyStruct, EVENTMAP_ENTRY_VALUETYPE_STRING, EVENTMAP_ENTRY_VALUETYPE_ULONG, EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP, EVENT_PROPERTY_INFO, EVENT_RECORD, TDH_INTYPE_HEXINT32, TDH_INTYPE_UINT16, TDH_INTYPE_UINT32, TDH_INTYPE_UINT8, _TDH_IN_TYPE
    },
};

use crate::{
    error::{ParseError, TraceError}, tdh_wrappers::{EventMapInfo, TraceEventInfo}, values::{compound::{StringOrStruct, Struct, StructArray, StructOrValue}, event::{Event, EventRecord, Header}, in_value::InValue, value::Value}
};

use super::{in_type::InType, out_type::OutType};

pub struct SchemaCache {
    schemas: RwLock<HashMap<(GUID, u16, u8), Arc<EventInfo>>>,
}

impl SchemaCache {
    pub fn new() -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_from_event_record(&self, event_record: &EVENT_RECORD) -> Result<Arc<EventInfo>, TraceError> {
        let key = (
            event_record.EventHeader.ProviderId,
            event_record.EventHeader.EventDescriptor.Id,
            event_record.EventHeader.EventDescriptor.Version,
        );
        if let Ok(guard) = self.schemas.read() {
            if let Some(schema) = guard.get(&key) {
                return Ok(Arc::clone(schema));
            }
        }
        else {
            todo!("Mutex was poisoned");
        }
        if let Ok(mut guard) = self.schemas.write() {
            // Can't use .or_insert_with because errors cannot exit the closure 
            match guard.entry(key) {
                Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
                Entry::Vacant(entry) => {
                    let trace_event_info = TraceEventInfo::from_event(event_record)?; 
                    let cached_event_info = EventInfo::parse(&trace_event_info, Some(event_record))?;
                    log::trace!(
                        "Caching event info for {:?}:{}:{}: {:?}",
                        event_record.EventHeader.ProviderId,
                        event_record.EventHeader.EventDescriptor.Id,
                        event_record.EventHeader.EventDescriptor.Version,
                        &cached_event_info
                    );
                    Ok(Arc::clone(entry.insert(Arc::new(cached_event_info))))
                }
            }
        }
        else {
            todo!("Mutex was poisoned");
        }
    }

    pub fn get(&self, provider_id: GUID, event_id: u16, event_version: u8) -> Option<Arc<EventInfo>> {
        if let Ok(guard) = self.schemas.read() {
            guard.get(&(provider_id, event_id, event_version)).map(|v| Arc::clone(v))
        }
        else {
            log::warn!("mutex was poisoned");
            None
        }

    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum StringOrIntegerMap {
    Integer(HashMap<u32, String>),
    String(HashMap<String, String>),
}

impl StringOrIntegerMap {
    fn has_map_name(property: &EVENT_PROPERTY_INFO) -> bool {
        unsafe {
            if (property.Flags.0 & PropertyStruct.0) != 0 {
                return false;
            }
            property.Anonymous1.nonStructType.MapNameOffset != 0
        }
    }

    fn parse(trace_event_info: &TraceEventInfo, property: &EVENT_PROPERTY_INFO, event_record: &EVENT_RECORD) -> Result<(String, StringOrIntegerMap), ParseError> {
        unsafe {
            if (property.Flags.0 & PropertyStruct.0) != 0 {
                return Err(ParseError::InvalidType);
            }
            if property.Anonymous1.nonStructType.MapNameOffset == 0 {
                return Err(ParseError::NoMapName);
            }
            if ![
                    TDH_INTYPE_UINT8,
                    TDH_INTYPE_UINT16,
                    TDH_INTYPE_UINT32,
                    TDH_INTYPE_HEXINT32,
                ]
                .contains(&_TDH_IN_TYPE(i32::from(
                    property.Anonymous1.nonStructType.InType,
                )))
            {
                return Err(ParseError::InvalidType);
            }

            let map_name = trace_event_info.offset_string(
                    property.Anonymous1.nonStructType.MapNameOffset.try_into()?, 
                    true
                ).ok_or_else(|| ParseError::UnalignedData("MapNameOffset".to_string()))?;
            let map_name_without_nul = if map_name.last() == Some(&0) {
                &map_name[..map_name.len() - 1]
            } else {
                map_name
            };

            let event_map_info = EventMapInfo::from(map_name, event_record)?;
            let map_name = String::from_utf16(map_name_without_nul)?;

            if (event_map_info.data().Flag.0 & EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP.0)
                != 0
            {
                let format_string = event_map_info.offset_string(
                    event_map_info
                        .data()
                        .Anonymous
                        .FormatStringOffset
                        .try_into()?,
                    false,
                );
                let _format_string = format_string.map(|f| String::from_utf16(f)).transpose()?.unwrap_or("".to_string());

                log::warn!("Event provider {:?} id {} version {} - Manifest pattern map '{}' not implemented", event_record.EventHeader.ProviderId, event_record.EventHeader.EventDescriptor.Id, event_record.EventHeader.EventDescriptor.Version, map_name);
                Err(ParseError::NotImplemented)
            } else {
                match event_map_info.data().Anonymous.MapEntryValueType {
                    EVENTMAP_ENTRY_VALUETYPE_ULONG => {
                        let mut map = HashMap::new();
                        for idx in 0..event_map_info.len() {
                            if let Some(entry) = event_map_info.get(idx) {
                                let key = entry.Anonymous.Value;
                                let value = entry.OutputOffset;
                                let value = event_map_info
                                    .offset_string(value.try_into()?, false);
                                let value = value.map(|v| String::from_utf16(v)).transpose()?.unwrap_or("".to_string());
                                map.insert(key, value);
                            }
                        }

                        Ok((map_name, StringOrIntegerMap::Integer(map)))
                    },

                    EVENTMAP_ENTRY_VALUETYPE_STRING => {
                        let mut map = HashMap::new();
                        for idx in 0..event_map_info.len() {
                            if let Some(entry) = event_map_info.get(idx) {
                                let key = entry.Anonymous.InputOffset;
                                let key = event_map_info
                                    .offset_string(key.try_into()?, false);
                                let key = key.map(|k| String::from_utf16(k)).transpose()?.unwrap_or("".to_string());

                                let value = entry.OutputOffset;
                                let value = event_map_info
                                    .offset_string(value.try_into()?, false);
                                let value = value.map(|v| String::from_utf16(v)).transpose()?.unwrap_or("".to_string());
                                map.insert(key, value);
                            }
                        }

                        Ok((map_name, StringOrIntegerMap::String(map)))
                    },

                    _ => {
                        unreachable!("Event provider {:?} id {} version {} - In map '{}' unknown MAP_VALUETYPE {}", event_record.EventHeader.ProviderId, event_record.EventHeader.EventDescriptor.Id, event_record.EventHeader.EventDescriptor.Version, map_name, event_map_info.data().Anonymous.MapEntryValueType.0);
                    }
                }
            }
        }
    }
}
         
#[cfg_attr(feature = "serde", derive(Debug, serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct EventInfo {
    #[cfg_attr(feature = "serde", serde(serialize_with = "super::super::serde::guid::serialize", deserialize_with = "super::super::serde::guid::deserialize"))]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub provider_guid: GUID,
    pub event_id: u16,
    pub event_version: u8,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub properties: PropertyStructInfo,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "HashMap::is_empty"))]
    pub maps: HashMap<String, StringOrIntegerMap>,
}

impl EventInfo {
    pub fn parse(trace_event_info: &TraceEventInfo, event_record: Option<&EVENT_RECORD>) -> Result<Self, ParseError> {
        let mut length_count_properties = HashSet::new();
        let mut maps = HashMap::new();
        let provider_guid = trace_event_info.provider_guid();
        let event_id = trace_event_info.event_id();
        let event_version = trace_event_info.event_version();

        for idx in 0..trace_event_info.property_count() {
            let property =
                trace_event_info
                    .get_raw_property(idx)
                    .ok_or(ParseError::IndexOutOfBounds {
                        index: idx,
                        count: trace_event_info.property_count(),
                    })?;
            if (property.Flags.0 & PropertyParamLength.0) != 0 {
                unsafe {
                    length_count_properties
                        .insert(usize::from(property.Anonymous3.lengthPropertyIndex));
                }
            }
            if (property.Flags.0 & PropertyParamCount.0) != 0 {
                unsafe {
                    length_count_properties
                        .insert(usize::from(property.Anonymous2.countPropertyIndex));
                }
            }
            if let Some(event_record) = event_record
                && StringOrIntegerMap::has_map_name(property)
            {
                match StringOrIntegerMap::parse(trace_event_info, property, event_record) {
                    Ok((name, map)) => {
                        maps.insert(name, map);
                    },
                    Err(err) => {
                        log::warn!("Event provider {:?} id {} version {} - Error parsing map: {}", provider_guid, event_id, event_version, err);
                    }
                }
            }
        }

        Ok(Self {
            provider_guid,
            event_id,
            event_version,
            maps,
            properties: PropertyStructInfo::parse(
                &trace_event_info,
                &length_count_properties,
                0,
                trace_event_info.top_level_property_count(),
            )?,
        })
    }
}

impl EventInfo {
    pub fn decode<'b, 'c>(&self, event_record: &'b EVENT_RECORD) -> Result<Event<'c>, ParseError>
    where
        'b: 'c,
    {
        let _event = EventRecord(event_record);
        let mut length_count_values = HashMap::new();
        let userdata = unsafe {
            slice::from_raw_parts(
                event_record.UserData as *const u8,
                event_record.UserDataLength.into(),
            )
        };
        let (struc, remainder) = self.properties.decode(userdata, &mut length_count_values)?;
        if !remainder.is_empty() {
            log::warn!("Unused data after parsing event record");
        }

        Ok(Event {
            header: Header::from(&event_record.EventHeader),
            data: StringOrStruct::Struct(struc),
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum PropertyValue {
    Constant(usize),
    Reference(usize),
}

impl Default for PropertyValue {
    fn default() -> Self {
        Self::Constant(0)
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct PropertyInfo {
    pub length: PropertyValue,
    pub count: PropertyValue,
    pub is_array: bool,
    pub value: PropertyNestedInfo,
}

impl PropertyInfo {
    pub fn decode<'b>(
        &self,
        mut userdata: &'b [u8],
        length_count_values: &mut HashMap<usize, usize>,
    ) -> Result<(StructOrValue<'b>, &'b [u8]), ParseError> {
        let length = match self.length {
            PropertyValue::Constant(size) => size,
            PropertyValue::Reference(handle) => length_count_values
                .get(&handle)
                .copied()
                .ok_or_else(|| ParseError::InvalidPropertyReference(handle))?,
        };
        let count = match self.count {
            PropertyValue::Constant(size) => size,
            PropertyValue::Reference(handle) => length_count_values
                .get(&handle)
                .copied()
                .ok_or_else(|| ParseError::InvalidPropertyReference(handle))?,
        };
        match self.value {
            PropertyNestedInfo::Struct(ref _name, ref struct_info) => {
                let mut array_members = Vec::with_capacity(count);

                for _ in 0..count {
                    let (struc, remaining) = struct_info.decode(userdata, length_count_values)?;
                    userdata = remaining;
                    array_members.push(struc);
                }

                Ok((
                    StructOrValue::Struct(StructArray {
                        values: array_members,
                        is_array: self.is_array,
                    }),
                    userdata,
                ))
            }
            PropertyNestedInfo::Value(ref _name, ref value_info) => {
                log::trace!("Decoding value type {:?}, length {:?}, count {:?}, is_array {:?}, {} bytes remaining", value_info.in_type, length, count, self.is_array, userdata.len());
                let (value, remaining) = value_info.decode(
                    userdata,
                    length_count_values,
                    length,
                    count,
                    self.is_array,
                )?;
                userdata = remaining;
                Ok((StructOrValue::Value(value), userdata))
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct PropertyStructInfo {
    pub fields: Vec<PropertyInfo>,
}

impl PropertyStructInfo {
    pub fn parse(
        trace_event_info: &TraceEventInfo,
        length_count_properties: &HashSet<usize>,
        prop_begin: usize,
        prop_end: usize,
    ) -> Result<Self, ParseError> {
        let mut fields = Vec::with_capacity(prop_end - prop_begin);

        for idx in prop_begin..prop_end {
            let property = trace_event_info.get_raw_property(idx).ok_or_else(|| {
                ParseError::IndexOutOfBounds {
                    index: idx,
                    count: trace_event_info.property_count(),
                }
            })?;

            unsafe {
                let name = trace_event_info.offset_string(property.NameOffset, false).map(String::from_utf16).transpose()?.unwrap_or(format!("_unknown_property_{}", idx));
                let size: PropertyValue = if (property.Flags.0 & PropertyParamLength.0) != 0 {
                    PropertyValue::Reference(usize::from(
                        property.Anonymous3.lengthPropertyIndex,
                    ))
                } else {
                    PropertyValue::Constant(usize::from(property.Anonymous3.length))
                };

                let count = if (property.Flags.0 & PropertyParamCount.0) != 0 {
                    PropertyValue::Reference(usize::from(
                        property.Anonymous2.countPropertyIndex,
                    ))
                } else {
                    PropertyValue::Constant(usize::from(property.Anonymous2.count))
                };

                let is_array =
                    (property.Flags.0 & (PropertyParamCount.0 | PropertyParamFixedCount.0)) != 0;

                let value = if (property.Flags.0 & PropertyStruct.0) != 0 {
                    let prop_begin = usize::from(property.Anonymous1.structType.StructStartIndex);
                    let prop_end =
                        prop_begin + usize::from(property.Anonymous1.structType.NumOfStructMembers);

                    PropertyNestedInfo::Struct(
                        name, 
                        PropertyStructInfo::parse(
                            trace_event_info,
                            length_count_properties,
                            prop_begin,
                            prop_end,
                        )?,
                    )
                } else if (property.Flags.0 & PropertyHasCustomSchema.0) != 0 {
                    todo!()
                } else {
                    let map_name_offset = property.Anonymous1.nonStructType.MapNameOffset;
                    let map_name = trace_event_info.offset_string(map_name_offset, false).map(String::from_utf16).transpose()?;
                    PropertyNestedInfo::Value(
                        name,
                        PropertyValueInfo {
                            in_type: InType::from(property.Anonymous1.nonStructType.InType),
                            out_type: OutType::from(property.Anonymous1.nonStructType.OutType),
                            map_name,
                            handle: length_count_properties.contains(&idx).then_some(idx),
                        },
                    )
                };

                let field = PropertyInfo {
                    length: size,
                    count,
                    is_array,
                    value,
                };
                fields.push(field);
            }
        }

        Ok(Self { fields })
    }

    pub fn decode<'b>(
        &self,
        mut userdata: &'b [u8],
        length_count_values: &mut HashMap<usize, usize>,
    ) -> Result<(Struct<'b>, &'b [u8]), ParseError> {
        let mut values = Vec::with_capacity(self.fields.len());

        for field in &self.fields {
            let (value, remaining) = field.decode(userdata, length_count_values)?;
            userdata = remaining;
            values.push(value);
        }

        Ok((Struct { values }, userdata))
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub enum PropertyNestedInfo {
    Struct(String, PropertyStructInfo),
    Value(String, PropertyValueInfo),
}

impl PropertyNestedInfo {
    pub fn name(&self) -> &str {
        match self {
            Self::Struct(name, _) => name,
            Self::Value(name, _) => name,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct PropertyValueInfo {
    pub in_type: InType,
    pub out_type: OutType,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub map_name: Option<String>,
    /// If this property is referenced by another (for a length or count), store the index here so that we can create a lookup table while parsing
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub handle: Option<usize>,
}

impl PropertyValueInfo {
    pub fn decode<'b>(
        &self,
        userdata: &'b [u8],
        length_count_values: &mut HashMap<usize, usize>,
        length: usize,
        count: usize,
        is_array: bool,
    ) -> Result<(Value<'b>, &'b [u8]), ParseError> {
        let (value, remainder) = Value::parse(userdata, self.in_type, length, count, is_array)?;
        if let Some(handle) = self.handle {
            if count != 1 || value.is_array() {
                return Err(ParseError::PropertySizeNotAScalar);
            }
            let int_value = match &value.value {
                InValue::UInt8(val) => usize::from(val.get(0).unwrap()),
                InValue::UInt16(val) => usize::from(val.get(0).unwrap()),
                InValue::UInt32(val) => val.get(0).unwrap().try_into()?,
                InValue::HexInt32(val) => val.get(0).unwrap().try_into()?,
                _ => return Err(ParseError::InvalidPropertySizeType(self.in_type)),
            };
            length_count_values.insert(handle, int_value);
        }
        Ok((value, remainder))
    }
}


#[cfg(test)]
mod tests {
    use std::{collections::HashMap, mem::size_of, slice, sync::Arc};

    use windows::{core::GUID, Win32::System::Diagnostics::Etw::{EVENT_HEADER, EVENT_PROPERTY_INFO, EVENT_RECORD, PropertyStruct}};

    use crate::{
        error::ParseError,
        schema::{in_type::InType, out_type::OutType},
        tdh_wrappers::ProviderEventDescriptors,
        values::{compound::{StringOrStruct, StructOrValue}, in_value::InValue, value::Value},
    };

    use super::{
        EventInfo, PropertyInfo, PropertyNestedInfo, PropertyStructInfo, PropertyValue, PropertyValueInfo, SchemaCache, StringOrIntegerMap,
    };

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even number of digits");
        (0..hex.len())
            .step_by(2)
            .map(|idx| u8::from_str_radix(&hex[idx..idx + 2], 16).unwrap())
            .collect()
    }

    fn event_record_from_hex(header_hex: &str, userdata_hex: &str) -> (EVENT_RECORD, Vec<u8>) {
        let header = decode_hex(header_hex);
        assert_eq!(header.len(), size_of::<EVENT_HEADER>());

        let mut userdata = decode_hex(userdata_hex);
        let mut event_record = unsafe { std::mem::zeroed::<EVENT_RECORD>() };

        unsafe {
            std::ptr::copy_nonoverlapping(
                header.as_ptr(),
                &mut event_record.EventHeader as *mut EVENT_HEADER as *mut u8,
                header.len(),
            );
        }

        event_record.UserDataLength = userdata.len().try_into().unwrap();
        event_record.UserData = userdata.as_mut_ptr() as *mut _;

        (event_record, userdata)
    }

    fn kernel_process_v4_schema() -> EventInfo {
        let provider_guid = GUID::try_from("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716").unwrap();
        let event_descriptors = ProviderEventDescriptors::new(&provider_guid).unwrap();
        let event_descriptor = event_descriptors.get_id_version(1, 4).unwrap();
        let trace_event_info = event_descriptor.manifest_information().unwrap();
        EventInfo::parse(&trace_event_info, None).unwrap()
    }

    fn assert_kernel_process_v4_sample_parses(
        schema: &EventInfo,
        header_hex: &str,
        userdata_hex: &str,
        expected_image_name: &str,
    ) {
        let (event_record, _userdata) = event_record_from_hex(header_hex, userdata_hex);
        assert_eq!(
            event_record.EventHeader.ProviderId,
            GUID::try_from("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716").unwrap()
        );
        assert_eq!(event_record.EventHeader.EventDescriptor.Id, 1);
        assert_eq!(event_record.EventHeader.EventDescriptor.Version, 4);

        let userdata = unsafe {
            slice::from_raw_parts(
                event_record.UserData as *const u8,
                event_record.UserDataLength.into(),
            )
        };
        let mut length_count_values = HashMap::new();
        let (struc, remainder) = schema
            .properties
            .decode(userdata, &mut length_count_values)
            .unwrap();
        assert!(
            remainder.is_empty(),
            "event for '{expected_image_name}' left {} trailing bytes",
            remainder.len()
        );
        assert_eq!(struc.values.len(), 16);

        let StructOrValue::Value(Value {
            value: InValue::UnicodeString(strings),
            ..
        }) = &struc.values[10]
        else {
            panic!("Expected ImageName to decode as a Unicode string");
        };
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].to_string(), expected_image_name);
    }

    #[test]
    fn test_decode_u8_scalar() {
        let data = [42u8];
        let decoder = PropertyInfo {
            length: PropertyValue::Constant(1),
            count: PropertyValue::Constant(1),
            is_array: false,
            value: PropertyNestedInfo::Value(
                "test".to_string(),
                PropertyValueInfo {
                    in_type: InType::UInt8,
                    out_type: OutType::Byte,
                    map_name: None,
                    handle: None,
                },
            ),
        };
        let mut length_count_values: HashMap<usize, usize> = std::collections::HashMap::new();
        let (value, remaining) = decoder.decode(&data, &mut length_count_values).unwrap();
        assert_eq!(remaining, &[] as &[u8]);
        let StructOrValue::Value(Value {
            raw,
            is_array,
            value: InValue::UInt8(val),
        }) = value
        else {
            panic!("Expected UInt8, got {:?}", value);
        };
        assert_eq!(val.get(0), Some(42));
        assert_eq!(val.len(), 1);
        assert_eq!(raw, &data);
        assert_eq!(is_array, false);
    }

    #[test]
    fn test_decode_u32_scalar() {
        let data = [0x40u8, 0x41u8, 0x42u8, 0x43u8];
        let decoder = PropertyInfo {
            length: PropertyValue::Constant(size_of::<u32>()),
            count: PropertyValue::Constant(1),
            is_array: false,
            value: PropertyNestedInfo::Value(
                "test".to_string(),
                PropertyValueInfo {
                    in_type: InType::UInt32,
                    out_type: OutType::Int,
                    map_name: None,
                    handle: None,
                },
            ),
        };
        let mut length_count_values: HashMap<usize, usize> = std::collections::HashMap::new();
        let (value, remaining) = decoder.decode(&data, &mut length_count_values).unwrap();
        assert_eq!(remaining, &[] as &[u8]);
        let StructOrValue::Value(Value {
            raw,
            is_array,
            value: InValue::UInt32(val),
        }) = value
        else {
            panic!("Expected UInt32, got {:?}", value);
        };
        assert_eq!(val.get(0), Some(0x43424140));
        assert_eq!(val.len(), 1);
        assert_eq!(raw, &data);
        assert_eq!(is_array, false);
    }

    #[test]
    fn test_decode_u32_array() {
        let data = [
            0x40u8, 0x41u8, 0x42u8, 0x43u8, 0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x20u8, 0x21u8, 0x22u8,
            0x23u8,
        ];
        let decoder = PropertyInfo {
            length: PropertyValue::Constant(size_of::<u32>()),
            count: PropertyValue::Constant(3),
            is_array: false,
            value: PropertyNestedInfo::Value(
                "test".to_string(),
                PropertyValueInfo {
                    in_type: InType::UInt32,
                    out_type: OutType::Int,
                    map_name: None,
                    handle: None,
                },
            ),
        };
        let mut length_count_values: HashMap<usize, usize> = std::collections::HashMap::new();
        let (value, remaining) = decoder.decode(&data, &mut length_count_values).unwrap();
        assert_eq!(remaining, &[] as &[u8]);
        let StructOrValue::Value(Value {
            raw,
            is_array,
            value: InValue::UInt32(val),
        }) = value
        else {
            panic!("Expected UInt32, got {:?}", value);
        };
        assert_eq!(val.get(0), Some(0x43424140));
        assert_eq!(val.get(1), Some(0x33323130));
        assert_eq!(val.get(2), Some(0x23222120));
        assert_eq!(val.len(), 3);
        assert_eq!(raw, &data);
        assert_eq!(is_array, false);
    }

    #[test]
    fn test_u32_scalar_wrong_size() {
        let data = [0x40u8, 0x41u8, 0x42u8, 0x43u8];
        let decoder = PropertyInfo {
            length: PropertyValue::Constant(2),
            count: PropertyValue::Constant(1),
            is_array: false,
            value: PropertyNestedInfo::Value(
                "test".to_string(),
                PropertyValueInfo {
                    in_type: InType::UInt32,
                    out_type: OutType::Int,
                    map_name: None,
                    handle: None,
                },
            ),
        };
        let mut length_count_values: HashMap<usize, usize> = std::collections::HashMap::new();
        let ParseError::UnexpectedSize =
            decoder.decode(&data, &mut length_count_values).unwrap_err()
        else {
            panic!("Expected ParseError::UnexpectedSize");
        };
    }

    #[test]
    fn test_string_or_integer_map_has_no_map_name_for_zero_offset() {
        let property = unsafe { std::mem::zeroed::<EVENT_PROPERTY_INFO>() };
        assert!(!StringOrIntegerMap::has_map_name(&property));
    }

    #[test]
    fn test_string_or_integer_map_has_no_map_name_for_struct_property() {
        let mut property = unsafe { std::mem::zeroed::<EVENT_PROPERTY_INFO>() };
        property.Flags = PropertyStruct;
        assert!(!StringOrIntegerMap::has_map_name(&property));
    }

    #[test]
    fn test_schema_cache_keys_by_event_version() {
        let provider_guid = GUID::try_from("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716").unwrap();
        let cache = SchemaCache::new();
        let schema_v1 = Arc::new(EventInfo {
            provider_guid,
            event_id: 1,
            event_version: 1,
            properties: PropertyStructInfo { fields: Vec::new() },
            maps: HashMap::new(),
        });
        let schema_v4 = Arc::new(EventInfo {
            provider_guid,
            event_id: 1,
            event_version: 4,
            properties: PropertyStructInfo { fields: Vec::new() },
            maps: HashMap::new(),
        });

        cache
            .schemas
            .write()
            .unwrap()
            .insert((provider_guid, 1, 1), Arc::clone(&schema_v1));
        cache
            .schemas
            .write()
            .unwrap()
            .insert((provider_guid, 1, 4), Arc::clone(&schema_v4));

        assert!(Arc::ptr_eq(&cache.get(provider_guid, 1, 1).unwrap(), &schema_v1));
        assert!(Arc::ptr_eq(&cache.get(provider_guid, 1, 4).unwrap(), &schema_v4));
        assert!(cache.get(provider_guid, 1, 0).is_none());
    }

    #[test]
    fn test_decode_kernel_process_v4_event_with_mandatory_label_sid() {
        const HEADER_HEX: &str =
            "0a01000040020000d80c000028060000ddb0b7dcb2d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000";
        const USERDATA_HEX: &str =
            "281900006502000000000000e5aab7dcb2d0dc01280600001b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c007400610073006b0068006f007300740077002e006500780065000000b32f0200af9c8bb40000000000000000";

        let (event_record, _userdata) = event_record_from_hex(HEADER_HEX, USERDATA_HEX);
        let provider_guid = GUID::try_from("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716").unwrap();
        assert_eq!(event_record.EventHeader.ProviderId, provider_guid);
        assert_eq!(event_record.EventHeader.EventDescriptor.Id, 1);
        assert_eq!(event_record.EventHeader.EventDescriptor.Version, 4);

        let event_descriptors = ProviderEventDescriptors::new(&provider_guid).unwrap();
        let event_descriptor = event_descriptors.get_id_version(1, 4).unwrap();
        let trace_event_info = event_descriptor.manifest_information().unwrap();
        let schema = EventInfo::parse(&trace_event_info, None).unwrap();
        let event = schema.decode(&event_record).unwrap();

        let StringOrStruct::Struct(struc) = &event.data else {
            panic!("Expected a structured event payload");
        };
        assert_eq!(struc.values.len(), 16);

        let StructOrValue::Value(Value {
            value: InValue::Sid(sids),
            ..
        }) = &struc.values[9]
        else {
            panic!("Expected MandatoryLabel to decode as a SID");
        };
        assert_eq!(sids.len(), 1);
        assert!(sids[0].is_valid());

        let StructOrValue::Value(Value {
            value: InValue::UnicodeString(strings),
            ..
        }) = &struc.values[10]
        else {
            panic!("Expected ImageName to decode as a Unicode string");
        };
        assert_eq!(strings.len(), 1);
        assert_eq!(
            strings[0].to_string(),
            r"\Device\HarddiskVolume3\Windows\System32\taskhostw.exe"
        );
    }

    #[test]
    fn test_decode_kernel_process_v4_log_samples_parse_fully() {
        let schema = kernel_process_v4_schema();
        let samples = [
            (
                "4e01000040020000d80c000028060000d0121fe5b8d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "b0280000660200000000000016101fe5b8d0dc01280600001b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00500072006f006700720061006d002000460069006c00650073002000280078003800360029005c004d006900630072006f0073006f00660074005c0045006400670065005500700064006100740065005c004d006900630072006f0073006f006600740045006400670065005500700064006100740065002e006500780065000000326c03004d3ad7690000000000000000",
                r"\Device\HarddiskVolume3\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            ),
            (
                "0a01000040020000241e000028060000428c1fe5b8d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "002600006702000000000000ee891fe5b8d0dc01280600001b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c007400610073006b0068006f007300740077002e006500780065000000b32f0200af9c8bb40000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\taskhostw.exe",
            ),
            (
                "b601000040020000682a00003c020000c98661e5b8d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080010000000000000000000000000000000000000000000000",
                "080500006802000000000000bd8461e5b8d0dc013c0200000d00000000000000020000000300000001000000010000000101000000000010001000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c006200610063006b00670072006f0075006e0064005400610073006b0048006f00730074002e0065007800650000001d9e01006314c65b4d006900630072006f0073006f00660074002e004100410044002e00420072006f006b006500720050006c007500670069006e005f0031003000300030002e00310039003500380030002e0031003000300030002e0032005f006e00650075007400720061006c005f006e00650075007400720061006c005f006300770035006e003100680032007400780079006500770079000000410070007000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\backgroundTaskHost.exe",
            ),
            (
                "ee01000040020000682a00003c020000546c74e5b8d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080020000000000000000000000000000000000000000000000",
                "9c2500006902000000000000bf6474e5b8d0dc013c0200000d00000000000000020000000300000001000000010000000101000000000010003000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c00520075006e00740069006d006500420072006f006b00650072002e006500780065000000277b0200e3ad5db94d006900630072006f0073006f00660074002e004100410044002e00420072006f006b006500720050006c007500670069006e005f0031003000300030002e00310039003500380030002e0031003000300030002e0032005f006e00650075007400720061006c005f006e00650075007400720061006c005f006300770035006e003100680032007400780079006500770079000000720075006e00740069006d006500620072006f006b006500720030003700660034003300350038006100380030003900610063003900390061003600340061003600370063003100000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe",
            ),
            (
                "3a01000040020000b80400009c0d0000e3a58ae5b8d0dc01d62cfb227b0e2b42a0c72fad1fd0e716010004100401010010000000000000800a0000000600000000000000000000000000000000000000",
                "882200006a02000000000000c6a18ae5b8d0dc019c0d00009b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c005500550053005c005000610063006b0061006700650073005c0050007200650076006900650077005c0061006d006400360034005c004d006f00550073006f0043006f007200650057006f0072006b00650072002e0065007800650000000e695700f5c381d30000000001000000",
                r"\Device\HarddiskVolume3\Windows\UUS\Packages\Preview\amd64\MoUsoCoreWorker.exe",
            ),
            (
                "06010000400200007c2a00008c03000039bd95e5b8d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "f41100006b020000000000003bba95e5b8d0dc018c0300000b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073007600630068006f00730074002e006500780065000000d65702001739e4970000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
            ),
            (
                "1201000040020000c41900003c020000f38c6503b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000200000000000000000000000000000000000000",
                "4004000079020000000000000a8b6503b9d0dc013c0200000d00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c007700620065006d005c0057006d006900500072007600530045002e0065007800650000007b7d08004cc8dfe30000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\wbem\WmiPrvSE.exe",
            ),
            (
                "00010000400200004c270000140200001186de02b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "741c00007102000000000000e583de02b9d0dc01140200000300000000000000030000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073006d00730073002e006500780065000000e26d0400aeb62dae0000000001000000",
                r"\Device\HarddiskVolume3\Windows\System32\smss.exe",
            ),
            (
                "0201000040020000141b0000741c000031f3df02b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "10280000720200000000000005f1df02b9d0dc01741c00007102000000000000030000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c00630073007200730073002e00650078006500000026b200006a6006690000000001000000",
                r"\Device\HarddiskVolume3\Windows\System32\csrss.exe",
            ),
            (
                "0801000040020000141b0000741c0000c864e402b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "0001000073020000000000008162e402b9d0dc01741c00007102000000000000030000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c00770069006e006c006f0067006f006e002e0065007800650000004c420f009206a6490000000001000000",
                r"\Device\HarddiskVolume3\Windows\System32\winlogon.exe",
            ),
            (
                "0801000040020000c80100008c030000ceab3703b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080010000000000000000000000000000000000000000000000",
                "bc1f0000740200000000000002aa3703b9d0dc018c0300000b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c00570055004400460048006f00730074002e006500780065000000005d060049fe50110000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\WUDFHost.exe",
            ),
            (
                "0e010000400200001c16000000010000537a4103b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080010000000000000000000000000000000000000000000000",
                "38250000750200000000000004774103b9d0dc01000100007302000000000000030000000000000001000000000000000101000000000010001000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0066006f006e00740064007200760068006f00730074002e006500780065000000ec290d00442d962a0000000001000000",
                r"\Device\HarddiskVolume3\Windows\System32\fontdrvhost.exe",
            ),
            (
                "0601000040020000c81d000000010000168a4503b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080050000000000000000000000000000000000000000000000",
                "ac2b000076020000000000007a874503b9d0dc01000100007302000000000000030000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c004c006f0067006f006e00550049002e006500780065000000e3400100b4aedc0a0000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\LogonUI.exe",
            ),
            (
                "fe00000040020000b4100000000100005ffb4503b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080010000000000000000000000000000000000000000000000",
                "9813000077020000000000005cf94503b9d0dc01000100007302000000000000030000000000000001000000000000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c00640077006d002e0065007800650000007d6a0200a31480900000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\dwm.exe",
            ),
            (
                "1e01000040020000241e00002806000016ad0331b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080010000000000000000000000000000000000000000000000",
                "741000007a0200000000000069aa0331b9d0dc01280600001b00000000000000000000000000000001000000000000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c00610070007000690064006300650072007400730074006f007200650063006800650063006b002e006500780065000000cfa20100301f783a0000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\appidcertstorecheck.exe",
            ),
            (
                "0601000040020000b0290000741000008bed0431b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000000000000000000000000000000000000000000",
                "d41500007b02000000000000e3ea0431b9d0dc01741000007a02000000000000000000000000000001000000000000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0063006f006e0068006f00730074002e0065007800650000003b1b100035c2ff630000000001000000",
                r"\Device\HarddiskVolume3\Windows\System32\conhost.exe",
            ),
            (
                "0801000040020000cc280000280600007b817d37bdd0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080280000003800000000000000000000000000000000000000",
                "c80d00009e02000000000000397e7d37bdd0dc01280600001b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c007700730071006d0063006f006e0073002e006500780065000000dbc001008c3df6040000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\wsqmcons.exe",
            ),
            (
                "0401000040020000b02100008c0300001dd2c8efbad0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080020000000000000000000000000000000000000000000000",
                "4c0c0000970200000000000027cdc8efbad0dc018c0300000b00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c007300700070007300760063002e006500780065000000c3484a00755b18940000000001000000",
                r"\Device\HarddiskVolume3\Windows\System32\sppsvc.exe",
            ),
            (
                "060100004002000014130000dc120000c7cde9dcbdd0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080020000000100000000000000000000000000000000000000",
                "f02b0000a202000000000000e1c2e9dcbdd0dc01dc1200007200000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073006400620069006e00730074002e006500780065000000ca7f0500ef29a3b30000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\sdbinst.exe",
            ),
            (
                "0601000040020000c41900003c0200009908ad02b9d0dc01d62cfb227b0e2b42a0c72fad1fd0e71601000410040101001000000000000080000000000100000000000000000000000000000000000000",
                "7c0700007002000000000000c306ad02b9d0dc013c0200000d00000000000000000000000000000001000000010000000101000000000010004000005c004400650076006900630065005c0048006100720064006400690073006b0056006f006c0075006d00650033005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0064006c006c0068006f00730074002e006500780065000000391002005816b3d00000000000000000",
                r"\Device\HarddiskVolume3\Windows\System32\dllhost.exe",
            ),
        ];

        for (header, userdata, image_name) in samples {
            assert_kernel_process_v4_sample_parses(&schema, header, userdata, image_name);
        }
    }
}
