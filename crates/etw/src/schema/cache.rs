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
    schemas: RwLock<HashMap<(GUID, u16), Arc<EventInfo>>>,
}

impl SchemaCache {
    pub fn new() -> Self {
        Self {
            schemas: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_from_event_record(&self, event_record: &EVENT_RECORD) -> Result<Arc<EventInfo>, TraceError> {
        let key = (event_record.EventHeader.ProviderId, event_record.EventHeader.EventDescriptor.Id);
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
                    log::trace!("Caching event info for {:?}:{}: {:?}", event_record.EventHeader.ProviderId, event_record.EventHeader.EventDescriptor.Id, & cached_event_info);
                    Ok(Arc::clone(entry.insert(Arc::new(cached_event_info))))
                }
            }
        }
        else {
            todo!("Mutex was poisoned");
        }
    }

    pub fn get(&self, provider_id: GUID, event_id: u16) -> Option<Arc<EventInfo>> {
        if let Ok(guard) = self.schemas.read() {
            guard.get(&(provider_id, event_id)).map(|v| Arc::clone(v))
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
            if let Some(event_record) = event_record {
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
    use std::{collections::HashMap, mem::size_of};

    use crate::{
        error::ParseError,
        schema::{in_type::InType, out_type::OutType},
        values::{compound::StructOrValue, in_value::InValue, value::Value},
    };

    use super::{
        PropertyInfo, PropertyNestedInfo, PropertyValue, PropertyValueInfo,
    };

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
}