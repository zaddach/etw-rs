use std::collections::{HashMap, HashSet};

use clap::Parser;

use args::{Args, VersionSpecification};
use etw::{schema::cache::{EventInfo, PropertyInfo}, tdh_wrappers::{Providers, TraceEventInfo}};
use uuid::Uuid;

mod args;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NullablePropertyInfo {
    min_version: u8,
    #[serde(flatten)]
    property_info: PropertyInfo,
}



fn main() {
    match Args::parse() {
        Args::Schema(args) => {
            let mut processed_schemas = HashMap::<Uuid, HashMap<u16, HashMap<String, NullablePropertyInfo>>>::new();

            for provider in Providers::new().unwrap().iter() {
                let provider_guid = provider.guid();

                // If filter spec is set, skip providers that don't match
                let events_filter = if !args.event_specifications.is_empty() {
                    if let Some(event_filter ) = args.event_specifications.iter().find(|v| v.provider == Uuid::from_u128(provider_guid.to_u128())) {
                        Some(event_filter)
                    }
                    else {
                        continue;
                    }
                }
                else {
                    None
                };
        
                let processed_events = processed_schemas.entry(Uuid::from_u128(provider_guid.to_u128())).or_insert(HashMap::new());
                if let Ok(event_descriptors) = provider.event_descriptors() {
                    let mut events = HashMap::new();
                    for event in event_descriptors.iter() {
                        // Skip event if id or version doesn't match filter
                        if let Some(events_filter) = events_filter {
                            if let Some(event_filter) = events_filter.events.iter().find(|v| v.event == event.id()) {
                                match event_filter.version {
                                    VersionSpecification::None => {}
                                    VersionSpecification::Version(version) => {
                                        if event.version() != version {
                                            continue;
                                        }
                                    }
                                    VersionSpecification::VersionRange(min_version, max_version) => {
                                        if event.version() < min_version || event.version() > max_version {
                                            continue;
                                        }
                                    }
                                }
                            }
                            else {
                                continue;
                            }
                        }
                        
                        let entry = events.entry(event.id()).or_insert_with(|| HashMap::new());
                        let trace_info = TraceEventInfo::from_provider_guid(&provider.guid(), event.data()).unwrap();
                        let schema = EventInfo::parse(&trace_info, None).unwrap();
                        entry.insert(event.version(), schema);
                    }
        
                    for (event_id, schemas) in events.iter() {
                        let mut properties = HashMap::<String, NullablePropertyInfo>::new();
                        let mut versions = schemas.keys().copied().collect::<Vec<_>>();
                        versions.sort_unstable();
                        for version in versions {
                            let schema = schemas.get(&version).unwrap();
                            if version >= 1 {
                                let prev_properties = properties.keys().cloned().collect::<HashSet<_>>();
                                let cur_properties = schema.properties.fields.iter().map(|f| f.value.name().to_string()).collect::<HashSet<_>>();
                                if !prev_properties.is_subset(&cur_properties) {
                                    eprintln!("Schemas of event {provider_guid:?}:{event_id} has events removed at version {version}");
                                }
                            }
                            for prop in & schema.properties.fields {
                                let name = prop.value.name();
                                if let Some(prev_prop) = properties.get(name) {
                                    if &prev_prop.property_info != prop {
                                        eprintln!("Schemas of event {provider_guid:?}:{event_id} don't agree on property {name} at version {version}")
                                    }
                                }
                                else {
                                    properties.insert(name.to_string(), NullablePropertyInfo {min_version: version, property_info: prop.clone()});
                                }
                            }
                        }
        
                        processed_events.insert(*event_id, properties);
                    }
                }
            }
        
            println!("{}", serde_json::to_string_pretty(&processed_schemas).unwrap());
        }
    }
}
