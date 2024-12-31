use clap::{Arg, Command};
use etw::{schema::cache::EventInfo, tdh_wrappers::{EventFieldType, ProviderEventDescriptors, ProviderFieldInformation, Providers, TraceEventInfo}};
use once_cell::sync::Lazy;
use regex::Regex;
use windows::core::GUID;

fn parse_guid(string: &str) -> Result<GUID, clap::Error> {
    static GUID_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
            .unwrap()
    });

    if GUID_REGEX.is_match(string) {
        Ok(GUID::from(string))
    } else {
        Err(clap::Error::new(clap::error::ErrorKind::InvalidValue))
    }
}

fn parse_field_type(string: &str) -> Result<EventFieldType, clap::Error> {
    match string {
        "keyword" => Ok(EventFieldType::KeywordInformation),
        "level" => Ok(EventFieldType::LevelInformation),
        "channel" => Ok(EventFieldType::ChannelInformation),
        "task" => Ok(EventFieldType::TaskInformation),
        "opcode" => Ok(EventFieldType::OpcodeInformation),
        _ => Err(clap::Error::new(clap::error::ErrorKind::InvalidValue)),
    }
}

fn cli() -> Command {
    Command::new("etwinfo")
        .about("Display information about ETW")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("providers").about("Display providers"))
        .subcommand(
            Command::new("events")
                .about("Display events for provider")
                .arg_required_else_help(true)
                .arg(Arg::new("provider").value_parser(parse_guid))
                .arg(
                    Arg::new("event_id")
                        .long("id")
                        .value_parser(clap::value_parser!(u16)),
                ),
        )
        .subcommand(
            Command::new("fieldinfo")
                .about("Show field information for a provider")
                .arg(Arg::new("provider").value_parser(parse_guid))
                .arg(Arg::new("field_type").value_parser(parse_field_type)),
        )
}

fn list_providers() {
    let providers = Providers::new().unwrap();
    for provider in providers.iter() {
        println!(
            "Provider {} ({:?}): schema {:?}",
            provider.name().to_str().unwrap(),
            provider.guid(),
            provider.schema_source()
        )
    }
}

fn list_events(provider_guid: &GUID, event_id: Option<u16>) {
    let event_descriptors = ProviderEventDescriptors::new(provider_guid).unwrap();

    println!("List for provider {:?}", provider_guid);

    for event_descriptor in event_descriptors.iter() {
        if let Some(event_id) = event_id {
            if event_id != event_descriptor.id() {
                continue;
            }
        }

        println!("{:?}", event_descriptor);

        let trace_event_info = TraceEventInfo::from_provider_guid(provider_guid, event_descriptor.data()).unwrap();
        let event_info = EventInfo::parse(&trace_event_info, None).unwrap();
        
        for property in event_info.properties.fields {
            println!("    {:?}", property);
        }
    }
}

fn list_fieldinfo(provider_guid: &GUID, event_field_type: &EventFieldType) {
    let field_info = ProviderFieldInformation::new(provider_guid, event_field_type).unwrap();
    for info in field_info.iter() {
        println!("{:?}", info);
    }
}

fn main() {
    let args = cli().get_matches();

    match args.subcommand() {
        Some(("providers", _providers_args)) => {
            list_providers();
        }
        Some(("events", events_args)) => {
            list_events(
                events_args.get_one::<GUID>("provider").unwrap(),
                events_args.get_one::<u16>("event_id").copied(),
            );
        }
        Some(("fieldinfo", fieldinfo_args)) => {
            list_fieldinfo(
                fieldinfo_args.get_one::<GUID>("provider").unwrap(),
                fieldinfo_args
                    .get_one::<EventFieldType>("field_type")
                    .unwrap(),
            );
        }
        Some(_) => unreachable!(),
        None => unreachable!(),
    }
}
