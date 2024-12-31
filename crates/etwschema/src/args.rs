use std::{num::ParseIntError, str::FromStr};

use uuid::Uuid;

#[derive(clap::Parser)]
pub enum Args {
    Schema(SchemaArgs),
}

#[derive(Clone)]
pub enum VersionSpecification {
    None,
    Version(u8),
    VersionRange(u8, u8),
}

impl FromStr for VersionSpecification {
    type Err = ParseProviderEventSpecificationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = s.split('-');

        match (components.next(), components.next(), components.next()) {
            (Some(""), None, None) => Ok(VersionSpecification::None),
            (Some(version), None, None) => Ok(VersionSpecification::Version(version.parse()?)),
            (Some(min), Some(max), None) => Ok(VersionSpecification::VersionRange(
                min.parse()?,
                max.parse()?,
            )),
            _ => Err(ParseProviderEventSpecificationError::Invalid),
        }
    }
}

#[derive(Clone)]
pub struct EventSpecification {
    pub event: u16,
    pub version: VersionSpecification,
}

impl FromStr for EventSpecification {
    type Err = ParseProviderEventSpecificationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = s.split(".");
        match (components.next(), components.next(), components.next()) {
            (Some(event), None, None) => Ok(Self {
                event: event.parse()?,
                version: VersionSpecification::None,
            }),
            (Some(event), Some(version), None) => Ok(Self {
                event: event.parse()?,
                version: version.parse()?,
            }),
            _ => Err(ParseProviderEventSpecificationError::Invalid),
        }
    }
}

#[derive(Clone)]
pub struct ProviderEventsSpecification {
    pub provider: Uuid,
    pub events: Vec<EventSpecification>,
}

#[derive(thiserror::Error, Debug)]
pub enum ParseProviderEventSpecificationError {
    #[error("While converting to int: {0}")]
    Int(#[from] ParseIntError),
    #[error("While converting to Uuid: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("Invalid format")]
    Invalid,
}

impl FromStr for ProviderEventsSpecification {
    type Err = ParseProviderEventSpecificationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = s.split(":");
        match (components.next(), components.next(), components.next()) {
            (Some(provider), None, None) => Ok(Self {provider: Uuid::from_str(provider)?, events: vec![]}),
            (Some(provider), Some(events), None) => {
                let events = events.split(",").map(EventSpecification::from_str).collect::<Result<Vec<_>, _>>()?;
                Ok(Self {
                    provider: Uuid::from_str(provider)?,
                    events,
                })
            },
            _ => Err(ParseProviderEventSpecificationError::Invalid),
        }
    }
}


#[derive(clap::Args)]
pub struct SchemaArgs {
    ///Some event specification in the form of <Provider GUID>[:<Event ID>,...]
    #[clap(value_parser = ProviderEventsSpecification::from_str)]
    pub event_specifications: Vec<ProviderEventsSpecification>,
}