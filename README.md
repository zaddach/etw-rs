etwschema
==========

Utility to get information about ETW providers and events.

## Usage
You can get help with `./etwschema --help`.
Functionalities:
- `./etschema providers`: List all providers. You can use a utility like `grep` to search the list.
- `./etwschema events <guid>` List events for provider `<guid>`. You can limit this to a single event with `--id <event-id>`.

## Proc macro
You can find a proc macro implementation in ./etw_macro. This will autmatically generate structures based on the ETW event schema. An example is given in ./etw_macro_test.

## Example
You can set up a simple trace session like this:
```
use std::sync::mpsc::{channel, RecvTimeoutError};

use etwschema::trace::TraceBuilder;
use etwschema::trace_session::TraceSessionBuilder;


#[etw::macro::etw_events]
pub mod events {
    #[etw_macro::etw_event(provider_guid = "2a576b87-09a7-520e-c21a-4942f0271d67", id = 1101, version = 1)]
    pub struct EtwAmsiEvent1101 {}
}

fn handler(event: &crate::events::Events) {
    //event is std::fmt::Debug
    //Autocompletion in VS Code will show the different enum members
    println!("Received event: {:?}", event);
    let _events_owned = crate::events::EventsOwned::try_from(event).unwrap();
    //_events_owned is serde::Serialize and serde::Deserialize (if you activated the crate features for etw_macro)
}

fn main() {
    const TRACE_NAME: &str = "my_awesome_trace";
    env_logger::init();
    let trace_session = TraceSessionBuilder::new(TRACE_NAME)
        .start()
        .unwrap();

    let mut trace = TraceBuilder::new()
        .session(trace_session).unwrap()
        .compound_handler(handler).unwrap()
        .open().unwrap();

    trace.start_processing(None, None);

    let (tx, rx) = channel();
    ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
        .expect("Error setting Ctrl-C handler");

    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(()) => {
                println!("Got CTRL-C, exiting");
                break;
            }
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if trace.is_finished() {
            println!("Trace ended");
            break;
        }
    }
}
```

## Notes
- Newer versions of ETW events are supposed to be backward compatible with older versions. This crate checks that the received event version is newer or the same to the event schema definition seen at compile time.
- Trace sessions are an expensive resource. The `TraceSession` struct will automatically shut down the session if the program exits orderly. The trace session may remain active if the program crashes. You could call `.close_previous()` on the trace session builder to close a session with the same name on startup if it exists.
