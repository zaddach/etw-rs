// use std::path::PathBuf;

// #[test]
// fn test_recorded_dns_wininet() {
//     let _ = env_logger::builder().is_test(true).try_init();
    
//     let cargo_manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/resources/dns_wininet.etl");
//     let mut trace = etwschema::trace::TraceBuilder::new()
//         .file(cargo_manifest_dir)
//         .unwrap()
//         .set_handler(None, |event| {
//             println!("Event {:?} {}", event.header.provider_id(), event.header.event_descriptor().id());
//         })
//         .unwrap()
//         .open()
//         .unwrap();

//     trace.start_processing(None, None, None::<fn()>);
//     trace.wait().unwrap();
// }