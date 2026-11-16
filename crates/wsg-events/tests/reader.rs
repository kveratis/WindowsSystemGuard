use std::path::PathBuf;

use wsg_events::{inventory_channels, parse_event_xml, query, query_file, ChannelState, XmlError};

const KERNEL_POWER_41: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power" Guid="{331C3B3A-2005-44C2-AC5E-77220C37D6B4}"/><EventID>41</EventID><Version>8</Version><Level>1</Level><Task>63</Task><Opcode>0</Opcode><Keywords>0x8000400000000002</Keywords><TimeCreated SystemTime="2026-11-13T10:00:00.123456700Z"/><EventRecordID>9876</EventRecordID><Correlation/><Execution ProcessID="4" ThreadID="8"/><Channel>System</Channel><Computer>HOST</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="BugcheckCode">278</Data><Data Name="BugcheckParameter1">0x1</Data><Data Name="SleepInProgress">0</Data><Data Name="PowerButtonTimestamp">0</Data></EventData></Event>"#;

#[test]
fn parses_kernel_power_41_fixture_xml() {
    let e = parse_event_xml(KERNEL_POWER_41).unwrap();
    assert_eq!(e.channel, "System");
    assert_eq!(e.provider, "Microsoft-Windows-Kernel-Power");
    assert_eq!((e.event_id, e.version, e.level, e.record_id), (41, 8, 1, 9876));
    assert_eq!(e.utc_ns, 1_794_564_000_123_456_700);
    assert_eq!(e.payload["BugcheckCode"], "278");
    assert_eq!(e.payload["BugcheckParameter1"], "0x1");
    assert_eq!(e.payload.len(), 4);
    assert_eq!(e.rendered_message, None);
    assert_eq!(e.raw_xml, KERNEL_POWER_41);
}

#[test]
fn parses_event_with_no_eventdata() {
    let xml = r#"<Event xmlns="x"><System><Provider Name="P"/><EventID Qualifiers="16384">7036</EventID><TimeCreated SystemTime="2026-11-13T10:00:00Z"/><EventRecordID>1</EventRecordID><Channel>System</Channel></System></Event>"#;
    let e = parse_event_xml(xml).unwrap();
    assert_eq!(e.event_id, 7036);
    assert!(e.payload.is_empty());
    assert_eq!((e.version, e.level), (0, 0));
}

#[test]
fn parses_userdata_and_unnamed_data() {
    let xml = r#"<Event xmlns="x"><System><Provider Name="P"/><EventID>1</EventID><TimeCreated SystemTime="2026-11-13T10:00:00Z"/><EventRecordID>2</EventRecordID><Channel>C</Channel></System><UserData><Thing xmlns="y"><Disk>0</Disk><Why>bad</Why></Thing></UserData><EventData><Data>a</Data><Data Name="n">b</Data></EventData></Event>"#;
    let e = parse_event_xml(xml).unwrap();
    assert_eq!(e.payload["Disk"], "0");
    assert_eq!(e.payload["Why"], "bad");
    assert_eq!(e.payload["Data0"], "a");
    assert_eq!(e.payload["n"], "b");
}

#[test]
fn parses_non_english_message_xml() {
    let xml = "<Event xmlns=\"x\"><System><Provider Name=\"P\"/><EventID>41</EventID><Level>2</Level><TimeCreated SystemTime=\"2026-11-13T10:00:00Z\"/><EventRecordID>3</EventRecordID><Channel>System</Channel></System><EventData><Data Name=\"Name\">диск ✓ 磁盘</Data></EventData><RenderingInfo Culture=\"ru-RU\"><Message>Система перезагрузилась без корректного завершения работы.</Message></RenderingInfo></Event>";
    let e = parse_event_xml(xml).unwrap();
    assert_eq!(e.payload["Name"], "диск ✓ 磁盘");
    assert_eq!(e.rendered_message.as_deref(), Some("Система перезагрузилась без корректного завершения работы."));
}

#[test]
fn render_failure_keeps_raw_xml_and_none_message() {
    // No RenderingInfo is what an unresolvable provider message DLL leaves behind.
    let e = parse_event_xml(KERNEL_POWER_41).unwrap();
    assert!(e.rendered_message.is_none());
    assert!(e.raw_xml.contains("BugcheckCode"));
}

#[test]
fn bad_xml_is_an_error_not_a_panic() {
    assert!(matches!(parse_event_xml("<Event"), Err(XmlError::Malformed(_))));
    assert_eq!(parse_event_xml("<Event/>"), Err(XmlError::Missing("System element")));
    let big = KERNEL_POWER_41.replace("<EventID>41", "<EventID>70000");
    assert!(matches!(parse_event_xml(&big), Err(XmlError::Invalid("EventID", _))));
}

fn now_ns() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64
}

#[test]
fn live_system_query_returns_events_in_range() {
    let day = 24 * 3600 * 1_000_000_000i64;
    let (to, from) = (now_ns(), now_ns() - 30 * day);
    let events = query("System", from, to, 5).expect("System channel readable");
    assert!(!events.is_empty(), "a month of System log is never empty");
    assert!(events.iter().all(|e| e.utc_ns >= from && e.utc_ns <= to));
    assert!(events.windows(2).all(|w| w[0].utc_ns <= w[1].utc_ns), "oldest first");
    assert!(events.iter().all(|e| e.channel == "System" && !e.raw_xml.is_empty()));
    assert!(events.iter().any(|e| e.rendered_message.is_some()), "some message resolves");
    let errors_only = query("System", from, to, 2).unwrap();
    assert!(errors_only.iter().all(|e| e.level <= 2));
    assert!(errors_only.len() <= events.len());
}

#[test]
fn inventory_reports_missing_channel() {
    let s = inventory_channels(&["System", "Wsg-No-Such-Channel/Operational"]);
    assert_eq!(s[0].state, ChannelState::Ok);
    assert_eq!(s[1].state, ChannelState::Missing);
    assert!(s[0].is_readable() && !s[1].is_readable());
}

#[test]
fn query_file_reads_exported_evtx() {
    let Some(dir) = std::env::var_os("WSG_FIXTURES") else {
        eprintln!("skipped: WSG_FIXTURES is not set; export one with `wevtutil epl System %WSG_FIXTURES%\\system.evtx`");
        return;
    };
    let path = PathBuf::from(dir).join("system.evtx");
    if !path.exists() {
        eprintln!("skipped: {} does not exist", path.display());
        return;
    }
    let events = query_file(&path, 0, now_ns(), 5).unwrap();
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e.channel == "System"));
    assert!(query_file(&path.with_extension("missing"), 0, 1, 5).is_err());
}

#[test]
fn default_channels_are_inventoried_and_rollover_is_checked() {
    let mut s = inventory_channels(&wsg_events::DEFAULT_CHANNELS);
    assert_eq!(s.len(), wsg_events::DEFAULT_CHANNELS.len());
    assert_eq!(s[0].state, ChannelState::Ok, "System");
    // A window starting at the epoch always predates the oldest retained event.
    wsg_events::check_rollover(&mut s, 0);
    assert_eq!(s[0].state, ChannelState::RolledOver);
    assert!(s[0].is_readable());
    for c in &s {
        eprintln!("{}: {:?}", c.name, c.state);
    }
}
