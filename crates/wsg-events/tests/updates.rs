use std::collections::BTreeMap;
use std::time::Duration;

use wsg_events::updates::{
    detect_install_loops, update_event_from, update_timeline_with_notes, UpdateEvent, UpdateKind,
};
use wsg_events::EventRecord;

const SEC: i64 = 1_000_000_000;
const HOUR: i64 = 3600 * SEC;

fn ue(t: i64, kind: UpdateKind, name: &str) -> UpdateEvent {
    UpdateEvent { utc_ns: t, kind, name: name.into(), detail: String::new() }
}

fn wu(id: u16, data: &[(&str, &str)]) -> EventRecord {
    EventRecord {
        channel: "System".into(),
        provider: "Microsoft-Windows-WindowsUpdateClient".into(),
        event_id: id,
        version: 0,
        level: 4,
        utc_ns: 5 * SEC,
        record_id: 1,
        payload: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
        rendered_message: None,
        raw_xml: String::new(),
    }
}

#[test]
fn detects_package_installed_ten_times_in_a_day() {
    let name = "9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2";
    let mut v = Vec::new();
    for i in 0..10 {
        v.push(ue(i * 2 * HOUR, UpdateKind::Started, name));
        v.push(ue(i * 2 * HOUR + 60 * SEC, UpdateKind::Succeeded, name));
    }
    let loops = detect_install_loops(&v, 10, Duration::from_secs(24 * 3600));
    assert_eq!(loops.len(), 1);
    assert_eq!((loops[0].name.as_str(), loops[0].count), (name, 10), "Started events are not double counted");
    assert_eq!((loops[0].first_utc_ns, loops[0].last_utc_ns), (60 * SEC, 18 * 2 * HOUR / 2 + 60 * SEC));
}

#[test]
fn installs_spread_over_weeks_are_not_a_loop() {
    let v: Vec<_> = (0..10).map(|i| ue(i * 48 * HOUR, UpdateKind::Succeeded, "slow")).collect();
    assert!(detect_install_loops(&v, 10, Duration::from_secs(24 * 3600)).is_empty());
    assert_eq!(detect_install_loops(&v, 10, Duration::from_secs(30 * 24 * 3600))[0].count, 10);
}

#[test]
fn ignores_single_install() {
    let v = vec![ue(0, UpdateKind::Started, "once"), ue(SEC, UpdateKind::Succeeded, "once")];
    assert!(detect_install_loops(&v, 2, Duration::from_secs(3600)).is_empty());
    assert!(detect_install_loops(&v, 0, Duration::from_secs(3600)).is_empty(), "min_repeats 0 still needs a repeat");
}

#[test]
#[allow(non_snake_case)]
fn failed_events_carry_error_code_0x80073D02() {
    let e = wu(20, &[("errorCode", "0x80073d02"), ("updateTitle", "9MV0B5HZVK9Z-Microsoft.GamingApp")]);
    let u = update_event_from(&e).unwrap();
    assert_eq!(u.kind, UpdateKind::Failed { code: "0x80073D02".into() });
    assert_eq!(u.name, "9MV0B5HZVK9Z-Microsoft.GamingApp");
    assert!(u.detail.contains("0x80073D02"));
    assert_eq!(update_event_from(&wu(19, &[("updateTitle", "X")])).unwrap().kind, UpdateKind::Succeeded);
    assert_eq!(update_event_from(&wu(43, &[("updateTitle", "X")])).unwrap().kind, UpdateKind::Started);
    assert!(update_event_from(&wu(44, &[("updateTitle", "X")])).is_none(), "download events are not tracked");
    assert!(update_event_from(&wu(19, &[])).is_none(), "no title, no event");
}

#[test]
fn failed_installs_count_toward_a_loop() {
    let v: Vec<_> = (0..6)
        .map(|i| ue(i * HOUR, UpdateKind::Failed { code: "0x80073D02".into() }, "stuck"))
        .collect();
    assert_eq!(detect_install_loops(&v, 5, Duration::from_secs(24 * 3600))[0].count, 6);
}

#[test]
fn loops_are_sorted_by_count_desc() {
    let mut v = Vec::new();
    for (name, n) in [("few", 3), ("many", 9), ("some", 5)] {
        v.extend((0..n).map(|i| ue(i * HOUR, UpdateKind::Succeeded, name)));
    }
    let loops = detect_install_loops(&v, 3, Duration::from_secs(24 * 3600));
    let order: Vec<_> = loops.iter().map(|l| (l.name.as_str(), l.count)).collect();
    assert_eq!(order, [("many", 9), ("some", 5), ("few", 3)]);
}

#[test]
fn pnp_driver_configuration_becomes_a_driver_install() {
    let mut e = wu(400, &[("DeviceInstanceId", r"ROOT\VMS_VSMP\0001"), ("DriverName", "wvms_mp_windows.inf"), ("DriverVersion", "10.0.26100.1"), ("DriverProvider", "Microsoft")]);
    e.provider = "Microsoft-Windows-Kernel-PnP".into();
    let u = update_event_from(&e).unwrap();
    assert_eq!((u.kind, u.name.as_str()), (UpdateKind::DriverInstall, r"wvms_mp_windows.inf [ROOT\VMS_VSMP\0001]"));
    assert!(u.detail.contains("10.0.26100.1"));
}

#[test]
fn one_inf_configured_on_many_devices_is_not_a_loop() {
    let events: Vec<UpdateEvent> = (0..10)
        .map(|i| {
            let mut e = wu(400, &[("DeviceInstanceId", &format!(r"ROOT\DEV\{i:04}")), ("DriverName", "same.inf")]);
            e.provider = "Microsoft-Windows-Kernel-PnP".into();
            e.utc_ns = i * SEC;
            update_event_from(&e).unwrap()
        })
        .collect();
    assert!(detect_install_loops(&events, 3, Duration::from_secs(3600)).is_empty());
    // The same device configured again and again still is.
    let again: Vec<UpdateEvent> = (0..10)
        .map(|i| {
            let mut e = wu(400, &[("DeviceInstanceId", r"ROOT\DEV\0001"), ("DriverName", "same.inf")]);
            e.provider = "Microsoft-Windows-Kernel-PnP".into();
            e.utc_ns = i * SEC;
            update_event_from(&e).unwrap()
        })
        .collect();
    assert_eq!(detect_install_loops(&again, 3, Duration::from_secs(3600))[0].count, 10);
}

#[test]
fn live_timeline_over_14_days_is_ordered_and_reports_loops() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64;
    let from = now - 14 * 24 * HOUR;
    let (events, notes) = update_timeline_with_notes(from, now).expect("System log readable");
    eprintln!("{} events, notes: {notes:?}", events.len());
    assert!(events.windows(2).all(|w| w[0].utc_ns <= w[1].utc_ns));
    assert!(events.iter().all(|e| e.utc_ns >= from && e.utc_ns <= now));
    let loops = detect_install_loops(&events, 10, Duration::from_secs(14 * 24 * 3600));
    for l in loops.iter().take(5) {
        eprintln!("loop: {} x{}", l.name, l.count);
    }
    assert!(loops.windows(2).all(|w| w[0].count >= w[1].count));
    // The owner's machine reinstalls this package over and over; skip where it does not.
    let war = "Microsoft.WindowsAppRuntime.2";
    if events.iter().any(|e| e.name.contains(war) && e.kind == UpdateKind::Succeeded) {
        assert!(loops.iter().any(|l| l.name.contains(war)), "WindowsAppRuntime loop reported");
    } else {
        eprintln!("skipped loop check: no {war} installs in the last 14 days");
    }
}
