use std::collections::BTreeMap;
use std::path::PathBuf;

use wsg_events::{
    group, group_key, query_file, score, triage, Disposition, EventRecord, History, IncidentWindow, NoiseRules,
    MAX_TIMES, MAX_VARIANTS,
};

const SEC: i64 = 1_000_000_000;

fn ev(provider: &str, id: u16, level: u8, t_s: i64, data: &[(&str, &str)]) -> EventRecord {
    EventRecord {
        channel: "System".into(),
        provider: provider.into(),
        event_id: id,
        version: 0,
        level,
        utc_ns: t_s * SEC,
        record_id: t_s as u64,
        payload: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
        rendered_message: None,
        raw_xml: String::new(),
    }
}

#[test]
fn same_event_different_locale_text_groups_together() {
    let mut a = ev("Disk", 7, 2, 10, &[("DeviceName", r"\Device\Harddisk1\DR1")]);
    let mut b = ev("Disk", 7, 2, 20, &[("DeviceName", r"\Device\Harddisk1\DR1")]);
    a.rendered_message = Some("The device has a bad block.".into());
    b.rendered_message = Some("Das Gerät hat einen fehlerhaften Block.".into());
    b.raw_xml = "<different/>".into();
    let g = group(&[a, b]);
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].count, 2);
}

#[test]
fn different_payload_creates_different_group() {
    let a = ev("Disk", 7, 2, 10, &[("DeviceName", r"\Device\Harddisk1\DR1")]);
    let b = ev("Disk", 7, 2, 20, &[("DeviceName", r"\Device\Harddisk2\DR2")]);
    let c = ev("Disk", 11, 2, 30, &[("DeviceName", r"\Device\Harddisk1\DR1")]);
    assert_eq!(group(&[a, b, c]).len(), 3);
}

#[test]
fn volatile_payload_parts_do_not_split_a_group() {
    let a = ev("P", 1, 3, 10, &[("Clsid", "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"), ("Pid", "1234567890")]);
    let b = ev("P", 1, 3, 20, &[("Clsid", "{11111111-2222-3333-4444-555555555555}"), ("Pid", "9876543210")]);
    let g = group(&[a, b]);
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].payload_variants.len(), 2, "both payloads kept as variants");
}

#[test]
fn suppressed_group_keeps_count_times_and_variants() {
    let evs: Vec<_> = (0..5)
        .map(|i| ev("Microsoft-Windows-DistributedCOM", 10016, 2, 100 + i, &[("param4", &format!("user{i}"))]))
        .collect();
    let g = group(&evs);
    assert_eq!(g.len(), 5, "differing payloads group apart");
    let evs: Vec<_> = (0..5)
        .map(|i| ev("Microsoft-Windows-DistributedCOM", 10016, 2, 100 + i, &[("param4", "same")]))
        .collect();
    let g = group(&evs).remove(0);
    assert!(matches!(NoiseRules::builtin().classify(&g), Disposition::Suppressed { .. }));
    assert_eq!((g.count, g.times_utc_ns.len(), g.first_utc_ns, g.last_utc_ns), (5, 5, 100 * SEC, 104 * SEC));
    assert_eq!(g.payload_variants.len(), 1);
    assert_eq!(g.sample.event_id, 10016);
}

#[test]
fn rare_never_seen_event_near_incident_outranks_frequent_noise() {
    let incident = IncidentWindow { start_utc_ns: 0, end_utc_ns: 10_000 * SEC };
    let noisy: Vec<_> = (0..5000).map(|i| ev("Chatty", 1, 2, i % 9000, &[])).collect();
    let rare = ev("Storport", 129, 3, 9_990, &[("Port", "0")]);
    let mut groups = group(&noisy);
    groups.extend(group(&[rare]));
    let history = History(groups.iter().filter(|g| g.key.provider == "Chatty").map(|g| (g.key.clone(), 50_000)).collect());
    let ranked = triage(groups, &NoiseRules::default(), Some(&incident), &history);
    assert_eq!(ranked[0].group.key.provider, "Storport", "{:?}", ranked.iter().map(|t| t.score).collect::<Vec<_>>());
    assert!(ranked[0].score > ranked[1].score);
}

#[test]
fn suppression_never_hides_a_group_inside_incident_window_if_novel() {
    let incident = IncidentWindow { start_utc_ns: 0, end_utc_ns: 1000 * SEC };
    let dcom = ev("Microsoft-Windows-DistributedCOM", 10016, 2, 990, &[]);
    let g = group(&[dcom]);
    let rules = NoiseRules::builtin();
    // Seen before: the rule applies.
    let seen = History(g.iter().map(|x| (x.key.clone(), 40)).collect());
    assert!(matches!(triage(g.clone(), &rules, Some(&incident), &seen)[0].disposition, Disposition::Suppressed { .. }));
    // Never seen before and inside the window: surfaced despite the rule.
    assert_eq!(triage(g.clone(), &rules, Some(&incident), &History::default())[0].disposition, Disposition::Surfaced);
    // Never seen before but outside the window: the rule applies.
    let far = IncidentWindow { start_utc_ns: 5000 * SEC, end_utc_ns: 6000 * SEC };
    assert!(matches!(triage(g, &rules, Some(&far), &History::default())[0].disposition, Disposition::Suppressed { .. }));
}

#[test]
fn level_frequency_and_proximity_move_the_score_the_right_way() {
    let w = IncidentWindow { start_utc_ns: 0, end_utc_ns: 1000 * SEC };
    let h = History::default();
    let g = |level, n: i64, t| group(&(0..n).map(|_| ev("P", 1, level, t, &[])).collect::<Vec<_>>()).remove(0);
    assert!(score(&g(1, 1, 990), Some(&w), &h) > score(&g(3, 1, 990), Some(&w), &h), "critical beats warning");
    assert!(score(&g(2, 1, 990), Some(&w), &h) > score(&g(2, 1000, 990), Some(&w), &h), "rare beats frequent");
    assert!(score(&g(2, 1, 990), Some(&w), &h) > score(&g(2, 1, 100), Some(&w), &h), "closer to the end wins");
    let seen = History([(g(2, 1, 990).key, 5)].into_iter().collect());
    assert!(score(&g(2, 1, 990), Some(&w), &h) > score(&g(2, 1, 990), Some(&w), &seen), "novel beats seen");
}

#[test]
fn group_still_firing_at_incident_end_is_near_even_past_the_timestamp_cap() {
    let w = IncidentWindow { start_utc_ns: 0, end_utc_ns: 100_000 * SEC };
    let h = History::default();
    // 2000 events: the first 1000 are far from the incident end, the last one is at it.
    let mut evs: Vec<_> = (0..1999).map(|i| ev("P", 1, 2, i, &[])).collect();
    evs.push(ev("P", 1, 2, 100_000, &[]));
    let capped = group(&evs).remove(0);
    assert_eq!(capped.times_utc_ns.len(), MAX_TIMES);
    let old_only = group(&(0..2000).map(|i| ev("P", 1, 2, i, &[])).collect::<Vec<_>>()).remove(0);
    assert!(score(&capped, Some(&w), &h) > score(&old_only, Some(&w), &h) + 1.0, "ongoing group ranks as near");
}

#[test]
fn rules_roundtrip_through_file() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("noise.toml");
    let rules = NoiseRules::builtin();
    rules.save(&p).unwrap();
    assert_eq!(NoiseRules::load(&p).unwrap(), rules);
    std::fs::write(&p, "[[rule]]\nname = \"x\"\nprovider = \"P\"\nevent_id = 1\nbogus = 2\n").unwrap();
    assert!(NoiseRules::load(&p).is_err(), "unknown field refused");
    assert!(NoiseRules::load(&d.path().join("absent.toml")).is_err());
}

#[test]
fn huge_group_caps_times_and_variants() {
    let evs: Vec<_> = (0..(MAX_TIMES as i64 + 500))
        .map(|i| ev("P", 1, 2, i, &[("Name", &format!("v{}", i % 100))]))
        .collect();
    let g = group(&evs);
    // 100 distinct short values make 100 groups; use one key to test the caps.
    assert_eq!(g.len(), 100);
    let one: Vec<_> = (0..(MAX_TIMES as i64 + 500)).map(|i| ev("P", 2, 2, i, &[("Name", "same")])).collect();
    let g = group(&one).remove(0);
    assert_eq!((g.count, g.times_utc_ns.len()), (MAX_TIMES as u64 + 500, MAX_TIMES));
    assert_eq!(g.last_utc_ns, (MAX_TIMES as i64 + 499) * SEC);
    // Many payloads that normalise to the same signature fill the variants cap.
    let many: Vec<_> = (0..(MAX_VARIANTS as i64 + 30))
        .map(|i| ev("P", 3, 2, i, &[("Id", &format!("{:032}", i + 1_000_000_000))]))
        .collect();
    let g = group(&many);
    assert_eq!(g.len(), 1);
    assert_eq!((g[0].count, g[0].payload_variants.len()), (MAX_VARIANTS as u64 + 30, MAX_VARIANTS));
    assert_eq!(group_key(&many[0]), g[0].key);
}

#[test]
fn builtin_rules_suppress_dcom_10016_on_fixture() {
    let Some(dir) = std::env::var_os("WSG_FIXTURES") else {
        eprintln!("skipped: WSG_FIXTURES is not set");
        return;
    };
    let path = PathBuf::from(dir).join("system.evtx");
    if !path.exists() {
        eprintln!("skipped: {} does not exist", path.display());
        return;
    }
    let events = query_file(&path, 0, i64::MAX / 2, 5).unwrap();
    let groups = group(&events);
    let dcom: Vec<_> = groups.iter().filter(|g| g.key.event_id == 10016 && g.key.provider.contains("DistributedCOM")).collect();
    if dcom.is_empty() {
        eprintln!("skipped: no DCOM 10016 in the fixture");
        return;
    }
    let rules = NoiseRules::builtin();
    assert!(dcom.iter().all(|g| matches!(rules.classify(g), Disposition::Suppressed { .. })));
    assert!(dcom.iter().all(|g| g.count as usize >= g.payload_variants.len() && !g.times_utc_ns.is_empty()));
}
