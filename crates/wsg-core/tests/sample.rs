use wsg_core::*;

fn unavailable<T>() -> Reading<T> {
    Reading::Unavailable { reason: "no counter".into() }
}

fn sample() -> Sample {
    Sample {
        cpu: Reading::Value { v: CpuStats { total_pct: 12.5, dpc_pct: 1.0, interrupt_pct: 0.5 }, age_ms: 3 },
        mem: Reading::Value {
            v: MemStats { commit_bytes: 1, available_bytes: 2, nonpaged_pool_bytes: 3, paged_pool_bytes: 4 },
            age_ms: 0,
        },
        disks: Reading::Value { age_ms: 0, v: vec![DiskStats { disk_id: "0 C:".into(), queue_len: 1.5, read_latency_ms: 2.0, write_latency_ms: 3.0, bytes_per_sec: 4 }] },
        net: Reading::Value { age_ms: 0, v: vec![NetStats { adapter: "eth0".into(), bytes_per_sec: 99 }] },
        procs: vec![ProcStat { pid: 4, name: "System".into(), cpu_pct: 0.1, working_set_bytes: 5, io_bytes_per_sec: 6, handles: 7 }],
        gpu: unavailable(),
        sensors: Reading::Value {
            v: SensorSet {
                cpu_temp_c: Some(55.0),
                per_core_clock_mhz: vec![3000.0],
                voltages: vec![("vcore".into(), 1.1)],
                fans_rpm: vec![("cpu".into(), 1200)],
            },
            age_ms: 10,
        },
        wsl_vm_running: Reading::Value { v: true, age_ms: 1 },
        cycle_ms: 1000,
    }
}

#[test]
fn unavailable_roundtrips_and_is_not_zero() {
    let mut s = sample();
    s.cpu = unavailable();
    s.disks = Reading::Unavailable { reason: "pdh down".into() };
    s.net = unavailable();
    let d = Sample::decode(&s.encode()).unwrap();
    assert!(matches!(d.cpu, Reading::Unavailable { ref reason } if reason == "no counter"));
    assert!(!matches!(d.cpu, Reading::Value { .. }));
    assert!(matches!(d.disks, Reading::Unavailable { ref reason } if reason == "pdh down"));
    assert!(matches!(d.net, Reading::Unavailable { ref reason } if reason == "no counter"));
}

#[test]
fn sample_roundtrips() {
    let s = sample();
    assert_eq!(Sample::decode(&s.encode()).unwrap(), s);
}

#[test]
fn rejects_unknown_schema_version() {
    let mut b = sample().encode();
    b[0] = 99;
    assert!(matches!(Sample::decode(&b), Err(DecodeError::UnknownSchema(99))));
    assert!(matches!(Sample::decode(&[]), Err(DecodeError::Corrupt)));
}

#[test]
fn mono_ns_is_monotonic() {
    let a = mono_ns();
    let b = mono_ns();
    assert!(b >= a);
    assert!(now_utc_ns() > 0);
    assert_ne!(new_boot_id(), new_boot_id());
}
