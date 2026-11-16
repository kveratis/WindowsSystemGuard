//! Event XML (as rendered by `EvtRender`) to `EventRecord`.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub channel: String,
    pub provider: String,
    pub event_id: u16,
    pub version: u8,
    pub level: u8,
    pub utc_ns: i64,
    pub record_id: u64,
    /// `EventData` and `UserData` values by name. An unnamed `Data` element is keyed `Data{index}`.
    pub payload: BTreeMap<String, String>,
    /// The localized message, or `None` when the provider's message DLL cannot be resolved.
    pub rendered_message: Option<String>,
    pub raw_xml: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum XmlError {
    #[error("event XML is not well formed: {0}")]
    Malformed(String),
    #[error("event XML has no {0}")]
    Missing(&'static str),
    #[error("event XML has an invalid {0}: {1:?}")]
    Invalid(&'static str, String),
}

pub fn parse_event_xml(xml: &str) -> Result<EventRecord, XmlError> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| XmlError::Malformed(e.to_string()))?;
    let root = doc.root_element();
    let sys = child(root, "System").ok_or(XmlError::Missing("System element"))?;
    let text = |name: &'static str| child(sys, name).and_then(|n| n.text()).map(str::trim);
    let num = |name: &'static str| -> Result<u64, XmlError> {
        let t = text(name).ok_or(XmlError::Missing(name))?;
        t.parse().map_err(|_| XmlError::Invalid(name, t.to_string()))
    };
    let provider = child(sys, "Provider").and_then(|p| p.attribute("Name")).unwrap_or_default().to_string();
    let stamp = child(sys, "TimeCreated")
        .and_then(|t| t.attribute("SystemTime"))
        .ok_or(XmlError::Missing("TimeCreated SystemTime"))?;
    let utc_ns = parse_system_time(stamp).ok_or_else(|| XmlError::Invalid("SystemTime", stamp.to_string()))?;
    let small = |name: &'static str, v: u64, max: u64| {
        if v <= max { Ok(v) } else { Err(XmlError::Invalid(name, v.to_string())) }
    };
    let event_id = small("EventID", num("EventID")?, u16::MAX as u64)? as u16;
    // Version and Level are always present in real events but a missing one means "none".
    let version = if text("Version").is_some() { small("Version", num("Version")?, u8::MAX as u64)? as u8 } else { 0 };
    let level = if text("Level").is_some() { small("Level", num("Level")?, u8::MAX as u64)? as u8 } else { 0 };

    let mut payload = BTreeMap::new();
    if let Some(data) = child(root, "EventData") {
        for (i, d) in data.children().filter(|n| n.has_tag_name("Data")).enumerate() {
            let key = d.attribute("Name").map(str::to_string).unwrap_or_else(|| format!("Data{i}"));
            payload.insert(key, d.text().unwrap_or_default().to_string());
        }
    }
    if let Some(user) = child(root, "UserData") {
        // UserData wraps one provider-specific element whose children are the fields.
        let holder = user.children().find(|n| n.is_element()).unwrap_or(user);
        for f in holder.children().filter(|n| n.is_element()) {
            payload.insert(f.tag_name().name().to_string(), f.text().unwrap_or_default().to_string());
        }
    }
    let rendered_message = child(root, "RenderingInfo")
        .and_then(|r| child(r, "Message"))
        .and_then(|m| m.text())
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty());

    Ok(EventRecord {
        channel: text("Channel").unwrap_or_default().to_string(),
        provider,
        event_id,
        version,
        level,
        utc_ns,
        record_id: num("EventRecordID").unwrap_or(0),
        payload,
        rendered_message,
        raw_xml: xml.to_string(),
    })
}

fn child<'a>(n: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    n.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

/// `2026-11-13T10:00:00.123456700Z` to nanoseconds since the Unix epoch.
pub(crate) fn parse_system_time(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':');
    let (h, mi, sec): (i64, i64, i64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 || frac.len() > 9 {
        return None;
    }
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let frac_ns: i64 = if frac.is_empty() { 0 } else { format!("{frac:0<9}").parse().ok()? };
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec) * 1_000_000_000) + frac_ns)
}

/// Nanoseconds since the Unix epoch to `2026-11-13T10:00:00.123Z`, rounded down to the millisecond.
pub(crate) fn format_system_time(ns: i64) -> String {
    let ms_total = ns.div_euclid(1_000_000);
    let secs = ms_total.div_euclid(1000);
    let ms = ms_total.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_round_trips() {
        let ns = parse_system_time("2026-11-13T10:00:00.123456700Z").unwrap();
        assert_eq!(format_system_time(ns), "2026-11-13T10:00:00.123Z");
        assert_eq!(parse_system_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_system_time("2000-03-01T00:00:00.5Z"), Some(951_868_800_500_000_000));
        assert_eq!(format_system_time(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(parse_system_time("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_system_time("2026-11-13T10:00:00"), None);
    }
}
