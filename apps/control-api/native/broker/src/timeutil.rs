//! Epoch-milliseconds <-> strict UTC ISO-8601 conversion for the broker's own
//! minted timestamps (Howard Hinnant's civil-date algorithms; no chrono dep).
//! The parse side only ever accepts the exact fixed format this module emits,
//! because the broker only parses timestamps it minted itself.

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { u64::from(m) - 3 } else { u64::from(m) + 9 };
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Format epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn format_iso_utc(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let millis = ms.rem_euclid(86_400_000);
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (
        millis / 3_600_000,
        (millis % 3_600_000) / 60_000,
        (millis % 60_000) / 1000,
    );
    format!(
        "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z",
        millis % 1000
    )
}

/// Parse the EXACT fixed format emitted by [`format_iso_utc`] (milliseconds
/// mandatory). Anything else is rejected — the broker never trusts an
/// externally formatted timestamp.
pub fn parse_iso_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24 {
        return None;
    }
    let digit = |i: usize| (b[i] as char).is_ascii_digit();
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22] {
        if !digit(i) {
            return None;
        }
    }
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'.' || b[23] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> i64 {
        s[r].parse::<i64>().unwrap_or(0)
    };
    let y = num(0..4);
    let mo = num(5..7) as u32;
    let d = num(8..10) as u32;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    Some(
        days * 86_400_000
            + num(11..13) * 3_600_000
            + num(14..16) * 60_000
            + num(17..19) * 1000
            + num(20..23),
    )
}
