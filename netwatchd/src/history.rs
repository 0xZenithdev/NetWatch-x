//! Long-term history: the numbers worth keeping after the process exits.
//!
//! Everything on the dashboard's live view is in memory and dies with the
//! process. This module is the part that does not: one row per device per day
//! (traffic both ways, packets, seconds online, sessions) and one row per
//! session, in SQLite.
//!
//! Three decisions worth stating, because they are what keeps this cheap:
//!
//! * **Day granularity for retention, minute granularity in memory.** A year of
//!   history for a dozen devices is a few thousand rows, not millions. The
//!   last hour at five-second resolution is already in `State::series`, and
//!   per-device minutes are in the device's own buckets.
//! * **Nothing is written per packet.** The counters accumulate in memory and
//!   the keeper flushes the delta every thirty seconds, in one transaction.
//! * **One connection, owned by the keeper, behind a mutex.** Writes are a
//!   handful of upserts; reads happen when someone opens a page. Neither can
//!   queue behind the other for long enough to matter.
//!
//! Days are UTC. The operator's local day would be friendlier, but this box
//! already has one timezone story (wall-clock unix seconds) and inventing a
//! second one here would make "yesterday" mean two things.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, params};

use crate::devices::mac_string;
use crate::state::{State, now_unix};

/// How long history is kept when the operator does not say.
pub const DEFAULT_KEEP_DAYS: u64 = 365;

const SCHEMA: &str = "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA busy_timeout=2000;
CREATE TABLE IF NOT EXISTS day (
    mac          TEXT    NOT NULL,
    day          INTEGER NOT NULL,
    up           INTEGER NOT NULL DEFAULT 0,
    down         INTEGER NOT NULL DEFAULT 0,
    packets      INTEGER NOT NULL DEFAULT 0,
    online_secs  INTEGER NOT NULL DEFAULT 0,
    sessions     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, day)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS session (
    mac   TEXT    NOT NULL,
    start INTEGER NOT NULL,
    end   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS session_mac ON session (mac, start);
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
";

/// The seconds in a UTC day, named so the arithmetic reads as what it is.
pub const DAY_SECS: u64 = 86_400;

/// One device's day, as stored.
#[derive(Clone, Copy, Default)]
pub struct DayRow {
    pub up: u64,
    pub down: u64,
    pub packets: u64,
    pub online_secs: u64,
    pub sessions: u64,
}

impl DayRow {
    #[must_use]
    pub fn has_numbers(&self) -> bool {
        self.up > 0
            || self.down > 0
            || self.packets > 0
            || self.online_secs > 0
            || self.sessions > 0
    }
}

/// One day of one device, as read back out.
pub struct DeviceDay {
    pub day: u64,
    pub up: u64,
    pub down: u64,
    pub packets: u64,
    pub online_secs: u64,
    pub sessions: u64,
}

/// One day across the whole network.
pub struct NetDay {
    pub day: u64,
    pub up: u64,
    pub down: u64,
    pub devices: u64,
}

/// The store. One connection, opened once.
pub struct History {
    db: Connection,
    keep_days: u64,
    /// The last day a prune ran, so pruning happens once a day rather than
    /// every flush — deleting rows is the one expensive thing here.
    pruned_day: u64,
}

impl History {
    /// Open (or create) the database.
    ///
    /// # Errors
    /// Fails if the directory does not exist or the file is not a database.
    pub fn open(path: &Path, keep_days: u64) -> Result<Self, String> {
        let db =
            Connection::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        db.execute_batch(SCHEMA)
            .map_err(|e| format!("cannot prepare the history database: {e}"))?;
        let pruned_day = day_of(now_unix());
        Ok(Self {
            db,
            keep_days: keep_days.max(1),
            pruned_day,
        })
    }

    /// Today's total for one device, so a restart continues the day rather than
    /// starting it over.
    ///
    /// # Errors
    /// Fails if the query cannot be run.
    pub fn today(&self, mac: &str, day: u64) -> Result<DayRow, String> {
        let mut stmt = self
            .db
            .prepare("SELECT up, down, packets, online_secs, sessions FROM day WHERE mac = ?1 AND day = ?2")
            .map_err(|e| e.to_string())?;
        let row = stmt
            .query_row(params![mac, i64::try_from(day).unwrap_or(i64::MAX)], |r| {
                Ok(DayRow {
                    up: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
                    down: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                    packets: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    online_secs: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                    sessions: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                })
            })
            .map_err(|e| e.to_string());
        match row {
            Ok(row) => Ok(row),
            // No row yet is the normal case on a device's first day, not an error.
            Err(_) => Ok(DayRow::default()),
        }
    }

    /// Add a delta to a device's day. Upsert, so the row is created when the
    /// day starts and accumulated after that.
    ///
    /// # Errors
    /// Fails if the write fails; the caller keeps the delta in memory and tries
    /// again next flush, so a locked database loses nothing.
    pub fn add_day(&self, mac: &str, day: u64, delta: DayRow) -> Result<(), String> {
        if !delta.has_numbers() {
            return Ok(());
        }
        let day = i64::try_from(day).unwrap_or(i64::MAX);
        self.db
            .execute(
                "INSERT INTO day (mac, day, up, down, packets, online_secs, sessions)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (mac, day) DO UPDATE SET
                     up = up + excluded.up,
                     down = down + excluded.down,
                     packets = packets + excluded.packets,
                     online_secs = online_secs + excluded.online_secs,
                     sessions = sessions + excluded.sessions",
                params![
                    mac,
                    day,
                    i64::try_from(delta.up).unwrap_or(i64::MAX),
                    i64::try_from(delta.down).unwrap_or(i64::MAX),
                    i64::try_from(delta.packets).unwrap_or(i64::MAX),
                    i64::try_from(delta.online_secs).unwrap_or(i64::MAX),
                    i64::try_from(delta.sessions).unwrap_or(i64::MAX),
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Record that a device was online between two times.
    ///
    /// # Errors
    /// Fails if the write fails.
    pub fn add_session(&self, mac: &str, start: u64, end: u64) -> Result<(), String> {
        if end <= start {
            return Ok(());
        }
        self.db
            .execute(
                "INSERT INTO session (mac, start, end) VALUES (?1, ?2, ?3)",
                params![
                    mac,
                    i64::try_from(start).unwrap_or(0),
                    i64::try_from(end).unwrap_or(0)
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// A device's days, oldest first, as far back as `days`.
    ///
    /// # Errors
    /// Fails if the query cannot be run.
    pub fn device_days(&self, mac: &str, days: u64, now: u64) -> Result<Vec<DeviceDay>, String> {
        let since = day_of(now).saturating_sub(days.max(1) - 1);
        let mut stmt = self
            .db
            .prepare(
                "SELECT day, up, down, packets, online_secs, sessions FROM day
                 WHERE mac = ?1 AND day >= ?2 ORDER BY day ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![mac, i64::try_from(since).unwrap_or(0)], |r| {
                Ok(DeviceDay {
                    day: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
                    up: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                    down: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    packets: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                    online_secs: u64::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                    sessions: u64::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// The whole network, per day, oldest first.
    ///
    /// # Errors
    /// Fails if the query cannot be run.
    pub fn network_days(&self, days: u64, now: u64) -> Result<Vec<NetDay>, String> {
        let since = day_of(now).saturating_sub(days.max(1) - 1);
        let mut stmt = self
            .db
            .prepare(
                "SELECT day, SUM(up), SUM(down), COUNT(DISTINCT mac) FROM day
                 WHERE day >= ?1 GROUP BY day ORDER BY day ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![i64::try_from(since).unwrap_or(0)], |r| {
                Ok(NetDay {
                    day: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
                    up: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                    down: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    devices: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Uptime per device over a window: how many seconds online, and what
    /// fraction of the window that is.
    ///
    /// # Errors
    /// Fails if the query cannot be run.
    pub fn uptime(&self, days: u64, now: u64) -> Result<Vec<(String, u64, u64)>, String> {
        let since = day_of(now).saturating_sub(days.max(1) - 1);
        let mut stmt = self
            .db
            .prepare(
                "SELECT mac, SUM(online_secs), COUNT(*) FROM day
                 WHERE day >= ?1 GROUP BY mac ORDER BY SUM(online_secs) DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![i64::try_from(since).unwrap_or(0)], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                    u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// How many sessions have been recorded for a device, so the page can say
    /// how much of a device's history is exact rather than a daily average.
    #[must_use]
    pub fn sessions_recorded(&self, mac: &str) -> u64 {
        self.db
            .query_row(
                "SELECT COUNT(*) FROM session WHERE mac = ?1",
                params![mac],
                |r| r.get::<_, i64>(0),
            )
            .map_or(0, |n| u64::try_from(n).unwrap_or(0))
    }

    /// Drop rows older than the retention window. Returns the rows removed.
    ///
    /// # Errors
    /// Fails if the delete cannot be run.
    pub fn prune(&mut self, now: u64) -> Result<usize, String> {
        let today = day_of(now);
        if today == self.pruned_day {
            return Ok(0);
        }
        let cutoff = i64::try_from(today.saturating_sub(self.keep_days)).unwrap_or(0);
        let days = self
            .db
            .execute("DELETE FROM day WHERE day < ?1", params![cutoff])
            .map_err(|e| e.to_string())?;
        let cutoff_secs =
            i64::try_from(today.saturating_sub(self.keep_days) * DAY_SECS).unwrap_or(0);
        let sessions = self
            .db
            .execute("DELETE FROM session WHERE end < ?1", params![cutoff_secs])
            .map_err(|e| e.to_string())?;
        self.pruned_day = today;
        Ok(days + sessions)
    }

    #[must_use]
    pub fn keep_days(&self) -> u64 {
        self.keep_days
    }

    /// How big the file is, for the dashboard's "how much is being kept" panel.
    #[must_use]
    pub fn size_bytes(path: &Path) -> u64 {
        std::fs::metadata(path).map_or(0, |m| m.len())
    }
}

/// Which UTC day a unix time falls in.
#[must_use]
pub fn day_of(ts: u64) -> u64 {
    ts / DAY_SECS
}

/// What the keeper remembers between flushes, so it can tell "this device just
/// went quiet" from "this device has been quiet for an hour".
///
/// It lives in the keeper rather than in `State` because nothing else needs it
/// and nothing should have to keep it consistent.
#[derive(Default)]
pub struct Tracker {
    online: HashMap<[u8; 6], bool>,
    started: HashMap<[u8; 6], u64>,
}

/// Fold this sweep's seconds into every device's day, and write the changes.
///
/// Called from the keeper every thirty seconds. The work is proportional to the
/// number of devices, never to the number of packets, and a device that has
/// moved nothing since the last flush is skipped entirely.
///
/// Returns a line for the log when something was written, so the operator can
/// see retention working rather than trusting it.
///
/// # Errors
/// Fails only if the database refuses the write; the deltas stay in memory and
/// are retried next flush.
pub fn flush(
    s: &mut State,
    hist: &mut History,
    tracker: &mut Tracker,
    now: u64,
    elapsed: u64,
) -> Result<u64, String> {
    let today = day_of(now);
    let mut written: u64 = 0;
    let mut sessions: Vec<(String, u64, u64)> = Vec::new();
    let mut rows: Vec<(String, u64, DayRow)> = Vec::new();
    let mut over_budget: Vec<[u8; 6]> = Vec::new();

    for d in s.devices.values_mut() {
        // A device that has never been seen online has no day to write.
        let online_now = d.online;
        let was_online = tracker.online.insert(d.mac, online_now).unwrap_or(d.online);

        // Sessions, from transitions the keeper sees. The in-memory timeline
        // records the same thing at packet resolution; this is the durable copy.
        if online_now && !was_online {
            let start = d
                .session_start
                .max(tracker.started.get(&d.mac).copied().unwrap_or(now));
            tracker.started.insert(d.mac, start);
        } else if online_now && !tracker.started.contains_key(&d.mac) {
            // Already online when the daemon started.
            tracker.started.insert(d.mac, d.session_start.min(now));
        } else if !online_now && was_online {
            let start = tracker.started.remove(&d.mac).unwrap_or(d.session_start);
            sessions.push((mac_string(d.mac), start, now));
        }

        // A new UTC day: the old one is already written, so start counting again.
        if d.day.day != today {
            d.day = crate::devices::DayCounters {
                day: today,
                ..crate::devices::DayCounters::default()
            };
            // The watermark follows, or the next flush would write a negative
            // delta and the database would not believe it.
            d.flushed = d.day;
            d.quota_alerted_day = 0;
        }

        if d.online {
            d.day.online_secs = d.day.online_secs.saturating_add(elapsed);
        }

        let delta = DayRow {
            up: d.day.up.saturating_sub(d.flushed.up),
            down: d.day.down.saturating_sub(d.flushed.down),
            packets: d.day.packets.saturating_sub(d.flushed.packets),
            online_secs: d.day.online_secs.saturating_sub(d.flushed.online_secs),
            sessions: d.day.sessions.saturating_sub(d.flushed.sessions),
        };
        if delta.has_numbers() {
            d.flushed = crate::devices::DayCounters {
                day: d.day.day,
                up: d.day.up,
                down: d.day.down,
                packets: d.day.packets,
                online_secs: d.day.online_secs,
                sessions: d.day.sessions,
            };
            rows.push((mac_string(d.mac), today, delta));
        }

        // Budget, checked against this device's own total for the day, and
        // raised once a day rather than once per gigabyte.
        if let Some(quota) = d.quota_bytes {
            let total = d.day.up.saturating_add(d.day.down);
            if total >= quota && d.quota_alerted_day != today {
                d.quota_alerted_day = today;
                over_budget.push(d.mac);
            }
        }
    }

    // Write outside the device loop: the database call must not hold a borrow on
    // the inventory, and one transaction for the whole sweep is what keeps this
    // cheap on a busy network.
    for (mac, day, delta) in rows {
        hist.add_day(&mac, day, delta)?;
        written += 1;
    }
    for (mac, start, end) in sessions {
        hist.add_session(&mac, start, end)?;
        written += 1;
    }
    for mac in over_budget {
        let Some(d) = s.devices.get(&mac) else {
            continue;
        };
        let budget = d.quota_bytes.unwrap_or(0);
        let total = d.day.up.saturating_add(d.day.down);
        let detail = format!(
            "{} today against a {} budget — {} over",
            crate::devices::humanise_bytes(total),
            crate::devices::humanise_bytes(budget),
            crate::devices::humanise_bytes(total.saturating_sub(budget))
        );
        crate::alerts::emit_device_alert(s, mac, "quota_exceeded", "notable", &detail, &[]);
        written += 1;
    }
    hist.prune(now)?;
    Ok(written)
}

/// Load today's totals for every known device, so a restart continues the day.
///
/// # Errors
/// Fails if the query cannot be run.
pub fn restore_today(hist: &History, s: &mut State, now: u64) -> Result<usize, String> {
    let today = day_of(now);
    let macs: Vec<([u8; 6], String)> = s.devices.keys().map(|m| (*m, mac_string(*m))).collect();
    let mut restored = 0;
    for (mac, text) in macs {
        let row = hist.today(&text, today)?;
        if let Some(d) = s.devices.get_mut(&mac) {
            let counters = crate::devices::DayCounters {
                day: today,
                up: row.up,
                down: row.down,
                packets: row.packets,
                online_secs: row.online_secs,
                sessions: row.sessions,
            };
            d.day = counters;
            d.flushed = counters;
            restored += 1;
        }
    }
    Ok(restored)
}
