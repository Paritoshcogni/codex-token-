//! Reads OpenCode V2 session history from its SQLite database and streams
//! their command history.
//!
//! OpenCode stores every session in one WAL-mode SQLite database at
//! `$XDG_DATA_HOME/opencode/opencode.db` (fallback `~/.local/share`). Tool
//! calls live in `part.data` JSON; a shell call is
//! `{"type":"tool","tool":"bash","callID":…,"state":{"status","input":
//! {"command"},"output","metadata":{"exit"}}}`.
//!
//! Access is strictly read-only (design D4): rtk never creates, migrates or
//! recovers another application's database. A missing database means "no
//! OpenCode history" (silent); an unreadable one is a clean
//! "provider unavailable" error, never a panic and never a silent zero.
//!
//! Verified against OpenCode v2.0.29.

// The provider is wired into `discover::run` by the `--agent` task of this
// change; until that lands nothing outside tests constructs it.
#![allow(dead_code)]

use super::provider::{ExtractedCommand, ProjectFilter, SessionProvider, SessionRef};
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, params};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Max chars of tool output kept for error detection, mirroring the ~1000-char
/// window Claude's extractor uses.
const OUTPUT_CONTENT_MAX: usize = 1000;

/// Default database location: `$XDG_DATA_HOME/opencode/opencode.db`, falling
/// back to `~/.local/share/opencode/opencode.db` where the XDG base is unset.
pub fn db_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("opencode").join("opencode.db"))
}

/// Session provider backed by OpenCode's SQLite store.
pub struct OpenCodeProvider {
    db: PathBuf,
}

impl Default for OpenCodeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenCodeProvider {
    /// Provider for the user's real OpenCode database (if the platform
    /// resolves a data dir at all).
    pub fn new() -> Self {
        Self {
            db: db_path().unwrap_or_else(|| PathBuf::from("opencode/opencode.db")),
        }
    }

    /// Provider for an explicit database path (tests).
    pub fn with_db_path(db: PathBuf) -> Self {
        Self { db }
    }

    /// Whether OpenCode storage exists at all. A never-installed OpenCode must
    /// stay fully silent (design D4).
    pub fn available(&self) -> bool {
        self.db.is_file()
    }

    /// Open the database strictly read-only. WAL-mode files that need
    /// `-wal`/`-shm` recovery fail here with `SQLITE_CANTOPEN` while OpenCode
    /// runs; that surfaces as a "provider unavailable" error the caller turns
    /// into a warning — rtk never recovers another application's WAL.
    fn connect(&self) -> Result<Connection> {
        Connection::open_with_flags(&self.db, OpenFlags::SQLITE_OPEN_READ_ONLY).with_context(|| {
            format!(
                "OpenCode provider unavailable: cannot open {} read-only",
                self.db.display()
            )
        })
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

impl SessionProvider for OpenCodeProvider {
    fn discover_sessions(
        &self,
        filter: ProjectFilter<'_>,
        since_days: Option<u64>,
    ) -> Result<Vec<SessionRef>> {
        if !self.available() {
            return Ok(Vec::new());
        }
        let conn = self.connect()?;

        // `session.time_created` is epoch milliseconds (verified against a
        // live store); the cutoff converts days to ms.
        let mut conditions: Vec<String> = Vec::new();
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(days) = since_days {
            conditions.push("time_created >= ?".to_string());
            args.push(Box::new(now_millis() - (days as i64) * 86_400_000));
        }
        match filter {
            ProjectFilter::All => {}
            ProjectFilter::CurrentProject(dir) => {
                // OpenCode records the plain working directory per session.
                conditions.push("directory = ?".to_string());
                args.push(Box::new(dir.to_string_lossy().into_owned()));
            }
            ProjectFilter::Substring(s) => {
                conditions.push("directory LIKE '%' || ? || '%'".to_string());
                args.push(Box::new(s.to_string()));
            }
        }
        let sql = format!(
            "SELECT id FROM session{} ORDER BY time_created DESC, id",
            if conditions.is_empty() {
                String::new()
            } else {
                format!(" WHERE {}", conditions.join(" AND "))
            }
        );
        let mut stmt = conn.prepare_cached(&sql).context(
            "OpenCode provider unavailable: session query failed (corrupt or locked store)",
        )?;
        let refs = stmt
            .query_map(
                rusqlite::params_from_iter(args.iter().map(|p| p.as_ref())),
                |row| {
                    Ok(SessionRef::OpenCode {
                        session_id: row.get(0)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()
            .context("OpenCode provider unavailable: session scan failed")?;
        Ok(refs)
    }

    fn extract_commands(&self, session: &SessionRef) -> Result<Vec<ExtractedCommand>> {
        let SessionRef::OpenCode { session_id } = session else {
            return Err(anyhow::anyhow!(
                "OpenCodeProvider cannot read {}",
                session.display()
            ));
        };
        let conn = self.connect()?;
        // Filtering and field mapping happen in SQL (design D5); malformed
        // rows yield NULLs and are skipped per fail-open, never an error.
        let mut stmt = conn
            .prepare_cached(
                "SELECT json_extract(data, '$.callID'),
                        json_extract(data, '$.state.input.command'),
                        json_extract(data, '$.state.output'),
                        json_extract(data, '$.state.status'),
                        json_extract(data, '$.state.metadata.exit')
                 FROM part
                 WHERE session_id = ?1
                   AND json_extract(data, '$.type') = 'tool'
                   AND json_extract(data, '$.tool') IN ('bash', 'shell')
                 ORDER BY time_created, id",
            )
            .context(
                "OpenCode provider unavailable: part query failed (corrupt or locked store)",
            )?;
        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .context("OpenCode provider unavailable: part scan failed")?;

        let mut commands = Vec::new();
        for (call_id, command, output, status, exit) in rows {
            let Some(command) = command else { continue };
            let is_error = status.as_deref() != Some("completed") || exit.is_some_and(|e| e != 0);
            let output_content = output
                .as_ref()
                .map(|o| truncate_chars(o, OUTPUT_CONTENT_MAX).to_string());
            commands.push(ExtractedCommand {
                command,
                output_len: output.as_ref().map(|o| o.len()),
                session_id: session_id.clone(),
                tool_use_id: call_id.unwrap_or_default(),
                output_content,
                is_error,
                sequence_index: commands.len(),
            });
        }
        Ok(commands)
    }
}

/// First `max` chars of `s` (char-safe, unlike a byte slice).
fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::path::Path;
    use tempfile::NamedTempFile;

    /// Minimal mirror of OpenCode's real schema (v2.0.29) with the columns
    /// this provider reads; seeded JSON only, never real user data.
    fn seed_db() -> (NamedTempFile, Connection) {
        let file = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(file.path()).expect("open sqlite");
        conn.execute_batch(
            "CREATE TABLE session (
                id TEXT PRIMARY KEY,
                directory TEXT NOT NULL,
                time_created INTEGER NOT NULL
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                data TEXT NOT NULL
            );",
        )
        .expect("schema");
        (file, conn)
    }

    fn insert_session(conn: &Connection, id: &str, directory: &str, time_created: i64) {
        conn.execute(
            "INSERT INTO session (id, directory, time_created) VALUES (?1, ?2, ?3)",
            params![id, directory, time_created],
        )
        .unwrap();
    }

    /// Insert one tool part. `exit` of `None` omits `metadata.exit` entirely,
    /// matching how OpenCode writes errored calls.
    fn insert_tool_part(
        conn: &Connection,
        session_id: &str,
        part_id: &str,
        time_created: i64,
        _tool: &str,
        data_json: &str,
    ) {
        conn.execute(
            "INSERT INTO message (id, session_id, time_created, data) VALUES (?1, ?2, ?3, '{}')",
            params![format!("m_{part_id}"), session_id, time_created],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![part_id, format!("m_{part_id}"), session_id, time_created, data_json],
        )
        .unwrap();
    }

    fn bash_json(command: &str, output: &str, status: &str, exit: Option<i64>) -> String {
        let mut state = serde_json::Map::new();
        state.insert("status".into(), status.into());
        state.insert("input".into(), serde_json::json!({ "command": command }));
        state.insert("output".into(), output.into());
        if let Some(e) = exit {
            state.insert("metadata".into(), serde_json::json!({ "exit": e }));
        }
        let mut root = serde_json::Map::new();
        root.insert("type".into(), "tool".into());
        root.insert("tool".into(), "bash".into());
        root.insert("callID".into(), format!("call_{command}").into());
        root.insert("state".into(), serde_json::Value::Object(state));
        serde_json::Value::Object(root).to_string()
    }

    fn opencode_ref(id: &str) -> SessionRef {
        SessionRef::OpenCode {
            session_id: id.to_string(),
        }
    }

    fn extract(file: &Path, session: &str) -> Vec<ExtractedCommand> {
        OpenCodeProvider::with_db_path(file.to_path_buf())
            .extract_commands(&opencode_ref(session))
            .expect("extract")
    }

    #[test]
    fn extracts_bash_commands_with_fields() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        insert_tool_part(
            &conn,
            "s1",
            "p1",
            1_700_000_000_001,
            "bash",
            &bash_json("git status", "clean", "completed", Some(0)),
        );
        insert_tool_part(
            &conn,
            "s1",
            "p2",
            1_700_000_000_002,
            "bash",
            &bash_json("cargo test", "ok", "completed", Some(0)),
        );

        let cmds = extract(f.path(), "s1");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "git status");
        assert_eq!(cmds[0].tool_use_id, "call_git status");
        assert_eq!(cmds[0].output_len, Some(5));
        assert_eq!(cmds[0].output_content.as_deref(), Some("clean"));
        assert!(!cmds[0].is_error);
        assert_eq!(cmds[1].command, "cargo test");
        assert_eq!(cmds[0].session_id, "s1");
    }

    #[test]
    fn ignores_non_bash_tools() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        for (id, tool) in [("p1", "edit"), ("p2", "read"), ("p3", "grep")] {
            insert_tool_part(
                &conn,
                "s1",
                id,
                1_700_000_000_000,
                tool,
                &format!(
                    "{{\"type\":\"tool\",\"tool\":\"{tool}\",\"callID\":\"c\",\"state\":{{\"status\":\"completed\",\"input\":{{\"command\":\"not-a-shell\"}},\"output\":\"x\"}}}}"
                ),
            );
        }
        assert!(extract(f.path(), "s1").is_empty());
    }

    #[test]
    fn ignores_non_tool_parts() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        for (id, kind) in [("p1", "text"), ("p2", "reasoning"), ("p3", "step-finish")] {
            insert_tool_part(
                &conn,
                "s1",
                id,
                1_700_000_000_000,
                kind,
                &format!("{{\"type\":\"{kind}\",\"text\":\"hi\"}}"),
            );
        }
        assert!(extract(f.path(), "s1").is_empty());
    }

    #[test]
    fn detects_error_via_status() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        insert_tool_part(
            &conn,
            "s1",
            "p1",
            1_700_000_000_001,
            "bash",
            &bash_json("false", "boom", "error", None),
        );

        let cmds = extract(f.path(), "s1");
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].is_error);
    }

    #[test]
    fn detects_error_via_exit_code() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        insert_tool_part(
            &conn,
            "s1",
            "p1",
            1_700_000_000_001,
            "bash",
            &bash_json("test -f nope", "no", "completed", Some(1)),
        );

        let cmds = extract(f.path(), "s1");
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].is_error);
    }

    #[test]
    fn truncates_output_content_keeps_full_length() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        let big = "x".repeat(5_000);
        insert_tool_part(
            &conn,
            "s1",
            "p1",
            1_700_000_000_001,
            "bash",
            &bash_json("ls", &big, "completed", Some(0)),
        );

        let cmds = extract(f.path(), "s1");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].output_len, Some(5_000));
        let content = cmds[0].output_content.as_deref().unwrap();
        assert_eq!(content.chars().count(), OUTPUT_CONTENT_MAX);
    }

    #[test]
    fn returns_commands_in_chronological_order() {
        let (f, conn) = seed_db();
        insert_session(&conn, "s1", "/home/u/proj", 1_700_000_000_000);
        // Insert newest first so insertion order cannot mask the sort.
        insert_tool_part(
            &conn,
            "s1",
            "p3",
            1_700_000_000_030,
            "bash",
            &bash_json("third", "", "completed", Some(0)),
        );
        insert_tool_part(
            &conn,
            "s1",
            "p1",
            1_700_000_000_010,
            "bash",
            &bash_json("first", "", "completed", Some(0)),
        );
        insert_tool_part(
            &conn,
            "s1",
            "p2",
            1_700_000_000_020,
            "bash",
            &bash_json("second", "", "completed", Some(0)),
        );

        let cmds = extract(f.path(), "s1");
        let order: Vec<&str> = cmds.iter().map(|c| c.command.as_str()).collect();
        assert_eq!(order, ["first", "second", "third"]);
        let idx: Vec<usize> = cmds.iter().map(|c| c.sequence_index).collect();
        assert_eq!(idx, [0, 1, 2]);
    }

    // -- fail-open (task 3.3) ----------------------------------------------

    #[test]
    fn missing_db_stays_silent() {
        let provider = OpenCodeProvider::with_db_path(PathBuf::from("/nonexistent/opencode.db"));
        assert!(!provider.available());
        let sessions = provider
            .discover_sessions(ProjectFilter::All, None)
            .expect("missing store is not an error");
        assert!(sessions.is_empty());
    }

    #[test]
    fn corrupt_db_is_a_clean_unavailable_error() {
        let f = NamedTempFile::new().expect("tempfile");
        std::fs::write(f.path(), b"definitely not a sqlite database").expect("write");
        let provider = OpenCodeProvider::with_db_path(f.path().to_path_buf());
        assert!(provider.available());
        let err = provider
            .discover_sessions(ProjectFilter::All, None)
            .expect_err("corrupt store must surface an error, never a silent zero");
        assert!(err.to_string().contains("unavailable"), "{err}");
        // Extraction path maps the same failure.
        let err = provider
            .extract_commands(&opencode_ref("s1"))
            .expect_err("corrupt store must surface an error");
        assert!(err.to_string().contains("unavailable"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_db_maps_to_unavailable_not_panic() {
        use std::os::unix::fs::PermissionsExt;
        // A file that stats but cannot be opened yields SQLITE_CANTOPEN — the
        // same error class as WAL recovery being needed while OpenCode runs.
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("opencode.db");
        drop(Connection::open(&db).expect("create"));
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let provider = OpenCodeProvider::with_db_path(db.clone());
        assert!(provider.available());
        let err = provider
            .discover_sessions(ProjectFilter::All, None)
            .expect_err("unreadable store must surface an error, never a silent zero");
        assert!(err.to_string().contains("unavailable"), "{err}");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).expect("restore");
    }

    // -- filters (task 3.4) --------------------------------------------------

    fn ids(refs: &[SessionRef]) -> Vec<String> {
        refs.iter()
            .map(|r| match r {
                SessionRef::OpenCode { session_id } => session_id.clone(),
                SessionRef::File(_) => unreachable!(),
            })
            .collect()
    }

    fn seeded_store() -> (NamedTempFile, Connection) {
        let (f, conn) = seed_db();
        let now = now_millis();
        insert_session(&conn, "old", "/home/u/alpha", now - 40 * 86_400_000);
        insert_session(&conn, "recent", "/home/u/alpha", now - 86_400_000);
        insert_session(&conn, "other", "/home/u/beta", now - 2 * 86_400_000);
        (f, conn)
    }

    #[test]
    fn since_cutoff_excludes_older_sessions() {
        let (f, _conn) = seeded_store();
        let provider = OpenCodeProvider::with_db_path(f.path().to_path_buf());
        let recent = provider
            .discover_sessions(ProjectFilter::All, Some(30))
            .unwrap();
        assert_eq!(ids(&recent), ["recent", "other"]); // newest first
        let everything = provider
            .discover_sessions(ProjectFilter::All, None)
            .unwrap();
        assert_eq!(everything.len(), 3);
    }

    #[test]
    fn current_project_matches_directory_exactly() {
        let (f, conn) = seeded_store();
        insert_session(&conn, "nested", "/home/u/alpha/sub", 1);
        let provider = OpenCodeProvider::with_db_path(f.path().to_path_buf());
        let found = provider
            .discover_sessions(
                ProjectFilter::CurrentProject(Path::new("/home/u/alpha")),
                None,
            )
            .unwrap();
        // Newest first; the `/sub` sibling must not leak in via exact match.
        assert_eq!(ids(&found), ["recent", "old"]);
        assert!(!ids(&found).contains(&"nested".to_string()));
    }

    #[test]
    fn substring_filter_matches_directory_like() {
        let (f, _conn) = seeded_store();
        let provider = OpenCodeProvider::with_db_path(f.path().to_path_buf());
        let found = provider
            .discover_sessions(ProjectFilter::Substring("bet"), None)
            .unwrap();
        assert_eq!(ids(&found), ["other"]);
    }

    #[test]
    fn all_filter_includes_every_session() {
        let (f, _conn) = seeded_store();
        let provider = OpenCodeProvider::with_db_path(f.path().to_path_buf());
        assert_eq!(
            provider
                .discover_sessions(ProjectFilter::All, None)
                .unwrap()
                .len(),
            3
        );
    }
}
