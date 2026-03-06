//! ブロックリストホットリロード
//!
//! ファイル変更検出とブロックリストのアトミック入替。
//! mtime ポーリングによる軽量ファイル監視。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// リロード設定。
#[derive(Debug, Clone)]
pub struct ReloadConfig {
    /// 監視対象ファイルパス。
    pub watch_paths: Vec<PathBuf>,
    /// ポーリング間隔 (ミリ秒)。
    pub poll_interval_ms: u64,
    /// リロード時の統計リセット有効。
    pub reset_stats_on_reload: bool,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            poll_interval_ms: 30_000, // 30 秒
            reset_stats_on_reload: false,
        }
    }
}

/// リロードイベント。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadEvent {
    /// ファイルが更新された。
    Updated(PathBuf),
    /// 変更なし。
    NoChange,
    /// エラー発生。
    Error(String),
}

impl core::fmt::Display for ReloadEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Updated(path) => write!(f, "Updated: {}", path.display()),
            Self::NoChange => write!(f, "No change"),
            Self::Error(msg) => write!(f, "Error: {msg}"),
        }
    }
}

/// ファイル変更検出器。
#[derive(Debug)]
pub struct FileWatcher {
    /// ファイル → 最終更新時刻。
    mtimes: HashMap<PathBuf, SystemTime>,
}

impl Default for FileWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl FileWatcher {
    /// 新しいウォッチャーを作成。
    #[must_use]
    pub fn new() -> Self {
        Self {
            mtimes: HashMap::new(),
        }
    }

    /// ファイルの初期状態を記録。
    pub fn register(&mut self, path: &Path) {
        if let Ok(mtime) = Self::get_mtime(path) {
            self.mtimes.insert(path.to_path_buf(), mtime);
        }
    }

    /// ファイルが変更されたか確認。
    pub fn check(&mut self, path: &Path) -> ReloadEvent {
        let current_mtime = match Self::get_mtime(path) {
            Ok(t) => t,
            Err(e) => return ReloadEvent::Error(e),
        };

        let changed = self
            .mtimes
            .get(path)
            .is_none_or(|prev| *prev != current_mtime);

        if changed {
            self.mtimes.insert(path.to_path_buf(), current_mtime);
            ReloadEvent::Updated(path.to_path_buf())
        } else {
            ReloadEvent::NoChange
        }
    }

    /// 全監視ファイルをチェック。
    pub fn check_all(&mut self, paths: &[PathBuf]) -> Vec<ReloadEvent> {
        paths.iter().map(|p| self.check(p)).collect()
    }

    /// 監視ファイル数。
    #[must_use]
    pub fn watched_count(&self) -> usize {
        self.mtimes.len()
    }

    /// ファイルの更新時刻を取得。
    fn get_mtime(path: &Path) -> Result<SystemTime, String> {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map_err(|e| alloc::format!("{}: {e}", path.display()))
    }
}

/// リローダブルブロックリスト。
///
/// ドメインリストをアトミックに入替可能。
#[derive(Debug)]
pub struct ReloadableBlocklist {
    /// 現在のドメインリスト。
    domains: Vec<String>,
    /// 読み込み元パス。
    source_path: Option<PathBuf>,
    /// リロード回数。
    reload_count: u64,
    /// 最終リロード時刻。
    last_reload: Option<SystemTime>,
}

impl Default for ReloadableBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloadableBlocklist {
    /// 空のブロックリストを作成。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            domains: Vec::new(),
            source_path: None,
            reload_count: 0,
            last_reload: None,
        }
    }

    /// ドメインリストを設定。
    pub fn set_domains(&mut self, domains: Vec<String>) {
        self.domains = domains;
        self.reload_count += 1;
        self.last_reload = Some(SystemTime::now());
    }

    /// ファイルからリロード。
    ///
    /// # Errors
    ///
    /// ファイル読み取りに失敗した場合。
    pub fn reload_from_file(&mut self, path: &Path) -> Result<usize, ReloadError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ReloadError::IoError(e.to_string()))?;

        let domains: Vec<String> = crate::blocklist::parse_hosts(&content);
        let count = domains.len();

        self.source_path = Some(path.to_path_buf());
        self.set_domains(domains);

        Ok(count)
    }

    /// ファイル変更をチェックし、必要ならリロード。
    pub fn check_and_reload(&mut self, watcher: &mut FileWatcher) -> ReloadEvent {
        let path = match &self.source_path {
            Some(p) => p.clone(),
            None => return ReloadEvent::NoChange,
        };

        let event = watcher.check(&path);

        if let ReloadEvent::Updated(_) = &event {
            match self.reload_from_file(&path) {
                Ok(_) => return event,
                Err(e) => return ReloadEvent::Error(alloc::format!("{e}")),
            }
        }

        event
    }

    /// 現在のドメイン数。
    #[must_use]
    pub const fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// ドメインリストへの参照。
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// リロード回数。
    #[must_use]
    pub const fn reload_count(&self) -> u64 {
        self.reload_count
    }

    /// ソースパス。
    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }
}

/// リロードエラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadError {
    /// I/O エラー。
    IoError(String),
    /// パースエラー。
    ParseError(String),
}

impl core::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IoError(msg) => write!(f, "IO error: {msg}"),
            Self::ParseError(msg) => write!(f, "Parse error: {msg}"),
        }
    }
}

impl std::error::Error for ReloadError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config() {
        let config = ReloadConfig::default();
        assert_eq!(config.poll_interval_ms, 30_000);
        assert!(config.watch_paths.is_empty());
        assert!(!config.reset_stats_on_reload);
    }

    #[test]
    fn reload_event_display() {
        let updated = ReloadEvent::Updated(PathBuf::from("/tmp/hosts"));
        assert!(updated.to_string().contains("/tmp/hosts"));

        assert_eq!(ReloadEvent::NoChange.to_string(), "No change");

        let err = ReloadEvent::Error("fail".into());
        assert!(err.to_string().contains("fail"));
    }

    #[test]
    fn file_watcher_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hosts.txt");
        std::fs::write(&file_path, "0.0.0.0 ads.example.com\n").unwrap();

        let mut watcher = FileWatcher::new();
        // 未登録ファイルは変更あり
        let event = watcher.check(&file_path);
        assert!(matches!(event, ReloadEvent::Updated(_)));
    }

    #[test]
    fn file_watcher_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hosts.txt");
        std::fs::write(&file_path, "data").unwrap();

        let mut watcher = FileWatcher::new();
        watcher.register(&file_path);

        let event = watcher.check(&file_path);
        assert_eq!(event, ReloadEvent::NoChange);
    }

    #[test]
    fn file_watcher_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hosts.txt");
        std::fs::write(&file_path, "original").unwrap();

        let mut watcher = FileWatcher::new();
        watcher.register(&file_path);

        // 強制的に mtime を変更 (ファイル書き換え)
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.write_all(b"updated").unwrap();
        f.flush().unwrap();
        drop(f);

        let event = watcher.check(&file_path);
        assert!(matches!(event, ReloadEvent::Updated(_)));
    }

    #[test]
    fn file_watcher_nonexistent() {
        let mut watcher = FileWatcher::new();
        let event = watcher.check(Path::new("/nonexistent/path/hosts.txt"));
        assert!(matches!(event, ReloadEvent::Error(_)));
    }

    #[test]
    fn file_watcher_check_all() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");
        std::fs::write(&f1, "a").unwrap();
        std::fs::write(&f2, "b").unwrap();

        let mut watcher = FileWatcher::new();
        watcher.register(&f1);
        watcher.register(&f2);
        assert_eq!(watcher.watched_count(), 2);

        let events = watcher.check_all(&[f1, f2]);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn file_watcher_default() {
        let w = FileWatcher::default();
        assert_eq!(w.watched_count(), 0);
    }

    #[test]
    fn reloadable_blocklist_empty() {
        let bl = ReloadableBlocklist::new();
        assert_eq!(bl.domain_count(), 0);
        assert_eq!(bl.reload_count(), 0);
        assert!(bl.source_path().is_none());
    }

    #[test]
    fn reloadable_blocklist_set_domains() {
        let mut bl = ReloadableBlocklist::new();
        bl.set_domains(vec!["ads.com".into(), "track.com".into()]);
        assert_eq!(bl.domain_count(), 2);
        assert_eq!(bl.reload_count(), 1);
        assert_eq!(bl.domains()[0], "ads.com");
    }

    #[test]
    fn reloadable_blocklist_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hosts.txt");
        std::fs::write(
            &file_path,
            "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com\n# comment\n",
        )
        .unwrap();

        let mut bl = ReloadableBlocklist::new();
        let count = bl.reload_from_file(&file_path).unwrap();
        assert_eq!(count, 2);
        assert_eq!(bl.domain_count(), 2);
        assert!(bl.source_path().is_some());
    }

    #[test]
    fn reloadable_blocklist_from_nonexistent() {
        let mut bl = ReloadableBlocklist::new();
        let result = bl.reload_from_file(Path::new("/nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn reloadable_blocklist_default() {
        let bl = ReloadableBlocklist::default();
        assert_eq!(bl.domain_count(), 0);
    }

    #[test]
    fn check_and_reload_no_source() {
        let mut bl = ReloadableBlocklist::new();
        let mut watcher = FileWatcher::new();
        let event = bl.check_and_reload(&mut watcher);
        assert_eq!(event, ReloadEvent::NoChange);
    }

    #[test]
    fn reload_error_display() {
        assert_eq!(
            ReloadError::IoError("not found".into()).to_string(),
            "IO error: not found"
        );
        assert_eq!(
            ReloadError::ParseError("bad format".into()).to_string(),
            "Parse error: bad format"
        );
    }
}
