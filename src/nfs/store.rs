//! Private, transactional metadata storage using the embedded Turso engine.
//! Database lifetime and serialization are owned by one share backend. No cloud
//! connection or sync is configured, and file contents never enter this store.
use anyhow::{Context, Result, bail};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use tokio::sync::Mutex;
pub type Change<'a> = (&'a str, &'a [u8], Option<&'a [u8]>);

pub struct Store {
    _database: turso::Database,
    connection: Mutex<turso::Connection>,
    // The daemon owns the store across all sessions. A second process must not
    // run a conflicting NFS recovery epoch against the same database.
    _lock: fs::File,
}

impl Store {
    pub async fn open(directory: &Path) -> Result<Self> {
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            bail!("NFS metadata directory must be a private directory owned by this user");
        }
        let lock = private_file(&directory.join("owner.lock"))?;
        lock.try_lock().context("NFS metadata is already in use")?;
        let path = directory.join("metadata.db");
        let _file = private_file(&path)?;
        let _wal = private_file(&directory.join("metadata.db-wal"))?;
        // Turso opens sidecars by name. Reject pre-existing unsafe sidecars too.
        for name in ["metadata.db-wal", "metadata.db-shm"] {
            let p = directory.join(name);
            match fs::symlink_metadata(&p) {
                Ok(_) => {
                    let _ = private_file(&p)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let database =
            turso::Builder::new_local(path.to_str().context("NFS metadata path is not UTF-8")?)
                .build()
                .await?;
        let connection = database.connect()?;
        connection.execute("PRAGMA synchronous=FULL", ()).await?;
        connection.execute("CREATE TABLE IF NOT EXISTS metadata (kind TEXT NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY (kind, key))", ()).await?;
        let result = Self {
            _database: database,
            connection: Mutex::new(connection),
            _lock: lock,
        };
        match result.get("schema", b"version").await? {
            Some(v) if v != b"1" => bail!("unsupported NFS metadata schema"),
            Some(_) => {}
            None => result.put("schema", b"version", b"1").await?,
        }
        Ok(result)
    }

    pub async fn get(&self, kind: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT value FROM metadata WHERE kind=?1 AND key=?2",
                (kind, key),
            )
            .await?;
        Ok(match rows.next().await? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }
    pub async fn list(&self, kind: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT key,value FROM metadata WHERE kind=?1 ORDER BY key",
                [kind],
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push((row.get(0)?, row.get(1)?));
        }
        Ok(out)
    }
    pub async fn put(&self, kind: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch(&[(kind, key, Some(value))]).await
    }
    pub async fn remove(&self, kind: &str, key: &[u8]) -> Result<()> {
        self.batch(&[(kind, key, None)]).await
    }
    /// All entries commit together. Cancellation rolls back before the next
    /// connection operation; Turso also rolls back incomplete WAL transactions.
    pub async fn batch(&self, changes: &[Change<'_>]) -> Result<()> {
        let mut conn = self.connection.lock().await;
        let tx = conn.transaction().await?;
        for (kind, key, value) in changes {
            match value {
                Some(value) => {
                    tx.execute("INSERT INTO metadata(kind,key,value) VALUES(?1,?2,?3) ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value", (*kind, *key, *value)).await?;
                }
                None => {
                    tx.execute(
                        "DELETE FROM metadata WHERE kind=?1 AND key=?2",
                        (*kind, *key),
                    )
                    .await?;
                }
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

fn private_file(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.uid() != unsafe { libc::geteuid() }
    {
        bail!("unsafe NFS metadata file {}", path.display());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reopen_atomic_changes_and_locking() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        let store = Store::open(&dir).await.unwrap();
        store
            .batch(&[
                ("handles", b"a", Some(b"one")),
                ("recovery", b"b", Some(b"two")),
            ])
            .await
            .unwrap();
        assert!(Store::open(&dir).await.is_err());
        drop(store);
        let store = Store::open(&dir).await.unwrap();
        assert_eq!(
            store.get("handles", b"a").await.unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            store.list("recovery").await.unwrap(),
            vec![(b"b".to_vec(), b"two".to_vec())]
        );
        store.remove("handles", b"a").await.unwrap();
        assert!(store.get("handles", b"a").await.unwrap().is_none());
    }
    #[tokio::test]
    async fn rejects_symlinks_and_public_directories() {
        let temp = tempfile::tempdir().unwrap();
        let public = temp.path().join("public");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open(&public).await.is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&public, &link).unwrap();
        assert!(Store::open(&link).await.is_err());
        let private = temp.path().join("private");
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        std::os::unix::fs::symlink(temp.path().join("victim"), private.join("metadata.db"))
            .unwrap();
        assert!(Store::open(&private).await.is_err());
        assert!(!temp.path().join("victim").exists());
    }
}
