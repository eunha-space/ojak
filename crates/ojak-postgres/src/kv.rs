//! The key-value store, in a table of its own.
//!
//! Entries live in one table, `ojak_kv` unless named otherwise, created by
//! [`PostgresKvStore::initialize`] if it is not there. A key is stored as the
//! JSON array of its segments, so that no two keys share a row whatever
//! their segments hold, and a value as JSON text rather than `jsonb`, which
//! refuses a string with NUL in it; a cached document is whatever a peer
//! sent. An expired entry is ignored until [`PostgresKvStore::prune_expired`]
//! removes it.

use crate::table_name;
use ojak::kv::{KvError, KvStore};
use serde_json::Value;
use sqlx::PgPool;
use std::time::Duration;

/// A [`KvStore`] in a PostgreSQL table.
#[derive(Clone, Debug)]
pub struct PostgresKvStore {
    pool: PgPool,
    table: String,
}

impl PostgresKvStore {
    /// A store in the table `ojak_kv`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            table: "ojak_kv".to_owned(),
        }
    }

    /// A store in the table `table`, which may be prefixed by its schema.
    ///
    /// # Errors
    ///
    /// When `table` is not a plain SQL identifier.
    pub fn with_table(pool: PgPool, table: &str) -> Result<Self, KvError> {
        Ok(Self {
            pool,
            table: table_name(table).map_err(KvError)?,
        })
    }

    /// Create the table and its index if they do not exist. Safe to run from
    /// every process at start-up.
    ///
    /// # Errors
    ///
    /// When the database refuses.
    pub async fn initialize(&self) -> Result<(), KvError> {
        for statement in Self::schema(&self.table) {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .map_err(error)?;
        }
        Ok(())
    }

    /// The statements that create a store table named `table` and its
    /// index, each safe to run again, for an application to put in a
    /// migration of its own.
    #[must_use]
    pub fn schema(table: &str) -> Vec<String> {
        let index = format!("{}_expires", table.replace('.', "_"));
        vec![
            format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMPTZ
                )"
            ),
            format!(
                "CREATE INDEX IF NOT EXISTS {index} ON {table} (expires_at) \
                 WHERE expires_at IS NOT NULL"
            ),
        ]
    }

    /// Delete expired entries.
    ///
    /// # Errors
    ///
    /// When the database refuses.
    pub async fn prune_expired(&self) -> Result<u64, KvError> {
        let result = sqlx::query(&format!(
            "DELETE FROM {} WHERE expires_at <= now()",
            self.table
        ))
        .execute(&self.pool)
        .await
        .map_err(error)?;
        Ok(result.rows_affected())
    }
}

fn error(error: sqlx::Error) -> KvError {
    KvError(error.to_string())
}

fn encode_key(key: &[&str]) -> Result<String, KvError> {
    serde_json::to_string(key).map_err(|error| KvError(error.to_string()))
}

fn encode_value(value: &Value) -> Result<String, KvError> {
    serde_json::to_string(value).map_err(|error| KvError(error.to_string()))
}

fn seconds(ttl: Option<Duration>) -> Option<f64> {
    ttl.map(|ttl| ttl.as_secs_f64())
}

/// The expiry column's value for a TTL in `$3`.
const EXPIRES: &str = "CASE WHEN $3::float8 IS NULL THEN NULL \
                       ELSE now() + make_interval(secs => $3::float8) END";

impl KvStore for PostgresKvStore {
    async fn get(&self, key: &[&str]) -> Result<Option<Value>, KvError> {
        let value: Option<String> = sqlx::query_scalar(&format!(
            "SELECT value FROM {} WHERE key = $1 AND (expires_at IS NULL OR expires_at > now())",
            self.table
        ))
        .bind(encode_key(key)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(error)?;
        value
            .map(|value| serde_json::from_str(&value).map_err(|error| KvError(error.to_string())))
            .transpose()
    }

    async fn set(&self, key: &[&str], value: Value, ttl: Option<Duration>) -> Result<(), KvError> {
        sqlx::query(&format!(
            "INSERT INTO {} (key, value, expires_at) VALUES ($1, $2, {EXPIRES})
             ON CONFLICT (key) DO UPDATE
             SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at",
            self.table
        ))
        .bind(encode_key(key)?)
        .bind(encode_value(&value)?)
        .bind(seconds(ttl))
        .execute(&self.pool)
        .await
        .map_err(error)?;
        Ok(())
    }

    async fn insert(
        &self,
        key: &[&str],
        value: Value,
        ttl: Option<Duration>,
    ) -> Result<bool, KvError> {
        // Of inserts racing on one key, one inserts; the others wait for it
        // on the key's uniqueness, then find a live row and update nothing.
        let table = &self.table;
        let put: Option<i32> = sqlx::query_scalar(&format!(
            "INSERT INTO {table} (key, value, expires_at) VALUES ($1, $2, {EXPIRES})
             ON CONFLICT (key) DO UPDATE
             SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
             WHERE {table}.expires_at <= now()
             RETURNING 1"
        ))
        .bind(encode_key(key)?)
        .bind(encode_value(&value)?)
        .bind(seconds(ttl))
        .fetch_optional(&self.pool)
        .await
        .map_err(error)?;
        Ok(put.is_some())
    }

    async fn delete(&self, key: &[&str]) -> Result<(), KvError> {
        sqlx::query(&format!("DELETE FROM {} WHERE key = $1", self.table))
            .bind(encode_key(key)?)
            .execute(&self.pool)
            .await
            .map_err(error)?;
        Ok(())
    }
}
