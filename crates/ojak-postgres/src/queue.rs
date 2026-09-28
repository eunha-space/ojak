//! The queue, in a table of its own.
//!
//! Jobs live in one table, `ojak_queue` unless named otherwise, created by
//! [`PostgresQueue::initialize`] if it is not there. Every queue — deliveries,
//! and whatever else an application runs through Ojak — shares the table,
//! each claimed separately.
//!
//! A claim is an `UPDATE … FOR UPDATE SKIP LOCKED` that pushes `run_at` out by
//! the lease, so any number of workers in any number of processes can claim
//! from one table without two of them taking the same job, and a job whose
//! worker stopped comes back when its lease lapses. A job that is done is
//! deleted; one given up on keeps its row, with `failed_at` and the last
//! error, until [`PostgresQueue::prune_failed`] removes it.
//!
//! A payload is `jsonb`, which refuses a string with NUL in it, and a payload
//! is often a document a peer sent: one Note with `\u0000` in its content
//! would fail the enqueue, and the activity would be lost. A payload that
//! holds NUL anywhere is stored as its JSON text instead, in which NUL is
//! only ever the escape `\u0000`, wrapped as `{"ojak:json": text}`, and
//! unwrapped when it is claimed. Nothing else changes, so the table needs no
//! migration.

use crate::table_name;
use ojak::queue::{Job, Queue, QueueError};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::time::Duration;

/// A [`Queue`] in a PostgreSQL table.
#[derive(Clone, Debug)]
pub struct PostgresQueue {
    pool: PgPool,
    table: String,
}

impl PostgresQueue {
    /// A queue in the table `ojak_queue`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            table: "ojak_queue".to_owned(),
        }
    }

    /// A queue in the table `table`.
    ///
    /// # Errors
    ///
    /// When `table` is not a plain SQL identifier: ASCII letters, digits and
    /// underscores, not starting with a digit, optionally prefixed by a schema
    /// of the same shape and a dot.
    pub fn with_table(pool: PgPool, table: &str) -> Result<Self, QueueError> {
        Ok(Self {
            pool,
            table: table_name(table).map_err(QueueError)?,
        })
    }

    /// Create the table and its index if they do not exist.
    ///
    /// Safe to run from every process at start-up, including both colours of
    /// a blue/green deploy at once. An application that changes its schema
    /// only through its own migrations creates the table there instead, from
    /// [`PostgresQueue::schema`].
    ///
    /// # Errors
    ///
    /// When the database refuses.
    pub async fn initialize(&self) -> Result<(), QueueError> {
        for statement in Self::schema(&self.table) {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .map_err(error)?;
        }
        Ok(())
    }

    /// The statements that create a queue table named `table` and its index,
    /// each safe to run again. What [`PostgresQueue::initialize`] runs, for an
    /// application to put in a migration of its own.
    #[must_use]
    pub fn schema(table: &str) -> Vec<String> {
        let index = format!("{}_due", table.replace('.', "_"));
        vec![
            format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    id BIGSERIAL PRIMARY KEY,
                    queue TEXT NOT NULL,
                    payload JSONB NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_error TEXT,
                    failed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )"
            ),
            format!(
                "CREATE INDEX IF NOT EXISTS {index} ON {table} (queue, run_at) \
                 WHERE failed_at IS NULL"
            ),
        ]
    }

    /// Delete jobs given up on more than `age` ago.
    ///
    /// # Errors
    ///
    /// When the database refuses.
    pub async fn prune_failed(&self, age: Duration) -> Result<u64, QueueError> {
        let result = sqlx::query(&format!(
            "DELETE FROM {} WHERE failed_at < now() - make_interval(secs => $1)",
            self.table
        ))
        .bind(age.as_secs_f64())
        .execute(&self.pool)
        .await
        .map_err(error)?;
        Ok(result.rows_affected())
    }
}

/// How much of a job's last error is kept.
const MAX_ERROR_CHARS: usize = 2000;

/// An error message made safe to store: without NUL, which PostgreSQL `text`
/// refuses, and bounded.
///
/// A delivery's error can carry part of a peer's response. If recording it
/// failed, the job would keep its lease, be handed out again when the lease
/// lapsed, and never reach its last attempt: a job that cannot be failed is
/// retried forever.
fn storable(error: &str) -> String {
    let cleaned = error.replace('\0', "");
    match cleaned.char_indices().nth(MAX_ERROR_CHARS) {
        Some((end, _)) => format!("{}…", &cleaned[..end]),
        None => cleaned,
    }
}

/// The key a payload stored as its JSON text is wrapped under.
const WRAPPED: &str = "ojak:json";

/// `payload` as `jsonb` can hold it: itself, or, when it holds NUL or could
/// be mistaken for a wrapped payload, its JSON text wrapped.
fn wrap(payload: &Value) -> Value {
    let ambiguous = payload
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.contains_key(WRAPPED));
    if ambiguous || holds_nul(payload) {
        serde_json::json!({ WRAPPED: payload.to_string() })
    } else {
        payload.clone()
    }
}

/// A payload as it was enqueued.
fn unwrap(stored: Value) -> Value {
    if let Some(object) = stored.as_object()
        && object.len() == 1
        && let Some(Value::String(text)) = object.get(WRAPPED)
        && let Ok(payload) = serde_json::from_str(text)
    {
        return payload;
    }
    stored
}

fn holds_nul(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains('\0'),
        Value::Array(items) => items.iter().any(holds_nul),
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key.contains('\0') || holds_nul(value)),
        _ => false,
    }
}

fn error(error: sqlx::Error) -> QueueError {
    QueueError(error.to_string())
}

fn id(id: &str) -> Result<i64, QueueError> {
    id.parse()
        .map_err(|_| QueueError(format!("not a job id: {id}")))
}

impl Queue for PostgresQueue {
    async fn enqueue(&self, queue: &str, payloads: Vec<Value>) -> Result<(), QueueError> {
        if payloads.is_empty() {
            return Ok(());
        }
        sqlx::query(&format!(
            "INSERT INTO {} (queue, payload) SELECT $1, unnest($2::jsonb[])",
            self.table
        ))
        .bind(queue)
        .bind(payloads.iter().map(wrap).collect::<Vec<_>>())
        .execute(&self.pool)
        .await
        .map_err(error)?;
        Ok(())
    }

    async fn claim(
        &self,
        queue: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<Job>, QueueError> {
        let table = &self.table;
        let rows = sqlx::query(&format!(
            "UPDATE {table} SET run_at = now() + make_interval(secs => $3)
             WHERE id IN (
                 SELECT id FROM {table}
                 WHERE queue = $1 AND failed_at IS NULL AND run_at <= now()
                 ORDER BY run_at, id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, queue, payload, attempts"
        ))
        .bind(queue)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .bind(lease.as_secs_f64())
        .fetch_all(&self.pool)
        .await
        .map_err(error)?;
        rows.into_iter()
            .map(|row| {
                Ok(Job {
                    id: row.try_get::<i64, _>("id").map_err(error)?.to_string(),
                    queue: row.try_get("queue").map_err(error)?,
                    payload: unwrap(row.try_get("payload").map_err(error)?),
                    attempts: u32::try_from(row.try_get::<i32, _>("attempts").map_err(error)?)
                        .unwrap_or(0),
                })
            })
            .collect()
    }

    async fn complete(&self, job: &str) -> Result<(), QueueError> {
        sqlx::query(&format!("DELETE FROM {} WHERE id = $1", self.table))
            .bind(id(job)?)
            .execute(&self.pool)
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn retry(&self, job: &str, delay: Duration, message: &str) -> Result<(), QueueError> {
        sqlx::query(&format!(
            "UPDATE {} SET attempts = attempts + 1,
                 run_at = now() + make_interval(secs => $2),
                 last_error = $3
             WHERE id = $1",
            self.table
        ))
        .bind(id(job)?)
        .bind(delay.as_secs_f64())
        .bind(storable(message))
        .execute(&self.pool)
        .await
        .map_err(error)?;
        Ok(())
    }

    async fn fail(&self, job: &str, message: &str) -> Result<(), QueueError> {
        sqlx::query(&format!(
            "UPDATE {} SET attempts = attempts + 1, failed_at = now(), last_error = $2
             WHERE id = $1",
            self.table
        ))
        .bind(id(job)?)
        .bind(storable(message))
        .execute(&self.pool)
        .await
        .map_err(error)?;
        Ok(())
    }

    async fn next_due(&self, queue: &str) -> Result<Option<Duration>, QueueError> {
        let seconds: Option<f64> = sqlx::query_scalar(&format!(
            "SELECT EXTRACT(EPOCH FROM (min(run_at) - now()))::float8
             FROM {} WHERE queue = $1 AND failed_at IS NULL",
            self.table
        ))
        .bind(queue)
        .fetch_one(&self.pool)
        .await
        .map_err(error)?;
        Ok(seconds.map(|seconds| Duration::from_secs_f64(seconds.max(0.0))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn what_jsonb_refuses_is_wrapped_and_comes_back() {
        for payload in [
            json!({"activity": {"content": "a\u{0}b"}}),
            json!({"a\u{0}": 1}),
            json!(["x", ["\u{0}"]]),
            json!({WRAPPED: "not wrapped by us"}),
        ] {
            let stored = wrap(&payload);
            assert!(!stored.to_string().contains('\0'));
            assert_ne!(stored, payload);
            assert_eq!(unwrap(stored), payload);
        }
        let plain = json!({"activity": {"content": "hello"}});
        assert_eq!(wrap(&plain), plain);
        assert_eq!(unwrap(plain.clone()), plain);
    }
}
