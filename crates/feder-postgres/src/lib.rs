//! A PostgreSQL [`Queue`] backend for Feder.
//!
//! Jobs live in one table, `feder_queue` unless named otherwise, created by
//! [`PostgresQueue::initialize`] if it is not there. Every queue — deliveries,
//! and whatever else an application runs through Feder — shares the table,
//! each claimed separately.
//!
//! A claim is an `UPDATE … FOR UPDATE SKIP LOCKED` that pushes `run_at` out by
//! the lease, so any number of workers in any number of processes can claim
//! from one table without two of them taking the same job, and a job whose
//! worker stopped comes back when its lease lapses. A job that is done is
//! deleted; one given up on keeps its row, with `failed_at` and the last
//! error, until [`PostgresQueue::prune_failed`] removes it.
//!
//! Queries are built at run time rather than checked by `sqlx`'s macros
//! against a database at compile time, since the table's name is the
//! application's to choose and an application building with this crate
//! should not need a database for it.

use feder::queue::{Job, Queue, QueueError};
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
    /// A queue in the table `feder_queue`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            table: "feder_queue".to_owned(),
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
        let valid = table.split('.').count() <= 2
            && table.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with(|c: char| c.is_ascii_digit())
                    && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
        if !valid {
            return Err(QueueError(format!("not a table name: {table}")));
        }
        Ok(Self {
            pool,
            table: table.to_owned(),
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
        .bind(payloads)
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
                    payload: row.try_get("payload").map_err(error)?,
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
