//! PostgreSQL backends for Feder: the queue, [`PostgresQueue`], and the
//! key-value store, [`PostgresKvStore`], each in a table of its own that it
//! creates on first use or that the application creates in a migration.
//!
//! Queries are built at run time rather than checked by `sqlx`'s macros
//! against a database at compile time, since the tables' names are the
//! application's to choose and an application building with this crate
//! should not need a database for it.

mod kv;
mod queue;

pub use kv::PostgresKvStore;
pub use queue::PostgresQueue;

/// `table`, if it is a plain SQL identifier: ASCII letters, digits and
/// underscores, not starting with a digit, optionally prefixed by a schema
/// of the same shape and a dot. Table names are put into queries as they
/// are, so nothing else is.
fn table_name(table: &str) -> Result<String, String> {
    let valid = table.split('.').count() <= 2
        && table.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with(|c: char| c.is_ascii_digit())
                && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    if valid {
        Ok(table.to_owned())
    } else {
        Err(format!("not a table name: {table}"))
    }
}
