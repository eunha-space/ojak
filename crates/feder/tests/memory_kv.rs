//! The in-memory key-value store passes the backend checks.

#[tokio::test]
async fn memory_kv_passes_the_checks() {
    feder::testing::check_kv(&feder::kv::MemoryKvStore::new()).await;
}
