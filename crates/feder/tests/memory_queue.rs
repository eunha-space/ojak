//! The in-memory queue passes the backend checks.

#[tokio::test]
async fn memory_queue_passes_the_checks() {
    feder::testing::check_queue(&feder::queue::MemoryQueue::new()).await;
}
