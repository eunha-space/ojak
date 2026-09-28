//! The in-memory queue passes the backend checks.

#[tokio::test]
async fn memory_queue_passes_the_checks() {
    ojak::testing::check_queue(&ojak::queue::MemoryQueue::new()).await;
}
