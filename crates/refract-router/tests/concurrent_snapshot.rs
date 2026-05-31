//! Loom model for concurrent snapshot reader and writer publication.

#[cfg(not(miri))]
#[test]
fn concurrent_reader_during_writer_update_loom_one_million_permutation_cap() {
    use loom::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let mut builder = loom::model::Builder::new();
    builder.max_permutations = Some(1_000_000);
    builder.max_branches = 64;

    builder.check(|| {
        let published = Arc::new(AtomicUsize::new(0));
        let reader_state = Arc::clone(&published);
        let writer_state = Arc::clone(&published);

        let reader = loom::thread::spawn(move || {
            let observed = reader_state.load(Ordering::Acquire);
            assert!(observed == 0 || observed == 1);
        });

        let writer = loom::thread::spawn(move || {
            writer_state.store(1, Ordering::Release);
        });

        reader.join().unwrap();
        writer.join().unwrap();
    });
}
