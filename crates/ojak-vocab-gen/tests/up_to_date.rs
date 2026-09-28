//! The committed generated code is what the generator writes now.

#[test]
fn generated_code_is_up_to_date() {
    let expected = ojak_vocab_gen::render().expect("render");
    let path = ojak_vocab_gen::output_path();
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == expected,
        "{} is stale; run `cargo run -p ojak-vocab-gen`",
        path.display()
    );
}
