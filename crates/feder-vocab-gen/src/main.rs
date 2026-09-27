//! Regenerate *crates/feder-vocab/src/generated.rs* from the vendored schemas.

fn main() -> anyhow::Result<()> {
    let source = feder_vocab_gen::render()?;
    let path = feder_vocab_gen::output_path();
    std::fs::write(&path, source)?;
    println!("wrote {}", path.display());
    Ok(())
}
