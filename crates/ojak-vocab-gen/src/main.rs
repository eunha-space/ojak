//! Regenerate *crates/ojak-vocab/src/generated.rs* from the vendored schemas.

fn main() -> anyhow::Result<()> {
    let source = ojak_vocab_gen::render()?;
    let path = ojak_vocab_gen::output_path();
    std::fs::write(&path, source)?;
    println!("wrote {}", path.display());
    Ok(())
}
