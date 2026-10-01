Vocabulary schemas
==================

The YAML files in this directory describe the ActivityStreams types and their
extensions that *ojak-vocab* generates Rust types for.  They are [Fedify]'s
vocabulary schemas, copied verbatim, and *format/schema.yaml* is the JSON
Schema Fedify describes their format with.  They are Fedify's work, under the
MIT license in *LICENSE*; nothing else in this crate is.

[Fedify]: https://fedify.dev/


Provenance
----------

Copied from Fedify [2.4.0], commit `a0002240fd95ca028b897007ae6ab505399f2cb4`
(2026-10-01):

| Here                 | In Fedify                              |
| -------------------- | -------------------------------------- |
| `*.yaml`             | `packages/vocab/src/*.yaml`            |
| `format/schema.yaml` | `packages/vocab-tools/src/schema.yaml` |
| `LICENSE`            | `LICENSE`                              |

Each file's `$schema` still names its path in Fedify's tree; it is left as it
was so that the copies stay byte-for-byte what Fedify released.

[2.4.0]: https://github.com/fedify-dev/fedify/releases/tag/2.4.0


Updating
--------

Take them from a released version, never from a branch, so that what
*ojak-vocab* generates from can always be named:

~~~~ sh
git -C path/to/fedify archive <tag> packages/vocab/src \
  packages/vocab-tools/src/schema.yaml LICENSE | tar -x -C /tmp/fedify
cp /tmp/fedify/packages/vocab/src/*.yaml crates/ojak-vocab/schemas/
cp /tmp/fedify/packages/vocab-tools/src/schema.yaml \
  crates/ojak-vocab/schemas/format/schema.yaml
cp /tmp/fedify/LICENSE crates/ojak-vocab/schemas/LICENSE
cargo run -p ojak-vocab-gen
~~~~

Then update the version and commit above.  The generator refuses a schema
that uses a key or a range it does not know, so a change in Fedify's format
fails there rather than generating something subtly wrong.
