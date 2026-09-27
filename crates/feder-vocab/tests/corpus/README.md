Corpus
======

Documents other servers wrote, which the vocabulary has to read without
losing anything it should keep. `tests/corpus.rs` reads each one and lists
what the typed value did not keep in `losses.txt`.

 -  *lemmy/*: Lemmy's federation test assets, documents captured from
    Lemmy and from the servers it federates with, one directory per
    implementation. Copied from `crates/apub/apub/assets` of
    <https://github.com/LemmyNet/lemmy> at commit
    `f1476db8785600db709e6e01df331e00cffbe340`, under the GNU Affero General
    Public License version 3, as Lemmy is.
