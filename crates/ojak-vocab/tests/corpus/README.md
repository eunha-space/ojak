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

 -  *live/*: documents fetched on 2026-09-27 from the official accounts of
    projects whose documents the Lemmy assets do not cover: the account's
    actor, and up to three items of its outbox where the server serves one
    without a signed request. Only projects' own accounts, never a person's:

    | Directory     | Account                       |
    | ------------- | ----------------------------- |
    | `akkoma`      | `akkoma@ihatebeinga.live`     |
    | `bookwyrm`    | `bookwyrm@bookwyrm.social`    |
    | `fedify`      | `fedify@hollo.social` (Hollo) |
    | `misskey`     | `misskey@misskey.io`          |
    | `pixelfed`    | `pixelfed@pixelfed.social`    |
    | `sharkey`     | `sharkey@sharkey.team`        |
    | `writefreely` | `blog@write.as`               |


    GoToSocial and mastodon.social answer an unsigned fetch with 401, so
    they are not here; Mastodon's documents are in the Lemmy assets.
