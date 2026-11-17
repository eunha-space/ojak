//! The kinds an application names what it serves by: [`ActorKind`],
//! [`ObjectKind`] and [`CollectionKind`].
//!
//! An application declares each as a constant and uses the constant both to
//! register a dispatcher and to build URIs, so that a misspelt kind does not
//! compile, and an actor kind cannot be passed where a collection kind is
//! meant:
//!
//! ~~~~ rust
//! use ojak::federation::{ActorKind, CollectionKind};
//!
//! const PERSON: ActorKind = ActorKind::new("person");
//! const FOLLOWERS: CollectionKind = CollectionKind::new("followers");
//! ~~~~
//!
//! Two kinds of the same sort with the same name are the same kind.

use std::fmt;

/// What every sort of kind has: its name, and which sort it is.
pub trait Kind: Copy + fmt::Debug + Send + Sync + 'static {
    /// Which sort of dispatcher a kind of this sort names: `"actor"`,
    /// `"object"` or `"collection"`.
    const NOUN: &'static str;

    /// The kind's name, as registered.
    fn name(self) -> &'static str;
}

macro_rules! kind {
    ($(#[$doc:meta])* $name:ident, $noun:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(&'static str);

        impl $name {
            /// The kind called `name`.
            #[must_use]
            pub const fn new(name: &'static str) -> Self {
                Self(name)
            }

            /// Its name.
            #[must_use]
            pub const fn name(self) -> &'static str {
                self.0
            }
        }

        impl Kind for $name {
            const NOUN: &'static str = $noun;

            fn name(self) -> &'static str {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }
    };
}

kind!(
    /// A kind of actor: a person, a group, the instance actor.
    ActorKind,
    "actor"
);
kind!(
    /// A kind of object: a note, a question, a collection of the
    /// application's own making that has no owner.
    ObjectKind,
    "object"
);
kind!(
    /// A kind of collection that belongs to something: its followers, its
    /// outbox.
    CollectionKind,
    "collection"
);
