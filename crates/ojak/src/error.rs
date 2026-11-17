//! [`Error`]: what an application's callback fails with, and whether doing
//! it again could help.

use std::error::Error as StdError;
use std::fmt;

type Boxed = Box<dyn StdError + Send + Sync + 'static>;

/// What a callback failed with: any error, kept with its sources so that it
/// can be looked into ([`Error::downcast_ref`], [`Error::chain`]), and
/// whether trying again could help ([`Error::is_permanent`]).
///
/// Any `std::error::Error` converts into one with `?`, and so does an
/// `anyhow::Error`, a `String` or a `&str`. An application whose error type is not a
/// `std::error::Error` gives it a `From` impl of its own:
///
/// ~~~~ rust
/// # use std::fmt;
/// #[derive(Debug)]
/// enum AppError { NotFound, Database(String) }
/// # impl fmt::Display for AppError {
/// #     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
/// # }
/// impl From<AppError> for ojak::Error {
///     fn from(error: AppError) -> Self {
///         match error {
///             AppError::NotFound => Self::msg(error).permanent(),
///             AppError::Database(_) => Self::msg(error),
///         }
///     }
/// }
/// ~~~~
///
/// Like `anyhow::Error`, it is not a `std::error::Error` itself, which is
/// what lets every one of those convert into it. [`Error::into_boxed`]
/// gives one back.
pub struct Error {
    inner: Boxed,
    permanent: bool,
}

/// An error made from a message alone.
struct Message(String);

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for Message {}

impl Error {
    /// `error`, to be tried again.
    pub fn new(error: impl StdError + Send + Sync + 'static) -> Self {
        Self::from_boxed(Box::new(error))
    }

    /// An error that says only `message`.
    pub fn msg(message: impl fmt::Display) -> Self {
        Self::from_boxed(Box::new(Message(message.to_string())))
    }

    /// `error`, already boxed.
    #[must_use]
    pub fn from_boxed(error: Boxed) -> Self {
        Self {
            inner: error,
            permanent: false,
        }
    }

    /// The same error, marked as one that trying again will not mend: the
    /// same activity will fail the same way. An inbox worker fails its job
    /// at once instead of retrying it, and an inbox answering inside the
    /// request accepts the activity rather than asking its sender to send
    /// it again.
    #[must_use]
    pub fn permanent(mut self) -> Self {
        self.permanent = true;
        self
    }

    /// Whether trying again will not mend it ([`Error::permanent`]).
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        self.permanent
    }

    /// This error, then what caused it, and so on.
    pub fn chain(&self) -> impl Iterator<Item = &(dyn StdError + 'static)> {
        let mut next: Option<&(dyn StdError + 'static)> = Some(&*self.inner);
        std::iter::from_fn(move || {
            let current = next?;
            next = current.source();
            Some(current)
        })
    }

    /// The first error in [`Error::chain`] that is a `T`.
    #[must_use]
    pub fn downcast_ref<T: StdError + 'static>(&self) -> Option<&T> {
        self.chain().find_map(<dyn StdError>::downcast_ref)
    }

    /// The error itself, boxed.
    #[must_use]
    pub fn into_boxed(self) -> Boxed {
        self.inner
    }
}

/// Whatever a `Box<dyn std::error::Error>` is made from: any error, an
/// `anyhow::Error`, a `String` or a `&str`.
impl<E: Into<Boxed>> From<E> for Error {
    fn from(error: E) -> Self {
        Self::from_boxed(error.into())
    }
}

impl AsRef<dyn StdError + Send + Sync + 'static> for Error {
    fn as_ref(&self) -> &(dyn StdError + Send + Sync + 'static) {
        &*self.inner
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.permanent {
            write!(f, "permanent: ")?;
        }
        fmt::Debug::fmt(&self.inner, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)?;
        if f.alternate() {
            for source in self.chain().skip(1) {
                write!(f, ": {source}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Outer(std::io::Error);
    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer")
        }
    }
    impl StdError for Outer {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn its_causes_can_be_looked_into() {
        let error = Error::from(Outer(std::io::Error::other("inner")));
        assert!(!error.is_permanent());
        assert_eq!(format!("{error:#}"), "outer: inner");
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(error.permanent().is_permanent());
    }

    #[test]
    fn anyhow_errors_keep_their_causes() {
        let error =
            Error::from(anyhow::Error::new(std::io::Error::other("inner")).context("outer"));
        assert_eq!(error.to_string(), "outer");
        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }
}
