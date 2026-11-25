//! Minimal big-endian reader and writer.
//!
//! Variable-length fields are a u32 length followed by that many bytes.
//! Nothing here can panic: every read is bounds-checked and every length
//! conversion is checked.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Ran out of input while reading the named field.
    Truncated(&'static str),
    /// Input continued past the end of the structure.
    TrailingBytes(usize),
    /// A field held a value the format does not allow.
    Invalid(&'static str),
    /// A count or length exceeded its limit.
    TooLarge(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(what) => write!(f, "truncated while reading {what}"),
            Self::TrailingBytes(n) => write!(f, "{n} unexpected trailing bytes"),
            Self::Invalid(what) => write!(f, "invalid {what}"),
            Self::TooLarge(what) => write!(f, "{what} exceeds its limit"),
        }
    }
}

impl std::error::Error for WireError {}

#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Fixed-length bytes, written with no length prefix.
    pub fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Length-prefixed bytes.
    ///
    /// # Errors
    /// Fails if the length does not fit in a u32.
    pub fn bytes(&mut self, v: &[u8]) -> Result<(), WireError> {
        self.count(v.len(), "field length")?;
        self.raw(v);
        Ok(())
    }

    /// A count of items that follow.
    ///
    /// # Errors
    /// Fails if the count does not fit in a u32.
    pub fn count(&mut self, n: usize, what: &'static str) -> Result<(), WireError> {
        self.u32(u32::try_from(n).map_err(|_e| WireError::TooLarge(what))?);
        Ok(())
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// The next `n` bytes.
    ///
    /// # Errors
    /// Fails if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], WireError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(WireError::Truncated(what))?;
        self.rest = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    ///
    /// # Errors
    /// Fails if fewer than `N` bytes remain.
    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], WireError> {
        let (head, tail) = self.rest.split_first_chunk::<N>().ok_or(WireError::Truncated(what))?;
        self.rest = tail;
        Ok(*head)
    }

    /// # Errors
    /// Fails if no input remains.
    pub fn u8(&mut self, what: &'static str) -> Result<u8, WireError> {
        let [v] = self.array(what)?;
        Ok(v)
    }

    /// # Errors
    /// Fails if fewer than four bytes remain.
    pub fn u32(&mut self, what: &'static str) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array(what)?))
    }

    /// # Errors
    /// Fails if fewer than eight bytes remain.
    pub fn u64(&mut self, what: &'static str) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array(what)?))
    }

    /// Length-prefixed bytes. The length is checked against the remaining
    /// input before anything is allocated.
    ///
    /// # Errors
    /// Fails if the prefix or the bytes it promises are missing.
    pub fn bytes(&mut self, what: &'static str) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.u32(what)?).map_err(|_e| WireError::TooLarge(what))?;
        self.take(len, what)
    }

    /// A count of following items, bounded by `max`.
    ///
    /// # Errors
    /// Fails if the count is missing or greater than `max`.
    pub fn count(&mut self, max: usize, what: &'static str) -> Result<usize, WireError> {
        let n = usize::try_from(self.u32(what)?).map_err(|_e| WireError::TooLarge(what))?;
        if n > max {
            return Err(WireError::TooLarge(what));
        }
        Ok(n)
    }

    /// Succeeds only if every byte of the input was consumed.
    ///
    /// # Errors
    /// Fails if input remains.
    pub const fn finish(self) -> Result<(), WireError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes(self.rest.len()))
        }
    }
}
