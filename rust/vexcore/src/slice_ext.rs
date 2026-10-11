//! Turning a table pointer and a length that came from a file into a slice.
//!
//! Every table this crate reads is described by a pointer the C side computed
//! from headers the file supplied, plus a count it derived from those headers.
//! The C versions indexed them directly, which put the bounds check at each
//! use site; here they become one slice at the top, and the check that used to
//! be a comparison before every access is the `get` that returns an `Option`.

/// The slice `(ptr, len)` names, or `None` when the pair cannot be one.
///
/// A null pointer is the C side's way of saying "the file did not have this
/// table", and it is answered the same as a zero length: there is nothing to
/// search. The caller only ever reaches this with a length that was already
/// checked against the mapped file's own size.
#[inline]
pub(crate) unsafe fn table<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if ptr.is_null() || len == 0 {
        return None;
    }

    // SAFETY: the caller guarantees `ptr` is valid for `len` elements. Every
    //         call site gets its pair from one of the parsers, which only
    //         records a table after checking that its whole extent lies inside
    //         the mapped file.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}
