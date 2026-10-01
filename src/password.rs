//! A password buffer that zeroizes on every mutation and on drop. Nothing
//! outside `auth.rs` ever sees its contents; `lockscreen.rs` only learns
//! that *a* key was pressed, never which one.

use zeroize::Zeroize;

/// Hard cap on the plaintext buffer's length. A real password never
/// reaches four digits of characters; the cap exists so a stuck key
/// repeat (or a hostile auto-replayer) cannot grow the buffer without
/// bound and pressure the locker's (mlocked) memory. Extra characters
/// beyond the cap are dropped, and `is_full` lets the UI show "too
/// long" instead of silently eating keystrokes.
const MAX_LEN: usize = 1024;

#[derive(Default)]
pub struct PasswordBuffer(String);

impl PasswordBuffer {
    pub fn push(&mut self, c: char) {
        if self.0.len() + c.len_utf8() <= MAX_LEN {
            self.0.push(c);
        }
    }

    pub fn backspace(&mut self) {
        // Zeroize the removed character rather than just shrinking the
        // string, so it doesn't linger in the buffer's spare capacity.
        if let Some(c) = self.0.pop() {
            let mut tmp = [0u8; 4];
            c.encode_utf8(&mut tmp).zeroize();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True when the buffer refused more input because it hit
    /// [`MAX_LEN`] (the UI can hint "password too long").
    #[allow(dead_code)] // exposed for the lockscreen contract; wired in 0.3
    pub fn is_full(&self) -> bool {
        self.0.len() >= MAX_LEN
    }

    /// Consumes the buffer, handing ownership of the plaintext to the
    /// caller (which must zeroize it in turn -- see `auth::spawn_login`'s
    /// use of `zeroize::Zeroizing`).
    pub fn take(&mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for PasswordBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_backspace_take_round_trip() {
        let mut b = PasswordBuffer::default();
        assert!(b.is_empty());
        for c in "hunter2ü".chars() {
            b.push(c);
        }
        assert!(!b.is_empty());
        b.backspace();
        let taken = b.take();
        assert_eq!(taken, "hunter2");
        assert!(b.is_empty());
    }

    #[test]
    fn length_is_capped() {
        let mut b = PasswordBuffer::default();
        for _ in 0..(MAX_LEN + 100) {
            b.push('x');
        }
        assert_eq!(b.take().len(), MAX_LEN);
        assert!(!b.is_full(), "after take the buffer is empty, not full");
    }

    #[test]
    fn multi_byte_chars_counted_correctly() {
        let mut b = PasswordBuffer::default();
        for _ in 0..600 {
            b.push('ü'); // 2 bytes each
        }
        // Byte cap: 600 * 2 = 1200 > 1024, so pushes stop earlier.
        let len = b.take().len();
        assert!(len <= MAX_LEN);
        assert!(len % 2 == 0, "a partial multi-byte char is never stored");
    }

    #[test]
    fn take_leaves_empty_zeroized_buffer() {
        let mut b = PasswordBuffer::default();
        b.push('s');
        b.push('e');
        b.push('c');
        b.push('r');
        b.push('e');
        b.push('t');
        let _ = b.take();
        assert!(b.is_empty());
        // A second take yields the empty string, not stale bytes.
        assert_eq!(b.take(), "");
    }
}
