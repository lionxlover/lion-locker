//! Turns raw `wl_keyboard` keycodes into characters, using the keymap the
//! compositor hands over on `wl_keyboard.keymap`. This is the standard
//! Wayland pattern: the compositor never sends text, only keycodes plus a
//! keymap, and it's up to each client to run xkbcommon over both.

use std::os::fd::OwnedFd;
use xkbcommon::xkb;

pub enum KeyOutcome {
    Char(char),
    Backspace,
    Enter,
    Escape,
    Ignored,
}

pub struct XkbState {
    context: xkb::Context,
    keymap: Option<xkb::Keymap>,
    state: Option<xkb::State>,
    /// Last Caps Lock state observed, so we only report *changes*.
    last_caps: Option<bool>,
}

impl XkbState {
    pub fn new() -> Self {
        Self {
            context: xkb::Context::new(xkb::CONTEXT_NO_FLAGS),
            keymap: None,
            state: None,
            last_caps: None,
        }
    }

    /// Current Caps Lock state, from the keymap's LED state (the same
    /// source the compositor's own indicator uses).
    pub fn caps_lock_on(&self) -> bool {
        self.state
            .as_ref()
            .map(|s| s.led_name_is_active("Caps Lock"))
            .unwrap_or(false)
    }

    /// Load the keymap the compositor sent: `fd` is a memory-mapped file
    /// of `size` bytes containing the keymap as text (XKB_KEYMAP_FORMAT_TEXT_V1).
    pub fn load_keymap(&mut self, fd: OwnedFd, size: usize) {
        let data = match map_readonly(&fd, size) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "failed to map keymap");
                return;
            }
        };

        match unsafe {
            xkb::Keymap::new_from_string(
                &self.context,
                std::str::from_utf8_unchecked(data).to_owned(),
                xkb::KEYMAP_FORMAT_TEXT_V1,
                xkb::KEYMAP_COMPILE_NO_FLAGS,
            )
        } {
            Some(keymap) => {
                self.state = Some(xkb::State::new(&keymap));
                self.keymap = Some(keymap);
            }
            None => tracing::error!("xkbcommon failed to compile keymap"),
        }
    }

    /// Returns `Some(new_state)` when Caps Lock *changed* with this
    /// modifier update (so callers can forward just the transitions).
    pub fn update_modifiers(
        &mut self,
        depressed: u32,
        latched: u32,
        locked: u32,
        group: u32,
    ) -> Option<bool> {
        if let Some(state) = &mut self.state {
            state.update_mask(depressed, latched, locked, 0, 0, group);
        }
        let caps = self.caps_lock_on();
        if self.last_caps != Some(caps) {
            self.last_caps = Some(caps);
            return Some(caps);
        }
        None
    }

    /// `keycode` is the Wayland/evdev keycode; xkbcommon keycodes are
    /// offset by 8 from evdev (the historical X11 minimum keycode).
    pub fn process(&mut self, keycode: u32) -> KeyOutcome {
        let Some(state) = &self.state else {
            return KeyOutcome::Ignored;
        };
        let xkb_code = xkb::Keycode::new(keycode + 8);
        let sym = state.key_get_one_sym(xkb_code);

        match sym {
            xkb::Keysym::Return | xkb::Keysym::KP_Enter => KeyOutcome::Enter,
            xkb::Keysym::Escape => KeyOutcome::Escape,
            xkb::Keysym::BackSpace => KeyOutcome::Backspace,
            _ => match state.key_get_utf8(xkb_code).chars().next() {
                Some(c) if !c.is_control() => KeyOutcome::Char(c),
                _ => KeyOutcome::Ignored,
            },
        }
    }
}

fn map_readonly(fd: &OwnedFd, size: usize) -> std::io::Result<&'static [u8]> {
    use std::os::fd::AsRawFd;
    // SAFETY: `fd` and `size` come straight from the compositor's
    // wl_keyboard.keymap event, which promises a valid mapping of exactly
    // this length; the mapping is intentionally leaked (`'static`) since
    // xkbcommon needs the bytes to outlive this call and a keymap is
    // loaded at most a handful of times per process lifetime.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr as *const u8, size) })
}
