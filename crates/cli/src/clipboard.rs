//! Puts passwords on the system clipboard and takes them off again.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use std::{process, thread};

#[cfg(all(unix, not(target_os = "macos")))]
use arboard::SetExtLinux;
#[cfg(windows)]
use arboard::SetExtWindows;
use psm_core::Zeroizing;

/// What this process last put on the clipboard.
#[derive(Default)]
struct State {
    /// Counts copies, so a timer can tell whether its password is still the latest.
    copies: u64,
    password: Option<Zeroizing<String>>,
}

/// Copies passwords and clears each one after a delay, on [`Clipboard::clear`]
/// or on Ctrl+C, unless something else has been copied over it.
pub struct Clipboard {
    // Keeping a handle open lets this process keep serving the clipboard on X11.
    handle: arboard::Clipboard,
    state: Arc<Mutex<State>>,
    clear_after: Duration,
}

impl Clipboard {
    pub fn new(clear_after: Duration) -> Result<Self, String> {
        let handle =
            arboard::Clipboard::new().map_err(|e| format!("cannot open the clipboard: {e}"))?;
        let state = Arc::new(Mutex::new(State::default()));
        let on_interrupt = Arc::clone(&state);
        ctrlc::set_handler(move || {
            clear(&on_interrupt, None);
            eprintln!();
            process::exit(130);
        })
        .map_err(|e| format!("cannot handle Ctrl+C: {e}"))?;
        Ok(Self {
            handle,
            state,
            clear_after,
        })
    }

    pub const fn clear_after(&self) -> Duration {
        self.clear_after
    }

    /// Copies `password`, keeping it out of clipboard history where the
    /// platform allows, and schedules it to be cleared.
    pub fn copy(&mut self, password: &str) -> Result<(), String> {
        // Held until the copy is recorded, so a timer cannot clear in between.
        let mut state = lock(&self.state);
        let set = self.handle.set();
        #[cfg(all(unix, not(target_os = "macos")))]
        let set = set.exclude_from_history();
        #[cfg(windows)]
        let set = set
            .exclude_from_history()
            .exclude_from_cloud()
            .exclude_from_monitoring();
        set.text(password)
            .map_err(|e| format!("cannot copy to the clipboard: {e}"))?;
        state.copies += 1;
        state.password = Some(Zeroizing::new(password.to_owned()));
        let copy = state.copies;
        drop(state);

        let timer_state = Arc::clone(&self.state);
        let delay = self.clear_after;
        thread::spawn(move || {
            thread::sleep(delay);
            clear(&timer_state, Some(copy));
        });
        Ok(())
    }

    /// Clears the clipboard now if it still holds the last copied password.
    pub fn clear(&self) {
        clear(&self.state, None);
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Clears the clipboard if it still holds the password this process put
/// there. With `only_copy`, does nothing if a later copy has replaced it.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the lock is held so that a copy cannot land between checking and clearing"
)]
fn clear(state: &Mutex<State>, only_copy: Option<u64>) {
    let mut state = lock(state);
    if only_copy.is_some_and(|copy| copy != state.copies) {
        return;
    }
    let Some(password) = state.password.take() else {
        return;
    };
    // A fresh handle, because this may run on a timer or Ctrl+C thread.
    let Ok(mut handle) = arboard::Clipboard::new() else {
        return;
    };
    let ours = handle
        .get_text()
        .is_ok_and(|text| Zeroizing::new(text).as_str() == password.as_str());
    if ours && let Err(e) = handle.clear() {
        eprintln!("psm: cannot clear the clipboard: {e}");
    }
}
