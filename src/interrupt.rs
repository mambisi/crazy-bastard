use crate::{Result, invalid};
use std::sync::atomic::{AtomicBool, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

pub struct Guard {
    int: libc::sigaction,
    term: libc::sigaction,
}
impl Guard {
    pub fn install() -> Result<Self> {
        if ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(invalid(
                "only one run may own signal handling in this process",
            ));
        }
        INTERRUPTED.store(false, Ordering::Relaxed);
        // sigaction structures are initialized before use. The handler only writes
        // a lock-free atomic flag; process cleanup happens in the normal run loop.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = interrupt as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            let mut int = std::mem::zeroed();
            let mut term = std::mem::zeroed();
            if libc::sigaction(libc::SIGINT, &action, &mut int) != 0 {
                ACTIVE.store(false, Ordering::Release);
                return Err(std::io::Error::last_os_error().into());
            }
            if libc::sigaction(libc::SIGTERM, &action, &mut term) != 0 {
                let error = std::io::Error::last_os_error();
                libc::sigaction(libc::SIGINT, &int, std::ptr::null_mut());
                ACTIVE.store(false, Ordering::Release);
                return Err(error.into());
            }
            Ok(Self { int, term })
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        // Restore only the handlers this guard replaced.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.int, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &self.term, std::ptr::null_mut());
        }
        ACTIVE.store(false, Ordering::Release);
    }
}
