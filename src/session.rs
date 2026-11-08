use crate::{Result, invalid};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, PermissionsExt},
    io::{AsRawFd, FromRawFd},
};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
pub const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

pub struct Session {
    root: PathBuf,
}
impl Session {
    pub fn create() -> Result<Self> {
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let parent = if Path::new("/private/tmp").is_dir() {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let root = Path::new(parent).join(format!("cb-session-{suffix}"));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let session = Self {
            root: root.canonicalize()?,
        };
        for name in ["home", "tmp", "input", "bin", "work"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(session.root.join(name))?;
        }
        Ok(session)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn close(self) -> Result<()> {
        fs::remove_dir_all(&self.root).map_err(|error| {
            invalid(format!(
                "could not remove private session {}: {error}",
                self.root.display()
            ))
        })?;
        Ok(())
    }
    pub fn copy_input(&self, source: &Path, index: usize) -> Result<PathBuf> {
        let name = source
            .file_name()
            .ok_or_else(|| invalid("input needs a filename"))?;
        let target = self
            .root
            .join("input")
            .join(format!("{index:03}-{}", name.to_string_lossy()));
        copy_regular(source, &target, MAX_INPUT_BYTES, 0o400)?;
        Ok(target)
    }
    pub fn copy_program(&self, source: &Path) -> Result<PathBuf> {
        let target = self.root.join("bin/program");
        copy_regular(source, &target, 256 * 1024 * 1024, 0o500)?;
        Ok(target)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn open_regular_no_symlinks(path: &Path) -> Result<File> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components: Vec<_> = path
        .components()
        .filter(|c| !matches!(c, Component::RootDir))
        .collect();
    if components.is_empty() {
        return Err(invalid("a regular file is required"));
    }
    let mut directory = File::open("/")?;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(invalid("input paths cannot contain . or .."));
        };
        let name = CString::new(name.as_bytes())?;
        let last = index + 1 == components.len();
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        if !last {
            flags |= libc::O_DIRECTORY;
        }
        // Retaining each parent descriptor prevents ancestor symlink swaps.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // openat returned a new descriptor; File takes its unique ownership.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if last {
            if !opened.metadata()?.is_file() {
                return Err(invalid(
                    "special files and directories are not valid inputs",
                ));
            }
            return Ok(opened);
        }
        directory = opened;
    }
    Err(invalid("a regular file is required"))
}
fn copy_regular(source: &Path, target: &Path, limit: u64, mode: u32) -> Result<()> {
    let input = open_regular_no_symlinks(source)?;
    if input.metadata()?.len() > limit {
        return Err(invalid("selected file exceeds the copy limit"));
    }
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    destination.set_permissions(fs::Permissions::from_mode(0o600))?;
    let count = std::io::copy(&mut input.take(limit + 1), &mut destination)?;
    if count > limit {
        return Err(invalid("selected file grew beyond the copy limit"));
    }
    destination.flush()?;
    destination.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sessions_are_private_and_removed_on_drop() {
        let s = Session::create().unwrap();
        let root = s.root().to_owned();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(s);
        assert!(!root.exists());
    }
    #[test]
    fn symlink_files_and_parents_are_refused() {
        use std::os::unix::fs::symlink;
        let s = Session::create().unwrap();
        let r = s.root();
        fs::write(r.join("source"), "fixture").unwrap();
        symlink(r.join("source"), r.join("alias")).unwrap();
        assert!(open_regular_no_symlinks(&r.join("alias")).is_err());
        symlink(r.join("home"), r.join("linked-home")).unwrap();
        fs::write(r.join("home/input"), "fixture").unwrap();
        assert!(open_regular_no_symlinks(&r.join("linked-home/input")).is_err());
    }
    #[test]
    fn special_files_are_refused_without_blocking() {
        assert!(open_regular_no_symlinks(Path::new("/dev/null")).is_err());
    }
}
