//! Descriptor-relative reads. Project symlinks and special files are never followed.
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{File, Metadata},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::MetadataExt,
        },
    },
    path::{Component, Path, PathBuf},
};

pub(super) struct Directory {
    file: File,
    pub path: PathBuf,
}

fn invalid() -> io::Error {
    io::Error::other("unsupported file route or changed input")
}
fn open(parent: &File, name: &OsStr, directory: bool) -> io::Result<Option<File>> {
    let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // The retained parent descriptor prevents an ancestor substitution from retargeting this read.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    // This descriptor is newly owned and is closed by File.
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

fn revision(m: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

impl Directory {
    pub fn root(path: &Path) -> io::Result<(Self, PathBuf)> {
        // Only the explicitly selected root is resolved. Descendant links are refused.
        let physical = path.canonicalize()?;
        let mut file = File::open("/")?;
        for part in physical.components() {
            match part {
                Component::RootDir => (),
                Component::Normal(name) => file = open(&file, name, true)?.ok_or_else(invalid)?,
                _ => return Err(invalid()),
            }
        }
        if !file.metadata()?.is_dir() {
            return Err(invalid());
        }
        Ok((
            Self {
                file,
                path: PathBuf::new(),
            },
            physical,
        ))
    }
    pub fn same_root(&self, physical: &Path) -> bool {
        let Ok(now) = physical.symlink_metadata() else {
            return false;
        };
        let Ok(original) = self.file.metadata() else {
            return false;
        };
        now.is_dir() && now.dev() == original.dev() && now.ino() == original.ino()
    }
    pub fn directory(&self, name: &OsStr) -> io::Result<Option<Self>> {
        Ok(open(&self.file, name, true)?.map(|file| Self {
            file,
            path: self.path.join(name),
        }))
    }
    pub fn read(&self, name: &OsStr, max: usize) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = open(&self.file, name, false)? else {
            return Ok(None);
        };
        let before = file.metadata()?;
        if !before.is_file() || before.len() > max as u64 {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file).take(max as u64).read_to_end(&mut bytes)?;
        if bytes.len() > max || revision(&before) != revision(&file.metadata()?) {
            return Err(invalid());
        }
        Ok(Some(bytes))
    }
    pub fn entries(&self, max: usize) -> io::Result<Vec<OsString>> {
        let before = self.file.metadata()?;
        // A fresh descriptor avoids sharing readdir's offset with this directory.
        let file = open(&self.file, OsStr::new("."), true)?.ok_or_else(invalid)?;
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Stream(stream);
        let mut names = Vec::new();
        loop {
            // readdir uses errno to distinguish end of stream from an I/O failure.
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(not(target_os = "macos"))]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() == max {
                return Err(io::Error::other("directory entry limit exceeded"));
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        }
        if revision(&before) != revision(&self.file.metadata()?) {
            return Err(invalid());
        }
        names.sort();
        Ok(names)
    }
    pub fn executable(&self, name: &OsStr) -> io::Result<bool> {
        let file = open(&self.file, name, false)?.ok_or_else(invalid)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(invalid());
        }
        Ok(meta.mode() & 0o111 != 0)
    }
}
