//! File-descriptor based native user xattrs; privileged namespaces stay private.
use super::{NResult, status};
use std::{ffi::CString, fs::File, os::fd::AsRawFd};
pub const MAX: usize = 65536;
pub fn validate(name: &str) -> NResult<()> {
    super::name(name)?;
    if name.starts_with("system.")
        || name.starts_with("security.")
        || name.starts_with("trusted.")
        || name.starts_with("com.apple.system.")
    {
        return Err(1);
    }
    if name.len() > 250 {
        return Err(63);
    }
    Ok(())
}
fn native(name: &str) -> NResult<CString> {
    validate(name)?;
    #[cfg(target_os = "linux")]
    let name = format!("user.{name}");
    CString::new(name.as_bytes()).map_err(|_| 22u32)
}
fn buffer(mut f: impl FnMut(*mut libc::c_void, usize) -> isize) -> NResult<Vec<u8>> {
    // Size can change between calls. Retry a bounded number of times.
    for _ in 0..3 {
        let size = f(std::ptr::null_mut(), 0);
        if size < 0 {
            return Err(status(std::io::Error::last_os_error()));
        }
        if size as usize > MAX {
            return Err(27);
        }
        let mut bytes = vec![0; size as usize];
        if bytes.is_empty() {
            return Ok(bytes);
        }
        let len = f(bytes.as_mut_ptr().cast(), bytes.len());
        if len >= 0 {
            bytes.truncate(len as usize);
            return Ok(bytes);
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ERANGE) {
            return Err(status(e));
        }
    }
    Err(10008)
}
pub fn list(fd: &File) -> NResult<Vec<String>> {
    let bytes = buffer(|ptr, len| unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::flistxattr(fd.as_raw_fd(), ptr.cast(), len)
        }
        #[cfg(target_os = "macos")]
        {
            libc::flistxattr(fd.as_raw_fd(), ptr.cast(), len, 0)
        }
    })?;
    let mut names = Vec::new();
    for bytes in bytes.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let Ok(name) = std::str::from_utf8(bytes) else {
            continue;
        };
        #[cfg(target_os = "linux")]
        let Some(name) = name.strip_prefix("user.") else {
            continue;
        };
        if validate(name).is_ok() {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}
pub fn get(fd: &File, name: &str) -> NResult<Vec<u8>> {
    let name = native(name)?;
    buffer(|ptr, len| unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::fgetxattr(fd.as_raw_fd(), name.as_ptr(), ptr, len)
        }
        #[cfg(target_os = "macos")]
        {
            libc::fgetxattr(fd.as_raw_fd(), name.as_ptr(), ptr, len, 0, 0)
        }
    })
}
pub fn set(fd: &File, name: &str, bytes: &[u8], create: bool) -> NResult<()> {
    let name = native(name)?;
    let flags = if create { libc::XATTR_CREATE } else { 0 };
    let rc = unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::fsetxattr(
                fd.as_raw_fd(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                flags,
            )
        }
        #[cfg(target_os = "macos")]
        {
            libc::fsetxattr(
                fd.as_raw_fd(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                flags,
            )
        }
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(status(std::io::Error::last_os_error()))
    }
}
pub fn remove(fd: &File, name: &str) -> NResult<()> {
    let name = native(name)?;
    let rc = unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::fremovexattr(fd.as_raw_fd(), name.as_ptr())
        }
        #[cfg(target_os = "macos")]
        {
            libc::fremovexattr(fd.as_raw_fd(), name.as_ptr(), 0)
        }
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(status(std::io::Error::last_os_error()))
    }
}
