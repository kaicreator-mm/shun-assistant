//! Length-prefixed JSON frame codec for the private pipe protocol. Frames are
//! `u32 LE length | utf-8 JSON`; the length cap bounds memory on both sides.
//! No credential, API key or full goal text ever travels in a frame — only
//! the projection (which the user is explicitly approving), the redacted
//! scope and broker proofs.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};

pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

pub struct FrameIo {
    pipe: HANDLE,
}

impl FrameIo {
    pub fn new(pipe: HANDLE) -> Self {
        FrameIo { pipe }
    }

    /// Read one frame; `None` on EOF/oversize/IO error (caller drops the link).
    pub fn read_frame(&self) -> Option<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        read_exact(self.pipe, &mut len_buf)?;
        let len = u32::from_le_bytes(len_buf);
        if len == 0 || len > MAX_FRAME_BYTES {
            return None;
        }
        let mut body = vec![0u8; len as usize];
        read_exact(self.pipe, &mut body)?;
        Some(body)
    }

    /// Write one frame; `false` on IO error.
    pub fn write_frame(&self, body: &[u8]) -> bool {
        if body.len() as u64 > u64::from(MAX_FRAME_BYTES) {
            return false;
        }
        let len_buf = (body.len() as u32).to_le_bytes();
        write_all(self.pipe, &len_buf) && write_all(self.pipe, body)
    }

    /// Flush the pipe so a reply is on the wire before the peer waits on it.
    pub fn flush(&self) -> bool {
        unsafe { windows::Win32::Storage::FileSystem::FlushFileBuffers(self.pipe) }.is_ok()
    }
}

fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let mut got = 0u32;
        let ok = unsafe {
            ReadFile(
                pipe,
                Some(&mut buf[done..]),
                Some(&mut got),
                None,
            )
        };
        if ok.is_err() || got == 0 {
            return None;
        }
        done += got as usize;
    }
    Some(())
}

fn write_all(pipe: HANDLE, buf: &[u8]) -> bool {
    let mut done = 0usize;
    while done < buf.len() {
        let mut wrote = 0u32;
        let ok = unsafe { WriteFile(pipe, Some(&buf[done..]), Some(&mut wrote), None) };
        if ok.is_err() {
            return false;
        }
        done += wrote as usize;
    }
    true
}
