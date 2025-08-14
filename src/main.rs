#![cfg(windows)]

use std::env;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Read, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, Child};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const WINPMEM_BYTES: &[u8] = include_bytes!("../assets/winpmem_mini_x64.exe");

const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_CONTEXT_ASCII: usize = 4096;
const MAX_CONTEXT_UTF16_CODEUNITS: usize = 4096;

fn main() -> io::Result<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("Usage: memcap-win.exe \"<needle>\"");
        eprintln!("Example: memcap-win.exe \"Farmatic\"");
        std::process::exit(2);
    }
    let needle_str = args.remove(0);

    if !is_elevated() {
        eprintln!("[-] Must be run as Administrator.");
        std::process::exit(2);
    }

    // Prepare paths and shared state for Ctrl+C handler
    let winpmem_exe = extract_winpmem()?;
    let dump_path = temp_dump_path();

    let child_proc: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let dump_arc: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(Some(dump_path.clone())));
    let helper_arc: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(Some(winpmem_exe.clone())));

    // Ctrl+C handler: kill child, remove dump + helper, exit 130
    {
        let child_proc = Arc::clone(&child_proc);
        let dump_arc = Arc::clone(&dump_arc);
        let helper_arc = Arc::clone(&helper_arc);
        ctrlc::set_handler(move || {
            if let Ok(mut ch) = child_proc.lock() {
                if let Some(mut c) = ch.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
            if let Ok(mut d) = dump_arc.lock() {
                if let Some(p) = d.take() {
                    let _ = fs::remove_file(&p);
                }
            }
            if let Ok(mut h) = helper_arc.lock() {
                if let Some(p) = h.take() {
                    let _ = fs::remove_file(&p);
                }
            }
            eprintln!("\n[!] Interrupted. Cleaned up.");
            std::process::exit(130);
        }).expect("failed to set Ctrl+C handler");
    }

    // 1) Acquire RAW dump (spawn so Ctrl+C can terminate it)
    println!("[*] Using WinPmem: {}", winpmem_exe.display());
    println!("[*] Dumping to:    {}", dump_path.display());

    {
        let child = Command::new(&winpmem_exe)
            .arg(&dump_path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        *child_proc.lock().unwrap() = Some(child);
    }

    // Wait for completion
    let status = {
        let mut guard = child_proc.lock().unwrap();
        let st = guard.as_mut().unwrap().wait()?;
        guard.take(); // drop handle
        st
    };

    let _ = fs::remove_file(&winpmem_exe);
    *helper_arc.lock().unwrap() = None;

    let (proceed, dump_size_mb) = match fs::metadata(&dump_path) {
        Ok(md) => {
            let sz = md.len();
            (sz > 16 * 1024 * 1024, sz / (1024 * 1024))
        }
        Err(_) => (false, 0),
    };

    if !status.success() && !proceed {
        eprintln!("[-] WinPmem failed: {}", status);
        eprintln!("    • Ensure Admin rights and free disk space.");
        // cleanup dump if any
        let _ = fs::remove_file(&dump_path);
        *dump_arc.lock().unwrap() = None;
        std::process::exit(1);
    }

    if !status.success() && proceed {
        eprintln!(
            "[!] WinPmem returned {:?}, but dump exists ({} MB). Proceeding to scan.",
            status.code(),
            dump_size_mb
        );
    } else {
        println!("[+] Acquisition complete ({} MB).", dump_size_mb);
    }

    // 2) Scan for the needle (ASCII + UTF-16LE) and print WHOLE string
    println!("[*] Scanning for:  \"{}\" (ASCII + UTF-16LE)", needle_str);
    let scan_res = scan_for_single_needle(&dump_path, &needle_str);

    // 3) Cleanup dump
    let _ = fs::remove_file(&dump_path);
    *dump_arc.lock().unwrap() = None;

    scan_res
}


fn extract_winpmem() -> io::Result<PathBuf> {
    let mut path = env::temp_dir();
    path.push("winpmem_mini_x64.exe");
    let mut tmp = path.clone();
    tmp.set_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(WINPMEM_BYTES)?;
        f.flush()?;
    }
    fs::rename(&tmp, &path)?;
    Ok(path)
}

fn temp_dump_path() -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut p = env::temp_dir();
    p.push(format!("mem_{secs}.raw"));
    p
}

fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

// ---- scanning (prints WHOLE string around the match) -----------------

fn scan_for_single_needle(img: &Path, needle_str: &str) -> io::Result<()> {
    let ascii = needle_str.as_bytes().to_vec();
    let utf16 = utf16le_bytes(needle_str);

    // overlap must cover max context so we can expand across chunk edges
    let overlap = ascii.len()
        .max(utf16.len())
        .max(MAX_CONTEXT_ASCII)
        .max(MAX_CONTEXT_UTF16_CODEUNITS * 2)
        .saturating_sub(1);

    let mut rdr = BufReader::with_capacity(CHUNK_SIZE, File::open(img)?);
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut tail: Vec<u8> = Vec::with_capacity(overlap);
    let mut _offset: u64 = 0;
    let mut chunk = vec![0u8; CHUNK_SIZE];

    let mut total = 0u64;

    loop {
        let n = read_fully(&mut rdr, &mut chunk)?;
        if n == 0 && tail.is_empty() { break; }
        let view = &chunk[..n];

        let mut search = Vec::with_capacity(tail.len() + view.len());
        search.extend_from_slice(&tail);
        search.extend_from_slice(view);

        // ASCII matches
        total += find_expand_and_print_ascii(&search, &ascii, &mut out)?;
        // UTF-16LE matches
        total += find_expand_and_print_utf16(&search, &utf16, &mut out)?;

        tail.clear();
        if overlap > 0 && search.len() >= overlap {
            tail.extend_from_slice(&search[search.len() - overlap..]);
        } else if overlap > 0 && !search.is_empty() {
            tail.extend_from_slice(&search[..search.len().min(overlap)]);
        }

        _offset += n as u64;
        if n == 0 { break; }
    }

    out.flush()?;
    eprintln!("[+] Done. Hits: {}", total);
    Ok(())
}

fn read_fully<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn utf16le_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.push((u & 0xFF) as u8);
        out.push((u >> 8) as u8);
    }
    out
}

fn is_printable_ascii(b: u8) -> bool {
    (b.is_ascii_graphic()) || b == b' ' || b == b'\t'
}

fn is_printable_u16(u: u16) -> bool {
    let ch = char::from_u32(u as u32).unwrap_or('\u{FFFD}');
    ch.is_ascii_graphic() || ch == ' ' || ch == '\t'
}

fn find_expand_and_print_ascii(
    hay: &[u8],
    needle: &[u8],
    out: &mut BufWriter<io::StdoutLock<'_>>,
) -> io::Result<u64> {
    if needle.is_empty() || hay.len() < needle.len() { return Ok(0); }
    let mut hits = 0u64;
    let mut i = 0usize;
    let last = hay.len() - needle.len();

    while i <= last {
        if &hay[i..i + needle.len()] == needle {
            let mut l = i;
            let max_left = MAX_CONTEXT_ASCII.min(l);
            for _ in 0..max_left {
                if l == 0 || !is_printable_ascii(hay[l - 1]) { break; }
                l -= 1;
            }
            let mut r = i + needle.len();
            let max_right = MAX_CONTEXT_ASCII.min(hay.len() - r);
            for _ in 0..max_right {
                if r >= hay.len() || !is_printable_ascii(hay[r]) { break; }
                r += 1;
            }
            if r > l {
                out.write_all(&hay[l..r])?;
                out.write_all(b"\n")?;
                hits += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    Ok(hits)
}

fn find_expand_and_print_utf16(
    hay: &[u8],
    needle: &[u8],
    out: &mut BufWriter<io::StdoutLock<'_>>,
) -> io::Result<u64> {
    if needle.is_empty() || hay.len() < needle.len() { return Ok(0); }
    let mut hits = 0u64;
    let mut i = 0usize;
    let last = hay.len() - needle.len();

    while i <= last {
        if &hay[i..i + needle.len()] == needle {
            let mut l = i;
            let mut steps = 0usize;
            while l >= 2 && steps < MAX_CONTEXT_UTF16_CODEUNITS {
                let u = u16::from_le_bytes([hay[l - 2], hay[l - 1]]);
                if !is_printable_u16(u) { break; }
                l -= 2;
                steps += 1;
            }
            let mut r = i + needle.len();
            steps = 0;
            while r + 2 <= hay.len() && steps < MAX_CONTEXT_UTF16_CODEUNITS {
                let u = u16::from_le_bytes([hay[r], hay[r + 1]]);
                if !is_printable_u16(u) { break; }
                r += 2;
                steps += 1;
            }

            if r > l {
                let mut buf_u16 = Vec::with_capacity((r - l) / 2);
                let mut p = l;
                while p + 1 < r {
                    buf_u16.push(u16::from_le_bytes([hay[p], hay[p + 1]]));
                    p += 2;
                }
                let s = String::from_utf16_lossy(&buf_u16);
                out.write_all(s.as_bytes())?;
                out.write_all(b"\n")?;
                hits += 1;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(hits)
}
