# memcap-win

A tiny, **Windows-only**, single-EXE tool that:

1. **Acquires a RAM image** using an embedded **WinPmem mini** driver.
2. **Scans** the dump for **one exact string** (ASCII **and** UTF-16LE).
3. Prints every **whole matching string** (the full contiguous text around the match) to **stdout**.
4. **Cleans up** the temporary dump automatically — even on **Ctrl+C**.

> ⚠️ DFIR/Research tool. Run only on systems you own or are authorized to examine.



## Features

- **Single argument**:  
```powershell
  memcap-win.exe "String"
```

* **No Python/Volatility required** on the target.
* **Low RAM footprint**: streamed scanning with small buffers.
* **ASCII + UTF-16LE** search.
* Proceeds to scan even if WinPmem returns a **non-zero** code **as long as** a sizable dump exists.



## Quick start

1. Open **PowerShell as Administrator**.
2. Run:

   ```powershell
   .\memcap-win.exe "String"
    ```

> Press **Ctrl+C** any time → dump & helper are removed before exit.



## Requirements

* Windows 10/11 x64
* **Administrator** privileges (driver load)
* Sufficient free space on the `%TEMP%` drive (memory dumps can be many GB)
* Security products (EDR/Defender) may need to allow the WinPmem driver


## Build it yourself

**Toolchain:** MSVC is recommended to produce a truly self-contained `.exe`.

```powershell
# 1) Ensure MSVC target:
rustup default stable-x86_64-pc-windows-msvc

# 2) Build release:
cargo build --release
```

### Dependencies

* [`windows-sys`](https://crates.io/crates/windows-sys) (Win32 API bindings)
* [`ctrlc`](https://crates.io/crates/ctrlc) (Ctrl+C handler)



## Notes on EDR / non-zero exit codes

* On some systems (VBS/HVCI, kernel protections), certain ranges are unreadable. WinPmem may still write a mostly complete dump but exit with a non-zero code.
* This tool **continues** if a dump larger than a small threshold (e.g., 16 MiB) exists, and **then scans it**.



## Legal & privacy

* **Use only with proper authorization**. Memory images can contain sensitive data (credentials, personal information).
* Handle, store, and dispose of dumps according to your organization’s security policies.
* This software is provided **“as is”**, without warranty of any kind.



## License

This project **bundles** WinPmem mini, which is **Apache-2.0** licensed.



## Acknowledgments

* **WinPmem** authors & contributors — for an excellent, widely used Windows memory acquisition driver.



## Troubleshooting

* **“Must be run as Administrator.”**
  Right-click PowerShell → *Run as administrator*.
* **Disk fills up.**
  Dumps are large; ensure `%TEMP%` has enough space. The file is deleted when scanning ends or on Ctrl+C.