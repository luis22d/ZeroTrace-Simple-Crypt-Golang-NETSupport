Simple Of Crypt In Golang Supports .NET Files

# ZeroTrace Crypt GO

An advanced Go-based crypter for Windows binaries with enhanced obfuscation techniques to minimize detection.

https://t.me/ZeroTraceOfficial


## Features

- **Multi-layer Encryption**
  - Hex encoding
  - XOR encryption
  - AES-GCM encryption
  - Optional ChaCha20-Poly1305 encryption

- **Advanced Process Execution**
  - RunPE implementation
  - Parent Process Spoofing (uses legitimate processes like explorer.exe)
  - DLL blocking capability (blocks non-Microsoft DLLs)

- **Obfuscation Techniques**
  - String obfuscation for API calls and DLL names
  - In-memory execution (no disk writing)
  - Code morphing through junk code insertion
  - Anti-analysis protections

- **Delivery Options**
  - Embedded payloads
  - Optional remote payload fetching

## Usage Guide

### Setup and Encryption

1. **Prepare Your Payload**
   - Place your payload executable in the `petoaes` folder
   - **Important**: Name your payload `sample.exe`

2. **Generate Encrypted Payload**
   - Run `PEtoAES.exe` from within the `petoaes` folder
   - This will generate two files in the parent directory:
     - `pe.txt` (encrypted payload)
     - `key.txt` (encryption key)

3. **Build the Loader**
   - For 32-bit compatibility (recommended):
     ```
     set GOARCH=386
     go build
     ```
   - For 64-bit build:
     ```
     go build
     ```

4. **Execution**
   - The final executable will load and execute your payload with all protection features enabled
   - No additional configuration required

### Configuration Options

You can modify settings in the source code before building:

- **Parent Process**: Change the spoofed parent process (default: explorer.exe)
- **Target Process**: Modify the process to inject into
- **Encryption**: Adjust encryption keys or algorithms
- **DLL Blocking**: Enable/disable non-Microsoft DLL blocking

### Example

```bash
# Place payload in petoaes folder as sample.exe
# Run the encryption tool
cd petoaes
./PEtoAES.exe

# Build the loader (32-bit)
cd ..
set GOARCH=386
go build

# The resulting executable is ready to use
```

## Implementation Details

The loader uses highly optimized techniques:

1. Decrypts the payload using multiple algorithms in sequence
2. Spoofs parent process for evasion
3. Blocks non-Microsoft DLLs to prevent analysis
4. Uses obfuscated Windows API calls
5. Implements heavy signature manipulation through junk code

The project incorporates both defensive (obfuscation, encryption) and offensive (process injection, spoofing) techniques designed to maximize stealth.

## Disclaimer

This tool is intended for educational purposes and legitimate software protection scenarios only. Users are responsible for ensuring compliance with applicable laws and regulations.

## License

This project is licensed under the MIT License - see the LICENSE file for details.


ZeroTrace Crypt GO
An advanced Go-based crypter for Windows binaries with enhanced obfuscation techniques to minimize detection.
Features

Multi-layer Encryption

Hex encoding
XOR encryption
AES-GCM encryption
Optional ChaCha20-Poly1305 encryption


Advanced Process Execution

RunPE implementation
Parent Process Spoofing (uses legitimate processes like explorer.exe)
DLL blocking capability (blocks non-Microsoft DLLs)


Obfuscation Techniques

String obfuscation for API calls and DLL names
In-memory execution (no disk writing)
Code morphing through junk code insertion
Anti-analysis protections
