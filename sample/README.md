# Sample: Hello World

This directory contains a simple hello-world program for demonstrating KnVest.

## Building on Windows

Using MinGW-w64 or Visual Studio:

```bash
# With MinGW-w64
gcc hello.c -o hello.exe

# With Visual Studio (x64 Native Tools Command Prompt)
cl hello.c /Fe:hello.exe
```

## Building on Linux (Cross-compile)

You can cross-compile for Windows using MinGW-w64:

```bash
# Install MinGW-w64
sudo apt-get install mingw-w64

# Compile for Windows x64
x86_64-w64-mingw32-gcc hello.c -o hello.exe
```

## Using KnVest

Once you have `hello.exe`, you can pack it and view its IR:

```bash
# Pack the executable
cargo run -- pack sample/hello.exe -o sample/hello_packed.exe

# View the VM bytecode IR
cargo run -- ir sample/hello_packed.exe
```

## Running the Packed Executable

On Windows, simply run:

```cmd
hello_packed.exe
```

The packed executable should still print "Hello, World!" just like the original.

## Notes

- The sample works best when compiled as a PE64 (x86-64) Windows executable
- KnVest virtualizes the entry point function by default
- The VM interprets the bytecode to produce the same behavior as the original code
