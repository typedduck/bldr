# bldr - Self-Hosting Build Library for C Projects

A single-header C23 build library that eliminates the need for external build tools like Make or CMake. Define your build process in C itself, leveraging the full power of a programming language for your build logic.

## Status

This project is currently in **alpha stage** and under active development. The API may change, and some features are still being implemented. Use in production at your own risk.

## Features

- **Zero Dependencies**: No external build tools required - just a C compiler
- **Self-Hosting**: The library builds itself using itself
- **Single Header**: Distribute as `bldr.h` - one file to copy
- **STB-Style Library**: Include once with `#define BLDR_IMPLEMENTATION`
- **Cross-Platform**: Linux, macOS, and FreeBSD support
- **Modern C23**: Takes advantage of latest C standard features
- **Process Management**: Execute commands with timeout, I/O redirection, and async support
- **File Operations**: Walk directories, pattern matching, file concatenation
- **Memory Management**: Arena allocator with virtual memory backing
- **Logging**: Built-in logging with multiple levels

## Quick Start

### Building the Library

```sh
gcc -o bldr bldr.c
./bldr
```

This generates `bldr.h` - a single-header library ready for use.

### Using in Your Project

1. Copy `bldr.h` to your project
2. Create `bldr.c`:

```c
#define BLDR_IMPLEMENTATION
#define BLDR_STRIP_PREFIX
#include "bldr.h"

int main(int argc, char **argv) {
    // Rebuild yourself if source changed
    build_yourself(argc, argv, "bldr.c", "bldr.h");
    
    // Initialize arena allocator
    DEFER(arena_t arena, arena_done) = {0};
    arena_init(&arena, 64 * 1024);
    
    // Build your project
    DEFER(cmd_t cmd, cmd_done) = {0};
    cmd_append(&cmd, "gcc", "-o", "myapp", "main.c");
    
    int exit_code;
    int result = proc_exec(&cmd, &exit_code, 
        .log_command = true,
        .log_stderr = true
    );
    
    return result == OK ? exit_code : result;
}
```

3. Build and run:

```sh
gcc -o bldr bldr.c
./bldr
```

## Core Components

### Arena Allocator

Fast bump allocator with checkpoint/rewind support:

```c
arena_t arena;
arena_init(&arena, 1024 * 1024);
char *str = arena_strdup(&arena, "hello");
size_t checkpoint = arena_save(&arena);
// ... allocate more ...
arena_rewind(&arena, checkpoint);  // Free everything after checkpoint
arena_done(&arena);
```

### Command Execution

```c
cmd_t cmd = {0};
cmd_append(&cmd, "gcc", "-c", "file.c");
proc_exec(&cmd, NULL, .timeout_ms = 5000);
cmd_done(&cmd);
```

### File Operations

```c
// Walk directory tree
strings_t files = {0};
strs_walk(&files, &arena, "src", "*.c", 
    .recursive = true,
    .no_dirs = true
);

// Check if rebuild needed
if (needs_rebuild("output", "input1.c", "input2.c") > 0) {
    // Rebuild...
}
```

### Process Management

```c
proc_handle_t handle;
proc_exec_async(&cmd, &handle, .close_stdin = true);
// ... do other work ...
proc_wait(&handle, &exit_code, 1000);  // 1 second timeout
proc_handle_done(&handle);
```

## Configuration Options

Customize behavior via preprocessor defines before including `bldr.h`:

```c
#define BLDR_ARENA_CAPACITY (8 * 1024 * 1024) // Default arena size
#define BLDR_OOM_ABORT true                   // Abort on out-of-memory
#define BLDR_LOG_LEVEL_DEFAULT BLDR_LOG_INFO  // Default log level
#define BLDR_LOG_LEVEL_MAX BLDR_LOG_INFO      // Max log level compiled
#define BLDR_STRIP_PREFIX                     // Remove bldr_ prefix
```

## Error Handling

The library uses result codes for error handling:

```c
int result = some_operation();
if (result != OK) {
    // Handle error
    return result;
}

// Or use the AND_THEN macro for chaining
AND_THEN(result, operation1());
AND_THEN(result, operation2());
```

With `BLDR_OOM_ABORT=true` (default), memory allocation failures abort the program. Set to `false` for manual error handling.

## Platform Support

- **Linux**: Full support with advanced features
- **macOS**: Full support (including Apple Silicon)
- **FreeBSD**: Partial support, some features limited

## Project Structure

```
.
├── bldr.c              # Build script (builds bldr.h)
├── bldr.h              # Generated single-header library
├── include/            # Modular headers (for development)
├── src/                # Modular sources (for development)
├── examples/           # Usage examples
└── tests/              # Test suite
```

The library is developed in modular form (`include/` and `src/`) but distributed as a single header.

## License

MIT License - see LICENSE file for details

## Credits

Partially inspired by [nob.h](https://github.com/tsoding/nob.h) by Tsoding.

## Roadmap

- [ ] Complete async command execution (cmd_procs_* functions)
- [ ] Comprehensive test suite
- [ ] Documentation
- [ ] More examples
- [ ] Stable 1.0 release
