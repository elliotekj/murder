# murder

A Rust CLI that kills processes bound to specified ports using progressively aggressive signals.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
murder <PORT>...
murder 4000
murder 3000 4000 5000
```

## Behavior

Sends signals in order, waiting up to 2 seconds per level before escalating:

1. **SIGINT** (2) - Polite interrupt
2. **SIGTERM** (15) - Termination request
3. **SIGKILL** (9) - Force kill

Polls every 100ms to check if the process has terminated. Total timeout is 10 seconds.

### Multi-Port

Multiple ports are processed in parallel. If the same PID is bound to multiple ports, it's only killed once.

### Permissions

If permission is denied (EPERM), murder re-executes itself with `sudo`.

## Example

```
$ murder 4000
[4000] Found PID 1234 (node)
[4000] Sending SIGINT to PID 1234
[4000] Process still running, waiting...
[4000] Sending SIGTERM to PID 1234
[4000] Process terminated
```

## Exit Codes

- **0** - Success (all processes killed, or no process was bound)
- **1** - Failure (unable to kill one or more processes)

## Platform Support

- macOS (uses `lsof`)
- Linux (uses `ss` or `/proc/net/tcp`)

## License

`murder` is released under the [Apache License 2.0](LICENSE).

## About

This package was written by [Elliot Jackson](https://elliotekj.com).

- Blog: [https://elliotekj.com](https://elliotekj.com)
- Email: elliot@elliotekj.com

