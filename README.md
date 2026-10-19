# Process Exp

A process manager for Linux inspired by **Sysinternals Process Explorer**, written in C++ with Qt 6 Widgets.

It shows your processes as a tree and highlights them by category. You can see which files, sockets and libraries a process has open, and you can kill, suspend, re-prioritise or restart processes. All data comes straight from `/proc`, and the program has no dependencies besides Qt.

> **Not affiliated with Microsoft.** "Process Explorer" and "Sysinternals" are Microsoft products. This is an independent re-implementation of the idea for Linux. It contains no Microsoft code or assets.

## Why

KDE's System Monitor uses a lot of memory for what it does. A tool that watches processes shouldn't be one of the bigger processes on the system itself. Process Exp aims to stay small:

- about **14 MB** of private memory
- about **1 % of one CPU core** while refreshing every second (≈ 290 processes)
- a **~900 KB** binary

These numbers were measured in a Fedora VM with KDE Plasma 6. Shared Qt libraries aren't counted.

## 100 % vibe-coded

This project is entirely vibe-coded. I didn't write the code myself. It was produced by an AI assistant (Claude) from conversational instructions. I described what I wanted, tested the results on my desktop and asked for fixes and changes. Keep that in mind when you read or reuse the code.

## Features

- **Process tree** with the familiar colours: new processes are green, exiting ones red, your own processes blue, system services pink, suspended processes grey, Flatpak apps cyan and kernel threads beige. All colours are configurable.
- **Columns** for CPU, Private Bytes, Working Set, PID, description, user, threads, handles, priority, I/O, start time, systemd unit, command line and more.
- **Toolbar graphs** for CPU (kernel time in red), commit charge, physical memory and disk I/O, plus GPU on AMD. Hover a graph for the top process at that point in time.
- **Lower pane** listing a process's open handles (files, sockets with resolved addresses, pipes, devices) or its mapped libraries.
- **Process properties**: image, performance, performance graphs, threads (including wait channel), TCP/IP connections, security (UIDs, capabilities, SELinux context, namespaces), environment and strings (from the binary or from memory).
- **System information**: CPU per core, memory and swap, kernel memory, disk, network and GPU.
- **Find Handle or DLL** across all processes.
- **Find Window's Process**: click any window to select its process. This works on KDE Plasma (KWin), including XWayland and Wine windows.
- **Process actions**: kill, kill tree, terminate (SIGTERM), suspend/resume, restart, set priority and affinity (applied to all threads), open file location, search online.
- **Safe signalling**: signals go through a `pidfd` and are checked against the process start time, so a reused PID never receives a signal meant for a process that already exited. When access is denied, the action is retried through `pkexec`, and the same check runs again as root.
- **Filter box** (Ctrl+K), a flat list mode, a pause button and a configurable refresh rate.

### How Windows concepts map to Linux

| Process Explorer | Process Exp |
|---|---|
| Handles | open file descriptors (`/proc/PID/fd`) |
| DLLs | mapped shared objects (`/proc/PID/maps`) |
| Services | processes in a systemd `system.slice` unit |
| Immersive / Store apps | Flatpak apps |
| Run as Administrator | `pkexec` |
| Commit charge | `Committed_AS` relative to RAM + swap |

## Installation

### Fedora (Copr)

Prebuilt packages for Fedora on x86_64 and aarch64 are available from the [n0x073/tools Copr repository](https://copr.fedorainfracloud.org/coprs/n0x073/tools/package/process-exp/):

```bash
sudo dnf copr enable n0x073/tools
sudo dnf install process-exp
```

On other distributions, build the program from source as described below.

## Requirements

- Linux 5.3 or newer (pidfd). Kernel 6.2 or newer gives cheaper file descriptor counting.
- glibc 2.36 or newer
- Qt 6.10 or newer (Core, Gui, Widgets, DBus). Tested with Qt 6.11.
- CMake 3.20 or newer and a C++20 compiler (GCC 11+ or Clang 14+)
- Optional: KDE Plasma (KWin) for "Find Window's Process", and polkit (`pkexec`) for actions on other users' processes

## Building

### Fedora

```bash
sudo dnf install gcc-c++ cmake ninja-build qt6-qtbase-devel
git clone https://github.com/n0x073/process-explorer.git
cd process-explorer
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/process-exp
```

### Arch Linux

```bash
sudo pacman -S --needed base-devel cmake ninja qt6-base
git clone https://github.com/n0x073/process-explorer.git
cd process-explorer
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/process-exp
```

### Installing

```bash
sudo cmake --install build
```

This installs the `process-exp` binary, a desktop entry and the license under `/usr/local`. To use another prefix, pass `-DCMAKE_INSTALL_PREFIX=…` when configuring.

## Keyboard shortcuts

| Key | Action |
|---|---|
| Ctrl+I | System information |
| Ctrl+T | Toggle tree / flat list |
| Ctrl+L | Show lower pane |
| Ctrl+H / Ctrl+D | Lower pane: handles / libraries |
| Ctrl+F | Find handle or DLL |
| Ctrl+K | Filter |
| Enter | Properties |
| Del | Kill process |
| Shift+Del | Kill process tree |
| Ctrl+Del | Terminate (SIGTERM) |
| Space | Pause updates |
| F5 | Refresh now |
| Ctrl+S | Save process list |

Clicking a column header sorts by that column. A third click restores the tree order.

## Limitations

- "Find Window's Process" needs KWin, because other Wayland compositors don't let applications inspect other windows.
- There is no "Always On Top" option: Wayland doesn't let applications keep themselves above other windows. On KDE, use the window menu ("More Actions → Keep Above Others") or a window rule instead.
- GPU usage only appears on drivers that provide `gpu_busy_percent` (e.g. amdgpu).
- Private Bytes is approximated as resident minus shared memory.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
