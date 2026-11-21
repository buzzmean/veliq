# ADR-004: Desktop UI
Choose WPF for the first Windows-only UI, with an unprivileged process and
ACL-restricted named pipe IPC to the Windows service.

| Option | Tradeoff |
|---|---|
| WPF | Mature Windows integration; .NET runtime; Windows-only |
| WinUI 3 | Modern controls; packaging and Windows App SDK complexity |
| Tauri | Cross-platform; Rust/WebView bridge and dependency footprint |
| Qt | Cross-platform native toolkit; licensing and C++ deployment |

UI is Phase 6. Home, Applications, Routes, Statistics, Diagnostics and Settings
must show measured service state. No fabricated connection or latency status.
