# Architecture
```mermaid
flowchart TD
 GUI[Unprivileged desktop] -->|Authenticated IPC| Service[Windows service]
 Service --> Backend[Process-aware networking backend]
 Backend --> Core[Routing core / pinned flows]
 Core --> Direct[DIRECT]
 Core --> Transport[Persistent QUIC session]
 Transport --> Relay[Linux relay]
 Relay --> Destination[Destination]
 CP[Control plane / PostgreSQL] -->|Signed config and tickets| Service
```
Go is shared by core, relay and control plane. UI never forwards packets.
Unknown process, invalid measurement or unavailable relay defaults to DIRECT.
Already established TCP connections never migrate. Control plane is outside the data path.
See ADRs and docs/STATUS.md for implemented boundaries.
