# Troubleshooting
Go must be the language toolchain, not /usr/bin/go on this worker.
Use PATH="$PWD/work/toolchain/go/bin:$PATH" for commands.
TLS errors: check CA, certificate validity, server hostname and client identity.
UDP unavailable: QUIC cannot connect; new flows should use DIRECT.
No packet capture occurs until the Windows backend is implemented.
