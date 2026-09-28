# Xray adapter

This package registers VLESS links with `type=xhttp`; other VLESS links use the
existing outbound implementation. Import it before processing node links.

Requires the official Xray executable on PATH (tested with v26.3.27).
`go test -race ./component/xray` runs isolated local integration tests when Xray
is available, including REALITY and VLESS encryption. No real node credentials
or external test servers are required.

The adapter owns its worker processes and local authenticated SOCKS gateways.
A gateway connects using the original dae dialer, rather than allowing Xray to
make direct remote connections. See daed's `docs/XRAY.md` for usage and limits.
