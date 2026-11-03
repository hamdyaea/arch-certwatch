# arch-certwatch — Local X.509 Certificate Expiration Monitor

Developer: Hamdy Abou El Anein
Contact: hamdy.aea@protonmail.com
License: GNU GPL v3 (see LICENSE).

A small Go tool to scan local PEM/DER X.509 certificates and report
certificates expiring within a configurable number of days.

## Build and test

```sh
go test ./... -count=1
go vet ./...
go build -o arch-certwatch .
./arch-certwatch -config config.yaml
```

The tests generate temporary self-signed certificates and never contact
a network service or modify production certificates.

## Exit codes

- `0`: no certificate is within the configured warning threshold.
- `2`: at least one certificate is nearing expiration.
- `3`: none of the configured scan paths can be accessed.

Missing individual paths are logged. Permission errors during directory
traversal are logged but do not necessarily make the scan fail; configure
the service with read access to the required certificate directories.

## Service

`arch-certwatch.service` is an **example** systemd unit. It now runs
with `--daemon --interval 60`, rather than executing one scan and
exiting. It is not automatically installed or enabled by this repository.

Check the paths in `config.yaml` and install the compiled binary at
`/usr/bin/arch-certwatch` only after reviewing the service permissions.
The service runs read-only and does not modify certificates.

`follow_symlinks: false` skips symlinked certificate files correctly;
previous code called `Stat` after opening the link, which always followed
it. Invalid `--interval` values are rejected.

This is a **local filesystem** certificate scanner. It does not connect to
HTTPS hosts or verify their deployed certificate chains.
The original version is preserved in Git branch `old`.
