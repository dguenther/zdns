# zdns

A DNS filtering server in Zig.

## 🚧 🚧 WARNING 🚧 🚧

This project primarily exists to experiment with Zig, and likely has bugs, missing features, and/or security vulnerabilities. For serious use, consider something like [Pi-Hole](https://github.com/pi-hole/pi-hole) or [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).

## Use

`zdns` filters DNS requests against a provided blocklist. If a requested domain is found in the blocklist, `zdns` will respond according to the configured block mode. Otherwise, it will forward the request to an upstream DNS server.

### Config

*   **Positional Arguments**
    *   `<upstream>`: (Required) The IPv4 address of the upstream DNS server to forward requests to (e.g. `1.1.1.1`).

*   **Flags**
    *   `--blocklist-url <url>` (or `-b <url>`): (Required) URL to the blocklist file. This file should be in a format where each line contains an IP address (usually `0.0.0.0` or `127.0.0.1` for blocking purposes) followed by one or more hostnames. Example: `https://some-site.com/hosts.txt`.
    *   `--address <ip>`: Local IP address for the DNS server to bind to. Defaults to `0.0.0.0`.
    *   `--port <port>` (or `-p <port>`): Local port for the DNS server to bind to. Defaults to `53`.
    *   `--block-mode <mode>`: Specifies the response type for filtered domain names. Defaults to `nullip`.
        *   `nullip`: "Return a null response (resolve to 0.0.0.0)"
        *   `nxdomain`: "Return an NXDOMAIN response (domain does not exist)"

### Example

```sh
zdns --blocklist-url https://my-blocklist-provider.com/hosts.txt 1.1.1.1
```
