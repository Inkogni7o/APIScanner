# Bundled third-party Semgrep rules

ADScan runs this local selection together with its six own rules when `--semgrep`
is enabled. Custom `--semgrep-config` files replace the complete default selection.
No registry access or downloads occur during a scan.

| Source | Snapshot | Rules | License |
| --- | --- | ---: | --- |
| [GitLab SAST rules](https://gitlab.com/gitlab-org/security-products/sast-rules) | `53bf5cf6df3c51b6c02110f5a638b5e6213666cd` | 48 | MIT; Go rules derived from gosec: Apache-2.0 |
| [njsscan](https://github.com/ajinabraham/njsscan) | `4137df39e743e07e912a31ca7dab19633f40324a` | 27 | LGPL-3.0 |

The selection covers Python, Go, Java and JavaScript/TypeScript: SQL injection,
SSRF, path traversal and archive extraction, XSS/template injection, command/code
execution, unsafe deserialization, TLS verification, JWT and dangerous configuration.
Rust uses ADScan's own process-execution rule; no third-party Rust rules are included.

Each source directory contains the upstream license and `provenance.json` with
the immutable commit, original paths, rule IDs and SHA-256 hashes. Selected YAML
files are distributed unchanged. The Go rule headers retain their original gosec
attribution and Apache-2.0 license; its full text is in `gitlab/LICENSE-gosec`.
njsscan's LGPL text is accompanied by the GPL-3.0 text it incorporates.

Rules remain under their respective licenses and may be replaced using local
Semgrep configs. A finding is a review candidate, not proof of an exploitable
vulnerability. Some upstream patterns recognize specific imports or framework APIs;
coverage varies with the application's coding style.
