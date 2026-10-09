# Bundled third-party Semgrep rules

ADScan runs this local selection together with its six own rules when `--semgrep`
is enabled. Custom `--semgrep-config` files replace the complete default selection.
No registry access or downloads occur during a scan.

| Source | Snapshot | Rules | License |
| --- | --- | ---: | --- |
| [GitLab SAST rules](https://gitlab.com/gitlab-org/security-products/sast-rules) | `53bf5cf6df3c51b6c02110f5a638b5e6213666cd` | 71 | MIT; Go rules derived from gosec: Apache-2.0 |
| [njsscan](https://github.com/ajinabraham/njsscan) | `4137df39e743e07e912a31ca7dab19633f40324a` | 27 | LGPL-3.0 |
| [0xdea / raptor](https://github.com/0xdea/semgrep-rules) | `dae50da6e6e629750f1daec73a01ef9206a372ab` | 8 | MIT |
| [Federico Dotta](https://github.com/federicodotta/semgrep-rules) | `51b9b69f4e74a857526a4b3d277a38d15a47853b` | 2 | MIT |
| [Shield](https://github.com/alissonlinneker/shield-claude-skill) | `8336d1ba6048ff3e72c8dcee7e496d0cee87eb4b` | 11 | MIT |

There are **119 third-party rules + 6 ADScan rules = 125 default rules**.
The selection covers Python, Go, Java, JavaScript/TypeScript, Rust, C/C++, C#,
PHP, Ruby, Kotlin and Scala: SQL injection, SSRF, path traversal and archive
extraction, XSS/template injection, command/code execution, unsafe deserialization,
TLS verification, JWT, memory safety and dangerous configuration. New rules include:

- C/C++: format strings, double free/use after free, unsafe copies and command execution.
- C#/Scala: SQL/command injection, XXE, deserialization and cryptographic configuration.
- PHP/Kotlin: dynamically constructed SQL, plus PHP XSS, file inclusion and deserialization.
- Ruby: SQL/command injection, mass assignment, deserialization and disabled CSRF protection.
- Rust: dynamically constructed SQL, disabled TLS verification and hardcoded secrets.

C/C++, C#, PHP, Ruby, Kotlin and Scala currently use Semgrep only; ADScan does not
extract their HTTP routes. Their results appear in `unmatched_findings` and the
terminal report. Rust findings can be attached to supported HTTP handlers.

Each source directory contains the upstream license and `provenance.json` with
the immutable commit, original paths, rule IDs and SHA-256 hashes. Selected YAML
files from GitLab, njsscan, 0xdea and Dotta are distributed unchanged. Shield files
contain only the selected named rules, with their original IDs. Its Rust TLS rule
was corrected to include a receiver in the method patterns; `provenance.json`
records these changes and both upstream and bundled hashes.
The Go rule headers retain their original gosec
attribution and Apache-2.0 license; its full text is in `gitlab/LICENSE-gosec`.
njsscan's LGPL text is accompanied by the GPL-3.0 text it incorporates.

Rules remain under their respective licenses and may be replaced using local
Semgrep configs. A finding is a review candidate, not proof of an exploitable
vulnerability. Some upstream patterns recognize specific imports or framework APIs;
coverage varies with the application's coding style.
