# SmartGate ports

Each folder is a native implementation of the engine (policy, scoring, cascade, kill registry, audit chain)
plus a client for the SmartGate server. All of them pass the same 88 vectors as the Python reference
(`../spec/conformance`), and their clients are checked against a running server. None is published on a
package registry; use them from a clone. None has a dependency.

    ports/conformance/run.sh        # vectors, every engine with an installed toolchain
    ports/conformance/interop.sh    # clients against the Python server

| Folder | Build and test |
|---|---|
| `node` | `node test/conformance.js` · interop: `node test/interop.js` |
| `go` | `go test ./...` · `go run ./cmd/conformance` · `go run ./cmd/interop` |
| `rust` | `cargo run --bin conformance` · `cargo run --bin interop` |
| `java` | `./build.sh` then `java -cp build/classes cloud.smarttasks.smartgate.Conformance` (or `mvn package`) |
| `csharp` | `dotnet run --project Conformance` · `dotnet run --project Interop` (`nuget.config` has no package source: there is nothing to restore) |
| `php` | `php bin/conformance.php` · `php bin/interop.php` |
| `ruby` | `ruby bin/conformance.rb` · `ruby bin/interop.rb` |

The Rust client speaks plain HTTP only; use it on a private network or next to a local TLS proxy.
