# Porting SmartGate

A port implements [SEMANTICS.md](SEMANTICS.md) and passes every file in `conformance/`:

1. **Canonical JSON** writer (integers only; ASCII keys sorted byte-wise; minimal escapes) and SHA-256.
2. **Policy** reader with every validation rule (`policies.json` has the cases to accept and reject). Keep
   integers and floats apart when reading JSON: `2.5` is not a valid score.
3. **Engine**: score, level, friction, reasons in the documented order, the per-agent cascade window.
4. **Registry** and **Session**: the operations of `sequences.json` with their exact results.
5. **Audit**: build a chain from events, and verify one, reporting the first bad index.
6. **Client**: evaluate, approval polling, start / complete, checkpoint, kill, with the fallback modes.

Compare results by canonical JSON text, not by your language's equality, so key order and number types
cannot hide a difference. Add the port to `ports/conformance/run.sh` and `interop.sh`, and to the CI job.
A port has no dependencies unless the maintainers decide otherwise.
