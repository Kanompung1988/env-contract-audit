# Environment contract rules

| Rule | Severity | Meaning |
|---|---|---|
| ENV001 | medium | Supported code references env names but no matching example file exists. |
| ENV002 | high / low | Referenced name is not documented in any example file. Explicit fallback makes it low. |
| ENV003 | high | A client-exposed VITE_/NEXT_PUBLIC_/PUBLIC_ variable name contains SECRET/TOKEN/PASSWORD/PRIVATE_KEY/CREDENTIAL/API_KEY. Heuristic: name alone is not proof of a leak. |
| ENV004 | low | Duplicate key in a single example file; later value overrides earlier value in common dotenv parsers. |
| ENV005 | info | With --check-unused, documented key not found by supported source heuristics; do not delete automatically. |

## Scope and false positives
- Python import aliases, computed strings, custom env wrappers and dotenv injection are outside scope.
- JS/TS matching is line-based and may match comments, strings or declarations unrelated to runtime execution.
- Keys documented in any example file count as documented across a monorepo; separate environment scopes and deployment-platform settings are not modeled.
- Browser exposure policy is framework-specific; Vite documents that `VITE_` variables are exposed in client code. See https://vite.dev/guide/env-and-mode.
- Never interpret an apparent missing key as evidence of outage without verifying deployment configuration.
