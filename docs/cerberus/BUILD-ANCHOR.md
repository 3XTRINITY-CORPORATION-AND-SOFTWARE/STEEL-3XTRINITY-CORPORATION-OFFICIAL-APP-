# CERBERUS BUILD ANCHOR

Base commit: 7260666d8d1cee88634a431091e5509838683123
Branch: cerberus/integration-build

## Rules

- main is immutable from this build workspace
- no direct automatic merge to main
- every change must be committed
- CI must pass before promotion
- external integrations use least privilege
- secrets must never be committed
- failed builds remain isolated
