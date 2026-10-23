# TRINITYWAYVE ↔ STEEL integration

TRINITYWAYVE is the 3XTRINITY parent homepage / command-center surface. STEEL remains an independent product repository and the source of truth for the music application.

## Parent homepage

Vercel preview:

https://trinitywayve-3xtrinity-hww0bz2br-3-xtrinity.vercel.app

GitLab implementation / merged MR:

https://gitlab.com/ARHIDEKT/my-side-project/-/merge_requests/3

Merge commit:

c1e4ded034c1275d7b21aa06a267394591d58310

## Contract

TRINITYWAYVE owns:
- the parent navigation and module discovery surface;
- the STEEL module landing page;
- cross-product visual identity and shared command-center UX.

STEEL owns:
- music-production runtime code;
- audio graph and local-first/PWA behavior;
- STEEL-specific build, tests and release evidence;
- the STEEL side of AURA synchronization.

## Next runtime binding

When STEEL has a verified stable runtime/deployment URL:
1. expose it from the STEEL release evidence;
2. bind the TRINITYWAYVE STEEL module CTA to that URL;
3. verify build + start + basic audio/runtime smoke tests;
4. preserve no-token-in-browser and secret/logging rules.

## Current infrastructure note

The TRINITYWAYVE GitLab pipeline was created but GitLab did not start jobs because CI quota was exceeded (ci_quota_exceeded). The Vercel static preview deployment reported READY.