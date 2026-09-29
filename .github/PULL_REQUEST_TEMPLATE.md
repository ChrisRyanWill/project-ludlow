## What and why

<!-- What does this change, and why is it needed? Link the issue. -->

## Checklist

- [ ] `npm test` passes (or I explained why not)
- [ ] I added tests that fail without this change
- [ ] No new third-party requests; no `innerHTML`, `eval` or inline scripts
- [ ] Nothing logs bodies, tokens or IPs; secrets stay in URL fragments
- [ ] Legal text: sources are cited and uncertainty is marked `TODO(lawyer)` (add the `needs-legal-review` label)
- [ ] New workspace route: goes through `W()` and the permission matrix; any route returning card ciphertext checks the release lock
- [ ] UI change: screenshots attached (light and dark)
- [ ] If a large part is AI-generated: I understand and have tested every line

## Notes for reviewers

<!-- Anything risky, surprising, or worth a second pair of eyes. -->
