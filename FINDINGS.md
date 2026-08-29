# Findings in the wild

Weaknesses this engine found in software it had never seen, reported to the maintainers, and
**fixed by them**. Nothing appears here until the project has shipped a public fix, because
until then the finding is theirs to disclose and not ours.

Reports that are still open are not listed. That is deliberate and it is the point of the list:
a confirmed entry is one somebody else agreed with and acted on.

---

### ArchiveBox — the URL branch of a snapshot lookup skipped the permission filter its sibling applied, and the add view was CSRF exempt

**Reported** 28 August 2026 · **Fixed** [`fce1827f`](https://github.com/ArchiveBox/ArchiveBox/commit/fce1827feda5) · [issue #1844](https://github.com/ArchiveBox/ArchiveBox/issues/1844)

`archivebox/core/views.py` built a permission-filtered queryset at line 716 and then used it on
only one of two branches. The `snapshot_id` branch checked `can_view_snapshot()` and redirected
when it failed; the `requested_url` branch built its own queryset from scratch and selected from
that. Both converged on the same canonical redirect, so a snapshot that was not public was
reachable through the URL branch by somebody who could not reach it through the id branch.

Separately, `AddView` carried `@method_decorator(csrf_exempt, name="dispatch")` while its
`form_valid` created and fetched a crawl, and `PUBLIC_ADD_VIEW` defaults to `False`, so on a
default install a page a logged-in user visited elsewhere could post to it.

The maintainer fixed both, and explained the second: the exemption dated to 2021, added so a
browser extension could reuse the admin session before ArchiveBox had a real API. It is now
`csrf_protect` for authenticated users and exempt only for anonymous ones where
`PUBLIC_ADD_VIEW` is on.

**How the engine got there.** `control-omitted-on-sibling-path`, which relates two paths that
reach the same operation and asks whether both are guarded — the rule exists because no analysis
that looks at one path at a time can see an asymmetry. The CSRF finding came from
`csrf-state-change`, an entry point with no token check that writes persistent state.

**This is the first entry the engine found on its own.** healthchecks below came from the
independent review track and the engine did not report it; here the engine named both defects,
at the file and line the maintainer changed, and a human verified them at source before the
report went out.

---

### healthchecks — email verification token did not cover the address it verified

**Reported** 27 August 2026 · **Fixed** [`6b634df`](https://github.com/healthchecks/healthchecks/commit/6b634df13367bea9502a451514f57a1038f7db6b)

`Channel.make_token()` seeded a SHA-256 with the channel's immutable UUID and the server secret,
so the token did not depend on the address it was verifying. Changing a channel's address left
the token unchanged, and the old verification link still worked.

The maintainer's own commit message describes the same attack the report did, arrived at
independently:

> eve@example.org adds an integration for eve@example.org and receives a verification link in
> their inbox. Before pressing the link, Eve edits the integration and changes the email address
> to alice@example.com

The fix seeds the token with the address and switches to HMAC.

**How the engine got there.** The rule is `unowned-record-access`: a caller-supplied key selects
a record, and nothing ties that key to the actor. The token here IS the key, and what it does not
cover is what makes it forgeable. The engine reported the shape; a human read the three files and
established that the address is what the token fails to bind.

---

## How this list is kept honest

- An entry needs a **public fix by the maintainer**, linked. Not an acknowledgement, not a triage
  state, not our own assessment.
- The report is written and read by a person before it is sent. Every one states plainly that it
  came from static analysis, that the application was never run, and that a check the analysis
  could not follow would make it wrong.
- A report a maintainer rejects is **more useful than one they confirm**: it goes back into the
  loop as a false positive with a reason, which is a defect in the engine rather than a defect in
  their software. Those do not appear here, because this list is about the engine's successes and
  the ledger is where its mistakes are kept.
