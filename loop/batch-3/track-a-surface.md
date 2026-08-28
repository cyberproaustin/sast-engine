# Batch 3, Track A: the surface, before anything was adjudicated

Frozen engine 7846838, ten repositories, no fixes in flight.

| repo | role | lang | entry points | findings | input readers NOTHING reaches |
|---|---|---|---|---|---|
| defectdojo | fix | py | 700 | 43 | 0 |
| rallly | fix | ts | 143 | 8 | 0 |
| ever-gauzy | hold | ts | 1542 | 235 | 0 |
| mealie | fix | py | 272 | 3 | 21 |
| kiwi | hold | py | 48 | 0 | 32 |
| netbox | fix | py | 128 | 6 | **116** |
| plane | fix | ts | 27 | 74 | **121** |
| misago | hold | py | 195 | 12 | **253** |
| oscar | fix | py | 30 | 6 | **279** |
| wagtail | fix | py | 199 | 2 | **429** |

**Five of the ten cannot see most of their own application.** That is not a rule problem and
no rule can be measured through it: a finding needs an entry point to anchor to, so a repo
whose surface is half enumerated has had half its code excused from judgement.

## It is not "Django"

DefectDojo is Django with DRF and enumerates 700 entry points with nothing unreached. What
separates it from oscar, wagtail, misago and netbox is the REGISTRATION IDIOM, and each of
those four uses one the engine has never been shown:

- **django-oscar** composes routes in `get_urls()` methods on Application classes that call
  `super().get_urls()` and append (`src/oscar/apps/catalogue/apps.py:27`). There is no
  module-level `urlpatterns` to read. 828 Python files, 30 entry points.
- **wagtail** serves pages through its own routing and registers admin views through hooks.
  429 functions read caller input that nothing reaches.
- **misago** and **netbox** each register through their own indirection, not yet read.

The prediction written before this batch said the misses would include "one framework idiom
we have never modelled, which is the pattern every batch has produced so far." That is right
in kind and wrong in scale: it is four idioms, in five of ten repositories, and it dwarfs
every rule-level gap on the list.

## One of these is my error, not the engine's

**plane** was labelled `ts` because 3295 TypeScript files outnumber 653 Python ones. Its API
is the Django `apiserver`, so the scan read the Next.js frontend and never opened the half
where authorization lives. The batch harness takes one language per repository and a
bilingual monorepo has two. paperless-ngx had the same shape in batch 2 and the fix went into
the rescan script rather than into selection.

## Route coverage, measured

Declared is `path()`/`re_path()`/`url()` plus DRF router registrations and FastAPI
decorators, counted from source. Enumerated is what the engine produced. Over 100% is
correct and expected: one `path()` can register several methods and a router expands into
six.

| repo | declared | enumerated | coverage |
|---|---|---|---|
| mealie | 236 | 272 | 115% |
| defectdojo | 650 | 700 | 108% |
| kiwi | 66 | 48 | 73% |
| misago | 337 | 195 | 58% |
| wagtail | 352 | 199 | 57% |
| netbox | 532 | 128 | **24%** |
| oscar | 219 | 30 | **14%** |
| plane | 399 | 51 | **13%** |

## plane, re-scanned as Python after correcting the selection error

The Django API is at `apps/api/plane/` with an ordinary `urlpatterns`, so the idiom is not
exotic. What defeats the enumerator is two hops:

    urlpatterns = [ path("api/", include("plane.app.urls")), ... ]

`include()` takes a DOTTED STRING, and `plane.app.urls` is a package whose `__init__.py`
re-exports from twenty-two submodules under aliases:

    from .analytic import urlpatterns as analytic_urls
    from .cycle    import urlpatterns as cycle_urls
    ...

Following that needs module resolution from a string plus aliased re-export composition.
396 declared routes, 51 enumerated, and those 51 carry no method or route detail at all.

Both scans are kept: `plane/ts-scan/` holds the Next.js result (27 entry points, 74
findings, 121 unreached) and `plane/` now holds the Python one (51, 15, 202 unreached).
Neither is the whole application, which is the honest description of a bilingual monorepo
read one language at a time.

## After the include/mount fix (merged, 200 corpora at 1.00/1.00)

| repo | declared | before | after | distinct addresses |
|---|---|---|---|---|
| plane | 399 | 51 (13%) | **578** | **370 (93%)** |
| defectdojo | 650 | 700 | 730 | - |
| wagtail | 352 | 199 | 201 | 69 of 164 registrations had their ADDRESS corrected |
| oscar | 219 | 30 | 33 | still the registry idiom, other agent's lane |

**paperless-ngx went 9 -> 78**, and it is a BATCH 2 repository. Its API was invisible when
batch 2 was measured, so every batch-2 number involving paperless was computed over roughly
an eighth of its surface. One finding and one rejected report came out of that repository;
the aggregate effect on batch 2 is small, but the principle is not: a coverage figure was
never recorded for batch 1 or batch 2, so we do not know how many of those numbers have the
same problem.

**Surface coverage must be measured and recorded per repository, every batch, before any
precision or recall figure is quoted.** A precision number over an eighth of an application
is not a statement about the engine.

The fixtures record something sharper than a miss. On `django-package-reexport` the old
frontend reported ASVS 1.2.5 **SATISFIED** for an application containing a command injection:
it found one entry point, at a class name, reaching nothing. A false clean bill is worse than
silence, and this is the second time an enumeration gap has produced one.
