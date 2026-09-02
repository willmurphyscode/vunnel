from __future__ import annotations

import logging
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
from collections import defaultdict
from contextlib import ExitStack, closing
from typing import TYPE_CHECKING, Any

import orjson

from vunnel import result, schema
from vunnel.tool import fixdate
from vunnel.utils import http_wrapper as http
from vunnel.utils import osv, silent_remove

from . import parser_legacy
from .os_downconvert import os_identifier_for, osv_ecosystem_to_os_namespace, osv_to_os
from .usn_fixdate_overlay import USNFixDateOverlay, usn_extra_candidates
from .vex_overlay import VEXOverlay, distro_label_from_purl, source_package_from_purl

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from vunnel.workspace import Workspace


_CVE_FILENAME_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")


_SCHEMA_VERSION_RE = re.compile(r"/schema-([0-9]+(?:\.[0-9]+){1,2})\.json$")


# Minimum live (non-withdrawn) records a fragment must hold for its release to count
# as covered by OSV. When Canonical stops publishing a release they leave a residue of
# already-withdrawn records behind rather than dropping the ecosystem, so fragment
# existence says nothing about whether there is usable data in it. Measured 2026-09:
# residue fragments hold 0-4 live records (25.04: 3, 24.10: 4, 26.04: 0, plus
# ecosystem-rename stubs at 1-2), while the smallest healthy fragment holds 986
# (Ubuntu:Pro:26.04:LTS). 100 sits clear of both by ~25x.
_MIN_LIVE_RECORDS_FOR_COVERAGE = 100

# Base-ecosystem fragment filenames: `ubuntu-25.10.db` / `ubuntu-24.04-lts.db`. Anchored
# so Pro/FIPS/Realtime/BlueField slugs (`ubuntu-pro-24.04-lts.db`,
# `ubuntu-22.04-lts-for-nvidia-bluefield.db`) deliberately do NOT match.
_BASE_FRAGMENT_RE = re.compile(r"^ubuntu-(\d+\.\d+)(?:-lts)?\.db$")


def ecosystem_to_slug(ecosystem: str) -> str:
    """Map an OSV ecosystem string to a filesystem-safe slug.

    Lowercase and replace `:` with `-`. The mapping is reversible by
    splitting on `-` against the known ecosystem set, but we don't rely
    on that — the slug is opaque to callers.
    """
    return ecosystem.lower().replace(":", "-")


_VERSION_RE = re.compile(r"^\d+\.\d+$")


def pro_to_base_ecosystem(ecosystem: str) -> str | None:
    """Map a plain Ubuntu Pro (ESM) ecosystem to its base Ubuntu form.

    Only the plain ESM tier qualifies. Sub-tiers (FIPS, FIPS-updates,
    FIPS-preview, Realtime) and adjacent product lines (Nvidia-BlueField)
    are intentionally excluded:

      - FIPS / FIPS-updates / FIPS-preview rebuild specific packages
        (kernel, openssl, libgcrypt, ...) against FIPS 140-validated
        cryptographic modules. The crypto code paths differ from base.
        A CVE in the FIPS-rebuilt binary may or may not exist in the
        mainline binary depending on whether the bug is in the
        FIPS-modified code; inference would be unreliable.

      - Realtime is the PREEMPT_RT kernel — locking, scheduling, and
        concurrency paths are materially different. RT-specific CVEs
        and non-RT-specific CVEs both exist.

      - Nvidia-BlueField is a separate SmartNIC/DPU OS product line
        with its own package set.

    Plain Ubuntu Pro packages are byte-identical to base packages while
    base is supported, then diverge only via ESM-backported security
    patches. A CVE on Pro means the same vulnerable code shipped on base
    — that's the inference this enables.

      Ubuntu:Pro:20.04:LTS              -> Ubuntu:20.04:LTS    (plain ESM, inferable)
      Ubuntu:Pro:14.04:LTS              -> Ubuntu:14.04:LTS
      Ubuntu:Pro:FIPS:20.04:LTS         -> None                (different build)
      Ubuntu:Pro:FIPS-updates:22.04:LTS -> None                (different build)
      Ubuntu:Pro:Realtime:24.04:LTS     -> None                (PREEMPT_RT kernel)
      Ubuntu:Nvidia-BlueField:22.04:LTS -> None                (separate product)
      Ubuntu:20.04:LTS                  -> None                (already base)
    """
    parts = ecosystem.split(":")
    # plain Pro shape: Ubuntu:Pro:<version>[:LTS], 3 or 4 segments, nothing between Pro and version
    if len(parts) not in (3, 4):
        return None
    if parts[0] != "Ubuntu" or parts[1] != "Pro":
        return None
    if not _VERSION_RE.match(parts[2]):
        return None
    if len(parts) == 4 and parts[3] != "LTS":
        return None
    return ":".join(["Ubuntu", *parts[2:]])


def _affected_package_names(payload: dict[str, Any]) -> set[str]:
    """Return the set of source-package names in a record's affected[]."""
    out: set[str] = set()
    for a in payload.get("affected", []):
        pkg = a.get("package", {}).get("name")
        if pkg:
            out.add(pkg)
    return out


def _synthesize_missing(
    pro_affs: list[dict[str, Any]],
    existing_pkgs: set[str],
    base_eco: str,
    pro_eco: str | None,
) -> list[dict[str, Any]]:
    """For each Pro affected[] entry whose source-package isn't already in the
    base envelope, produce a synthesized base affected[] entry tagged with the
    inference provenance.
    """
    new_affs: list[dict[str, Any]] = []
    for aff in pro_affs:
        pkg = aff.get("package", {}).get("name")
        if not pkg or pkg in existing_pkgs:
            continue
        existing_pkgs.add(pkg)
        synth = _build_synthetic_base_affected(aff, base_eco)
        synth["database_specific"]["anchore"]["inference"] = {
            "kind": "pro-only-fix",
            "source_ecosystems": [pro_eco] if pro_eco else [],
        }
        new_affs.append(synth)
    return new_affs


def _build_synthetic_base_affected(template: dict[str, Any], base_eco: str) -> dict[str, Any]:
    """Build a single synthetic affected[] entry for the base ecosystem.

    Inherits source package name and binary list from the Pro template (binaries
    on Pro ESM are byte-identical to base while base was supported; carrying
    them lets binary→source resolution still work downstream). Drops `purl`
    since its `distro=` qualifier points at a Pro codename (e.g. `esm-infra/jammy`).
    """
    src_pkg = dict(template.get("package", {}))
    src_pkg["ecosystem"] = base_eco
    src_pkg.pop("purl", None)

    eco_specific: dict[str, Any] = {}
    if "binaries" in template.get("ecosystem_specific", {}):
        eco_specific["binaries"] = template["ecosystem_specific"]["binaries"]

    return {
        "package": src_pkg,
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": eco_specific,
        "database_specific": {
            "anchore": {
                "status": "wont-fix",
                # `inference.source_ecosystems` filled in by the caller — the same
                # base (CVE, source-pkg) may have inferences from multiple Pro slices
                # (though restriction to plain Pro makes this rare in practice).
            },
        },
    }


def slice_by_ecosystem(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Group a record's affected[] entries by ecosystem.

    Returns a mapping {ecosystem -> sliced_record}. Each sliced record
    has the original top-level fields and an affected[] containing only
    the entries for that ecosystem. Records with no affected[] entries
    yield an empty mapping.
    """
    by_eco: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for aff in record.get("affected", []):
        eco = aff.get("package", {}).get("ecosystem")
        if not eco:
            continue
        by_eco[eco].append(aff)

    if not by_eco:
        return {}

    top = {k: v for k, v in record.items() if k != "affected"}
    return {eco: {**top, "affected": entries} for eco, entries in by_eco.items()}


def _os_fixed_in(os_payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return an OS-schema record's FixedIn list, or [] if it has no usable one.

    Used for merge accounting, so a record with a missing or oddly-shaped FixedIn
    has to read as "zero entries" rather than raise.
    """
    vuln = os_payload.get("Vulnerability")
    if not isinstance(vuln, dict):
        return []
    fixed_in = vuln.get("FixedIn")
    if not isinstance(fixed_in, list):
        return []
    return fixed_in


def _schema_from_envelope_url(url: str) -> schema.Schema:
    """Reconstruct a Schema object from an envelope's schema URL."""
    m = _SCHEMA_VERSION_RE.search(url)
    version = m.group(1) if m else "0.0.0"
    return schema.Schema(version=version, url=url)


def _iter_cve_records(tar: tarfile.TarFile) -> Iterator[dict[str, Any]]:
    """Yield parsed CVE records from a streaming tar (osv/cve/**/*.json only)."""
    for member in tar:
        if not member.isfile():
            continue
        if not (member.name.startswith("osv/cve/") and member.name.endswith(".json")):
            continue
        fh = tar.extractfile(member)
        if fh is None:
            continue
        yield orjson.loads(fh.read())


def _annotate_wont_fix(
    sliced: dict[str, dict[str, Any]],
    original: dict[str, Any],
    overlay: VEXOverlay,
) -> None:
    """Stamp `affected[].database_specific.anchore.status = "wont-fix"` for slices
    Canonical's VEX feed marks as won't-fix.

    Join key is (upstream CVE, PURL distro label, source package). The
    upstream CVE comes from the OSV record's `upstream[0]` (UBUNTU-CVE-* is
    Canonical's internal id; users and VEX use the upstream CVE). Distro
    label + source package come from each per-package PURL inside the slice.
    """
    upstream = original.get("upstream") or []
    if not upstream:
        return
    cve_id = upstream[0]

    for sliced_record in sliced.values():
        for aff in sliced_record.get("affected", []):
            purl = (aff.get("package") or {}).get("purl") or ""
            distro = distro_label_from_purl(purl)
            pkg = source_package_from_purl(purl)
            if not distro or not pkg:
                continue
            if not overlay.is_wont_fix(cve_id, distro, pkg):
                continue
            db_spec = aff.get("database_specific") or {}
            anchore = db_spec.get("anchore") or {}
            anchore["status"] = "wont-fix"
            db_spec["anchore"] = anchore
            aff["database_specific"] = db_spec


class Parser:
    _osv_url_ = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
    _vex_url_ = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
    _archive_filename_ = "osv-all.tar.xz"
    _vex_archive_filename_ = "vex-all.tar.xz"
    _fragments_subdir_ = "fragments"
    _normalized_subdir_ = "normalized-cve-data"

    def __init__(  # noqa: PLR0913
        self,
        workspace: Workspace,
        fixdater: fixdate.Finder | None = None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
        downconvert_osv_to_os: bool = False,
        downconvert_emit_esm: bool = True,
    ):
        self.workspace = workspace
        self.fixdater = fixdater if fixdater is not None else fixdate.default_finder(workspace)
        self.download_timeout = download_timeout
        self.logger = logger if logger is not None else logging.getLogger(self.__class__.__name__)
        # Opt-in compatibility: rewrite OSV fragments into v3 OS-schema records as they
        # are yielded. The legacy normalized-cve-data passthrough already emits OS shape,
        # so when this is enabled every yielded record is OS.
        self.downconvert_osv_to_os = downconvert_osv_to_os
        # When downconverting, also emit `ubuntu:X.YY+esm` channel records for plain Pro
        # (ESM). Default on; the frozen-v5 lane sets this off to take base records only.
        self.downconvert_emit_esm = downconvert_emit_esm

        self.archive_path = os.path.join(workspace.input_path, self._archive_filename_)
        self.vex_archive_path = os.path.join(workspace.input_path, self._vex_archive_filename_)
        self.fragments_dir = os.path.join(workspace.input_path, self._fragments_subdir_)
        self.normalized_cve_dir = os.path.join(workspace.input_path, self._normalized_subdir_)
        self.urls = [self._osv_url_, self._vex_url_]
        # USN fix-date overlay built lazily in get(); _iter_envelopes_with_fixdate reads it.
        self._usn_overlay: USNFixDateOverlay | None = None
        # Lazily computed set of ubuntu versions OSV actually covers, keyed off live
        # fragment record counts. Cached because the legacy passthrough asks the
        # predicate once per patch across ~70,000 CVE files.
        self._covered_versions: set[str] | None = None

    def __enter__(self) -> Parser:
        self.fixdater.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.fixdater.__exit__(exc_type, exc_val, exc_tb)

    def _download_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._osv_url_, self.archive_path)

    def _download_vex_archive(self) -> None:
        os.makedirs(self.workspace.input_path, exist_ok=True)
        self._stream_to_disk(self._vex_url_, self.vex_archive_path)

    def _stream_to_disk(self, url: str, path: str) -> None:
        self.logger.info(f"downloading {url}")
        with (
            http.get(url, self.logger, stream=True, timeout=self.download_timeout) as r,
            open(path, "wb") as fh,
        ):
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)

    def _record_schema(self, record: dict[str, Any]) -> schema.Schema:
        return schema.OSVSchema(version=record.get("schema_version", schema.OSV_SCHEMA_VERSION))

    def _open_fragment_writer(self, ecosystem: str) -> result.Writer:
        """Open a writer for a single ecosystem's fragment.

        Uses DELETE_BEFORE_WRITE so any prior fragment for this ecosystem
        is replaced wholesale. Fragments for ecosystems we don't open
        this run are left untouched (frozen).
        """
        os.makedirs(self.fragments_dir, exist_ok=True)
        path = os.path.join(self.fragments_dir, f"{ecosystem_to_slug(ecosystem)}.db")
        writer = result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=path,
            logger=self.logger,
        )
        return writer.__enter__()

    def _write_fragments(self, vex_overlay: VEXOverlay | None = None) -> None:
        """Stream the tarball, slice records by ecosystem, write per-ecosystem fragments.

        Each ecosystem encountered in today's tarball gets its fragment
        file wiped (via DELETE_BEFORE_WRITE) and rewritten. Ecosystems
        absent from today's tarball are not touched.

        NOTE: `patch_fix_date` is intentionally NOT called here. Fix-date
        annotations are applied at yield time (in _iter_fragments) so that
        improvements to the fixdate cache flow through to frozen fragments
        on the next run without rewriting them.

        Fix DISPOSITION (won't-fix vs other) is the opposite: it's baked
        into the fragment at write time using today's VEX overlay, so
        that frozen fragments carry the disposition forward through EOL.
        When VEX stops publishing for a release, the fragment retains the
        last-known wont-fix status from when the release was still tracked.
        """
        # Rewriting fragments invalidates any coverage classification computed from the
        # previous generation of them. get() already writes before the legacy passthrough
        # builds the cache, but resetting here keeps that independent of call order.
        self._covered_versions = None

        writers: dict[str, result.Writer] = {}
        exc: BaseException | None = None
        try:
            with tarfile.open(self.archive_path, mode="r:xz") as tar:
                for record in _iter_cve_records(tar):
                    self._dispatch_record_to_fragments(record, writers, vex_overlay)
        except BaseException as e:
            exc = e
            raise
        finally:
            for writer in writers.values():
                writer.__exit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)

    def _dispatch_record_to_fragments(
        self,
        record: dict[str, Any],
        writers: dict[str, result.Writer],
        vex_overlay: VEXOverlay | None,
    ) -> None:
        sliced = slice_by_ecosystem(record)
        if not sliced:
            return
        if vex_overlay is not None:
            _annotate_wont_fix(sliced, record, vex_overlay)
        rec_schema = self._record_schema(record)
        cve_id = record["id"].lower()
        for eco, sliced_record in sliced.items():
            if eco not in writers:
                writers[eco] = self._open_fragment_writer(eco)
            identifier = f"{ecosystem_to_slug(eco)}/{cve_id}"
            writers[eco].write(identifier=identifier, schema=rec_schema, payload=sliced_record)

    def _iter_fragments(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Yield (identifier, schema, payload) from every fragment on disk + inferred entries.

        Three things happen here, all at yield time so that improvements to
        upstream feeds + the fixdate cache flow through to frozen fragments
        on the next run without rewriting them:

          1. Real envelopes from each fragment are yielded verbatim (with
             fix-date patching applied).
          2. For each base Ubuntu ecosystem with sibling plain-Pro (ESM)
             fragments, any (CVE, source-pkg) tuple Pro has and base does
             NOT have produces a synthesized base wont-fix envelope. This
             reconstructs the signal Canonical encodes by *omission* of the
             base entry when a CVE will only be fixed in Pro.
          3. The inference runs from current Pro data every yield, so:
               - while base is still in OSV: inferred entries fill Pro-only-fix gaps
               - after base EOLs (frozen base fragment): inferred entries
                 from continuing Pro coverage layer on top of the frozen state.
        """
        if not os.path.isdir(self.fragments_dir):
            return

        base_paths, pro_paths, unclassified = self._group_fragments_by_base()

        # Yield unclassifiable fragments verbatim (test fixtures with empty affected[],
        # future shapes we don't recognize, etc.) — never apply inference to them.
        for path in unclassified:
            yield from self._iter_envelopes_with_fixdate(path)

        # Pass 1: yield Pro fragments verbatim. (Inference happens during the base pass.)
        seen_pro_paths: set[str] = set()
        for paths in pro_paths.values():
            for path in paths:
                if path in seen_pro_paths:
                    continue
                seen_pro_paths.add(path)
                yield from self._iter_envelopes_with_fixdate(path)

        # Pass 2: yield base envelopes (real + merged inferences from Pro siblings).
        # An inferred base entry shares the (base_eco, cve_id) key — and therefore the
        # envelope identifier — with any real base entry for the same CVE. We must
        # merge inferred affected[] entries INTO the real envelope before yielding;
        # emitting a separate envelope would collide under INSERT OR REPLACE and
        # the synthesized one would overwrite the real data.
        all_base_ecos = set(base_paths) | set(pro_paths)
        for base_eco in sorted(all_base_ecos):
            yield from self._yield_base_with_inferences(
                base_eco,
                base_path=base_paths.get(base_eco),
                pro_paths=pro_paths.get(base_eco, []),
            )

    def _yield_base_with_inferences(
        self,
        base_eco: str,
        base_path: str | None,
        pro_paths: list[str],
    ) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        # Collect real envelopes by cve, keyed so we can merge inferences in.
        by_cve: dict[str, dict[str, Any]] = {}
        cve_order: list[str] = []

        if base_path is not None:
            for env in self._iter_envelopes_with_fixdate(base_path):
                identifier, sch, payload = env
                cve = payload.get("id", "")
                if cve not in by_cve:
                    cve_order.append(cve)
                by_cve[cve] = {
                    "identifier": identifier,
                    "schema": sch,
                    "payload": payload,
                    "had_real": True,
                }

        if pro_paths:
            self._merge_inferred_into(by_cve, cve_order, pro_paths, base_eco)

        for cve in cve_order:
            entry = by_cve[cve]
            yield entry["identifier"], entry["schema"], entry["payload"]

    def _merge_inferred_into(
        self,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        pro_paths: list[str],
        base_eco: str,
    ) -> None:
        """Walk sibling Pro fragments. For each Pro envelope, append synthesized
        base entries to the real envelope (if one exists) or create a new
        envelope. Records the inference provenance.
        """
        for pro_path in pro_paths:
            with result.SQLiteReader(pro_path) as reader:
                for envelope in reader.each():
                    self._merge_pro_envelope(envelope, by_cve, cve_order, base_eco)

    def _merge_pro_envelope(
        self,
        envelope: result.Envelope,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        base_eco: str,
    ) -> None:
        payload = envelope.item
        cve = payload.get("id", "")
        if not cve:
            return
        pro_affs = payload.get("affected", [])
        pro_eco = pro_affs[0].get("package", {}).get("ecosystem") if pro_affs else None
        target = by_cve.get(cve)
        existing_pkgs = _affected_package_names(target["payload"]) if target else set()
        new_affs = _synthesize_missing(pro_affs, existing_pkgs, base_eco, pro_eco)
        if not new_affs:
            return
        if target is None:
            self._add_synthetic_envelope(by_cve, cve_order, envelope, new_affs, base_eco)
        else:
            target["payload"].setdefault("affected", []).extend(new_affs)

    def _add_synthetic_envelope(
        self,
        by_cve: dict[str, dict[str, Any]],
        cve_order: list[str],
        envelope: result.Envelope,
        new_affs: list[dict[str, Any]],
        base_eco: str,
    ) -> None:
        template = envelope.item
        cve = template["id"]
        synth_payload: dict[str, Any] = {k: v for k, v in template.items() if k != "affected"}
        synth_payload["affected"] = new_affs
        upstream = synth_payload.get("upstream") or []
        osv.patch_fix_date(
            synth_payload,
            self.fixdater,
            vuln_id_override=upstream[0] if upstream else None,
            extra_candidates=usn_extra_candidates(self._usn_overlay),
        )
        by_cve[cve] = {
            "identifier": f"{ecosystem_to_slug(base_eco)}/{cve.lower()}",
            "schema": _schema_from_envelope_url(envelope.schema),
            "payload": synth_payload,
            "had_real": False,
        }
        cve_order.append(cve)

    def _iter_envelopes_with_fixdate(
        self,
        fragment_path: str,
    ) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Read a fragment file, apply yield-time fix-date patching, yield envelopes."""
        extra_candidates = usn_extra_candidates(self._usn_overlay)
        with result.SQLiteReader(fragment_path) as reader:
            for envelope in reader.each():
                payload = envelope.item
                # patch_fix_date keys the lookup by vuln_id. The OSV record's `id` is
                # the Canonical-internal `UBUNTU-CVE-*`; the fix-date cache keys by the
                # upstream `CVE-*`. Pass the upstream override so the lookup hits.
                upstream = payload.get("upstream") or []
                osv.patch_fix_date(
                    payload,
                    self.fixdater,
                    vuln_id_override=upstream[0] if upstream else None,
                    extra_candidates=extra_candidates,
                )
                yield (
                    envelope.identifier,
                    _schema_from_envelope_url(envelope.schema),
                    payload,
                )

    def _group_fragments_by_base(self) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
        """Index fragments by their ecosystem.

        Returns (base_paths, pro_paths, unclassified_paths):
          - base_paths[base_eco]      → path to that base ecosystem's fragment, if present
          - pro_paths[base_eco]       → paths to plain-Pro sibling fragments of base_eco
          - unclassified_paths        → paths whose ecosystem couldn't be read (e.g. a
                                         hand-crafted test fragment or a future shape we
                                         don't recognize); yielded verbatim, no inference.

        Sub-tier fragments (FIPS / Realtime / Nvidia-BlueField) end up in base_paths
        keyed by their own ecosystem — they're yielded verbatim, with no inference
        applied (pro_to_base_ecosystem returns None for them).

        Fragment ecosystem is read from the first envelope's
        `affected[0].package.ecosystem` to avoid reverse-engineering the
        slug; every envelope in a fragment shares the same ecosystem by
        the slicing invariant.
        """
        base_paths: dict[str, str] = {}
        pro_paths: dict[str, list[str]] = {}
        unclassified: list[str] = []
        for filename in sorted(os.listdir(self.fragments_dir)):
            if not filename.endswith(".db"):
                continue
            path = os.path.join(self.fragments_dir, filename)
            eco = self._ecosystem_of_fragment(path)
            if eco is None:
                unclassified.append(path)
                continue
            base = pro_to_base_ecosystem(eco)
            if base is None:
                base_paths[eco] = path
            else:
                pro_paths.setdefault(base, []).append(path)
        return base_paths, pro_paths, unclassified

    @staticmethod
    def _ecosystem_of_fragment(path: str) -> str | None:
        """Peek the ecosystem string from a fragment by reading one envelope."""
        try:
            with result.SQLiteReader(path) as reader:
                for envelope in reader.each():
                    for aff in envelope.item.get("affected", []):
                        eco = aff.get("package", {}).get("ecosystem")
                        if eco:
                            return eco
                    return None
        except Exception:
            return None
        return None

    def _fragment_live_record_count(self, path: str) -> int:
        """Count the live (non-withdrawn) records in one fragment.

        Done in SQL rather than by parsing each record as JSON: the `withdrawn`
        key is only ever present on a withdrawn record, so a LIKE against the
        serialized record is enough to tell them apart. Verified to produce
        counts identical to full JSON parsing across the real 33-fragment,
        ~7 GB set, at 14.3s versus minutes for the parsing route.

        The database is opened read-only through a URI so that a missing or
        malformed path can neither be created nor mutated by the check.

        `closing()` rather than `with sqlite3.connect(...)`: sqlite3's own
        context manager scopes a TRANSACTION, not the connection — it leaves the
        handle open at block exit. There are 33 fragments totalling ~7 GB, and the
        repo's `filterwarnings` silences the unclosed-database ResourceWarning,
        so a leak here would be invisible.

        Any failure — file absent, not a database, truncated, no `results`
        table — counts as zero. That makes the release look uncovered, which is
        the safe direction: legacy also emits for it, and OSV still wins per-CVE
        downstream, so the worst case is redundancy rather than a coverage hole.
        """
        try:
            with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as conn:
                row = conn.execute("select count(*) from results where record not like '%\"withdrawn\":%'").fetchone()
            return int(row[0]) if row else 0
        except Exception as e:
            self.logger.debug(f"could not count live records in fragment {path}: {e}")
            return 0

    def _osv_covered_versions(self) -> set[str]:
        """Return the bare ubuntu versions (e.g. {"18.04", "25.10"}) OSV covers.

        Coverage is decided by live-record DENSITY, not by fragment existence.
        Canonical does not drop an ecosystem from the tarball when they stop
        publishing a release; they leave a residue of already-withdrawn records
        behind. `osv_to_os` drops withdrawn records, so an existing fragment can
        yield almost nothing while normalized-cve-data holds tens of thousands of
        usable records for the same release — exactly what happened to plucky
        (25.04): 184 rows, 181 of them withdrawn.

        The count is taken from the fragments on disk rather than from today's
        tarball on purpose. A release that has legitimately aged out of the feed
        keeps a healthy FROZEN fragment with thousands of live records and must
        still count as covered so legacy doesn't shadow it; counting from the
        tarball would misclassify every such release as uncovered.

        For the same reason staleness is not part of the test: a healthy frozen
        fragment is just as stale as a degenerate one, so `modified` age cannot
        separate them. Live record count can.

        Only base ecosystems are considered (`ubuntu-X.YY-lts.db` or
        `ubuntu-X.YY.db`). Pro/FIPS/Realtime/BlueField variants persisting after
        the base ecosystem drops is fine — they emit their own fragments, and the
        base release is meant to fall through to legacy.

        Cached on the instance: the legacy passthrough calls the predicate once
        per patch across ~70,000 CVE files, and recomputing per call would mean
        re-scanning every fragment that many times.
        """
        if self._covered_versions is not None:
            return self._covered_versions

        # A release is named by at most one of the two candidate filenames in practice,
        # but tolerate both: take the max live count so either healthy fragment covers it.
        counts: dict[str, int] = {}
        if os.path.isdir(self.fragments_dir):
            for filename in sorted(os.listdir(self.fragments_dir)):
                match = _BASE_FRAGMENT_RE.match(filename)
                if match is None:
                    continue
                version = match.group(1)
                count = self._fragment_live_record_count(os.path.join(self.fragments_dir, filename))
                counts[version] = max(counts.get(version, 0), count)

        covered: set[str] = set()
        for version, count in sorted(counts.items()):
            if count >= _MIN_LIVE_RECORDS_FOR_COVERAGE:
                covered.add(version)
                self.logger.info(f"osv coverage: ubuntu {version} has {count} live records -> covered")
            else:
                self.logger.info(f"osv coverage: ubuntu {version} has {count} live records -> uncovered")
                # A present-but-degenerate fragment is the plucky situation: OSV looks like
                # it covers the release, but nothing usable is left in it. Worth an
                # operator's attention, since legacy is now the one carrying the release.
                self.logger.warning(
                    f"ubuntu {version} has a fragment but only {count} live records "
                    f"(< {_MIN_LIVE_RECORDS_FOR_COVERAGE}); treating it as NOT covered by OSV "
                    f"and falling back to normalized-cve-data",
                )

        self._covered_versions = covered
        return covered

    def _osv_covers_legacy_namespace(self, ns: str) -> bool:
        """Return True if today's OSV feed covers a legacy namespace `ubuntu:X.YY`.

        Used to filter normalized-cve-data passthrough down to the at-cutover
        EOL set — we never want to emit legacy records for a release that
        OSV (or a frozen fragment for that release) already covers.

        A fragment merely EXISTING is not enough to establish that: Canonical
        leaves withdrawn-record residue behind for releases they've stopped
        publishing, and withdrawn records are dropped downstream. Coverage is
        therefore decided by live-record count — see `_osv_covered_versions`,
        which also explains why only base ecosystems are consulted (Pro/FIPS
        variants emit their own fragments; the base release falls through to
        legacy).
        """
        return ns.split(":")[-1] in self._osv_covered_versions()

    def _iter_normalized_cve_data(self, apply_osv_coverage_filter: bool = True) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Read input/normalized-cve-data/ via the vendored v3 map_parsed.

        With `apply_osv_coverage_filter` on (the default, and what the
        non-downconvert lane wants) this emits OS-schema envelopes for at-cutover
        EOL releases only — namespaces whose base ecosystem is in today's OSV feed
        (or a frozen fragment) are skipped. The filter is applied BEFORE map_parsed
        so fixdater isn't queried for releases we'd discard anyway.

        With it off every namespace is emitted. That is what the merged lane
        (`_iter_merged_os_records`) needs: coverage is decided per source package
        there, not per release, so legacy has to offer up its full set and let the
        merge pick the packages OSV has nothing to say about. The cost is real and
        accepted — map_parsed (and therefore fixdater) now runs for releases the
        release-level gate used to discard outright.
        """
        if not os.path.isdir(self.normalized_cve_dir):
            return

        os_schema = schema.OSSchema()
        for filename in sorted(os.listdir(self.normalized_cve_dir)):
            if not _CVE_FILENAME_RE.match(filename):
                continue
            full = os.path.join(self.normalized_cve_dir, filename)
            try:
                with open(full, "rb") as f:
                    cve_file = parser_legacy.CVEFile.from_dict(orjson.loads(f.read()))
            except Exception:
                self.logger.exception(f"failed to load normalized cve {full}")
                continue

            # Drop patches for releases OSV already covers. map_parsed would
            # otherwise call fixdater.best() per released patch — wasted work
            # for jammy/noble/etc. that we'd filter out post-mapping.
            if apply_osv_coverage_filter:
                cve_file.patches = [
                    p
                    for p in cve_file.patches
                    if (ns := parser_legacy.map_namespace(p.distro)) is not None and not self._osv_covers_legacy_namespace(ns)
                ]
            if not cve_file.patches:
                continue

            vulns = parser_legacy.map_parsed(cve_file, self.fixdater, self.logger)
            for vuln in vulns:
                if not vuln.NamespaceName or not vuln.Name:
                    continue
                identifier = f"{vuln.NamespaceName}/{vuln.Name.lower()}"
                yield identifier, os_schema, {"Vulnerability": vuln.json()}

    def _clean_input(self):
        # The ubuntu-cve-tracker repo is no longer used and is huge, so delete if it exists
        # to significantly reduce cache.
        cve_tracker_path = os.path.join(self.workspace.input_path, "ubuntu-cve-tracker")
        if os.path.exists(cve_tracker_path):
            silent_remove(cve_tracker_path, tree=True)

    def get(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        self._clean_input()
        self._download_archive()
        self._download_vex_archive()
        self.fixdater.download()
        vex_overlay = self._load_vex_overlay()
        self._usn_overlay = self._load_usn_overlay()
        self._write_fragments(vex_overlay=vex_overlay)
        # Measure OSV coverage on every run, in both lanes, for its operator logging:
        # "ubuntu 25.04 has 3 live records -> uncovered" plus the WARNING for a
        # present-but-degenerate fragment. In the merged lane this is an alarm only —
        # suppression now happens per source package inside _iter_merged_os_records —
        # but it is still the signal that a release has quietly fallen out of OSV.
        self._osv_covered_versions()
        if self.downconvert_osv_to_os:
            # Both sources emit the same identifier shape here, so they cannot simply be
            # concatenated: the second one to yield an identifier silently replaces the
            # first. They are merged per source package instead.
            yield from self._iter_merged_os_records()
        else:
            # legacy first; OSV last (policy-only — identifier shapes don't collide:
            # `ubuntu:24.04/cve-...` vs `ubuntu-24.04-lts/ubuntu-cve-...`), so the
            # release-level coverage gate still decides what legacy emits.
            yield from self._iter_normalized_cve_data()
            yield from self._iter_fragments()

    def _iter_merged_os_records(self) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Yield OS-schema records from OSV and legacy, merged per source package.

        Both sources emit the same identifier shape (`{namespace}/{cve}`) and the
        same `{"Vulnerability": {...}}` payload, and the result writer stores them
        with INSERT OR REPLACE. So whichever source is yielded LAST for a given
        (namespace, CVE) wholesale replaces the other — including `FixedIn` entries
        for source packages the winner says nothing about. Measured on noble: 2,381
        legacy rows carrying a real fix version (1,991 of them `linux-raspi-realtime`,
        a genuine OSV coverage gap) were destroyed that way, purely because OSV
        happened to have a record for the same CVE covering other packages.

        This replaces the old release-level gate (`_osv_covers_legacy_namespace`)
        with a per-package merge: OSV wins for every source package it covers, and
        legacy fills in only the packages OSV left out. Two coverage decisions can't
        be made at release granularity, so they aren't:

          - a CVE OSV has a record for, but only for some of its packages
            -> emit the OSV record with legacy's extra packages appended
          - a CVE OSV has no live record for at all
            -> emit legacy's record verbatim (the "leftovers" pass)

        The exception is a WITHDRAWN OSV record. A withdrawal is Canonical
        retracting the advisory, which is a real statement about the CVE, so it
        vetoes legacy's record for that (namespace, CVE) instead of falling through
        to it. `osv_to_os` also returns None for records with no upstream CVE and
        for records whose affected[] map to no namespace we emit — neither is a
        retraction, so neither vetoes anything.

        Legacy is materialized to a throwaway SQLite database first rather than held
        in memory: it is ~70,000 CVE files fanning out to hundreds of thousands of
        records, and only the ones OSV doesn't consume are ever needed. The temp
        directory is outside `workspace.input_path` on purpose — that directory is
        load-bearing provider state — and is removed on the way out, exception or not.
        """
        tempdir = tempfile.mkdtemp(prefix="vunnel-ubuntu-legacy-")
        try:
            legacy_db_path = os.path.join(tempdir, "legacy.db")
            self._materialize_legacy_records(legacy_db_path)
            with ExitStack() as stack:
                reader: result.SQLiteReader | None = None
                if os.path.isfile(legacy_db_path):
                    reader = stack.enter_context(result.SQLiteReader(legacy_db_path))
                else:
                    # Writer.close() only moves the database into place if something was
                    # written, so an absent file means legacy produced nothing at all.
                    self.logger.warning("no legacy records materialized; emitting OSV records only")
                yield from self._iter_osv_merged_with_legacy(reader)
        finally:
            shutil.rmtree(tempdir, ignore_errors=True)

    def _materialize_legacy_records(self, db_path: str) -> None:
        """Write every legacy record (unfiltered by OSV coverage) to a SQLite database.

        Uses the same result.Writer machinery the provider writes its real results
        with, so the on-disk envelope shape is exactly what `SQLiteReader` expects.
        """
        self.logger.info("materializing legacy normalized-cve-data records for merge")
        with result.Writer(
            workspace=self.workspace,
            result_state_policy=result.ResultStatePolicy.DELETE_BEFORE_WRITE,
            store_strategy=result.StoreStrategy.SQLITE,
            write_location=db_path,
            logger=self.logger,
        ) as writer:
            for identifier, record_schema, payload in self._iter_normalized_cve_data(apply_osv_coverage_filter=False):
                writer.write(identifier=identifier, schema=record_schema, payload=payload)

    def _iter_osv_merged_with_legacy(
        self,
        reader: result.SQLiteReader | None,
    ) -> Iterator[tuple[str, schema.Schema, dict[str, Any]]]:
        """Stream OSV records (merging legacy packages in), then the legacy leftovers.

        OSV must go first so that `consumed` is complete by the time the leftovers
        pass runs — that set is the only thing keeping an identifier from being
        emitted twice.
        """
        os_schema = schema.OSSchema()
        consumed: set[str] = set()
        withdrawn_veto: set[str] = set()
        osv_emitted = 0
        records_merged = 0
        entries_merged = 0

        for _osv_identifier, _osv_schema, osv_payload in self._iter_fragments():
            os_payload = osv_to_os(osv_payload, include_esm=self.downconvert_emit_esm)
            if os_payload is None:
                if osv_payload.get("withdrawn"):
                    veto = self._withdrawn_veto_identifier(osv_payload)
                    if veto is not None:
                        withdrawn_veto.add(veto)
                continue

            identifier = os_identifier_for(os_payload)
            legacy_envelope = reader.read(identifier) if reader is not None else None
            if legacy_envelope is not None:
                before = len(_os_fixed_in(os_payload))
                self._merge_legacy_fixed_in(os_payload, legacy_envelope)
                added = len(_os_fixed_in(os_payload)) - before
                if added > 0:
                    records_merged += 1
                    entries_merged += added

            consumed.add(identifier)
            osv_emitted += 1
            yield identifier, os_schema, os_payload

        leftovers = 0
        if reader is not None:
            for envelope in reader.each():
                if envelope.identifier in consumed or envelope.identifier in withdrawn_veto:
                    continue
                leftovers += 1
                yield envelope.identifier, os_schema, envelope.item

        self.logger.info(
            f"merged os records: {osv_emitted} from osv "
            f"({records_merged} with legacy packages merged in, {entries_merged} legacy fixed-in entries merged), "
            f"{leftovers} legacy-only records, {len(withdrawn_veto)} legacy records vetoed by withdrawn osv records",
        )

    def _withdrawn_veto_identifier(self, osv_payload: dict[str, Any]) -> str | None:
        """Build the OS identifier a withdrawn OSV record vetoes, or None if it names none.

        `osv_to_os` returns None for a withdrawn record before it computes anything,
        so the identifier has to be derived from the OSV payload directly. The
        ecosystem is taken from the first affected[] entry — by the slicing invariant
        every entry in an envelope shares one ecosystem.
        """
        affected = osv_payload.get("affected") or []
        if not affected:
            return None
        ecosystem = (affected[0].get("package") or {}).get("ecosystem") or ""
        namespace = osv_ecosystem_to_os_namespace(ecosystem, include_esm=self.downconvert_emit_esm)
        if not namespace:
            return None
        upstream = osv_payload.get("upstream") or []
        if not upstream or not upstream[0]:
            return None
        return f"{namespace}/{upstream[0].lower()}"

    @staticmethod
    def _merge_legacy_fixed_in(os_payload: dict[str, Any], legacy_envelope: dict[str, Any]) -> None:
        """Append legacy FixedIn entries for source packages OSV doesn't cover, in place.

        OSV always wins for a package it has an entry for — its data is newer, carries
        VEX won't-fix disposition and USN fix dates, and is what the whole downconvert
        lane exists to deliver. Legacy is only consulted for packages OSV is silent
        about (e.g. `linux-raspi-realtime` on noble). Nothing else on the OSV record is
        touched: Name, NamespaceName, Severity, Link, Metadata all stay as OSV made them.

        Every legacy package OSV is silent about is merged, whatever its disposition —
        including `Version: "0"` not-affected entries, which dominate by volume (on a
        real run, ~85% of merged entries are not-affected, ~14% are `Version: "None"`
        disclosures, and well under 1% carry a real fix version). That ratio looks like
        noise and is not: a not-affected entry is positive evidence that the package is
        NOT vulnerable, which downstream consumers use to suppress a false positive
        raised by another matcher against the same deb (a CPE match, say). Filtering the
        merge down to entries that can match on their own would silently re-open those
        false positives. See the "not affected" note in parser_legacy.map_parsed.

        `legacy_envelope` is the raw envelope dict read back out of the temp database
        (`{"schema": ..., "identifier": ..., "item": ...}`), so the payload lives under
        "item". Every shape read out of it is checked, because a malformed legacy record
        must degrade to "no merge" rather than take down the whole run.
        """
        osv_vuln = os_payload.get("Vulnerability")
        if not isinstance(osv_vuln, dict):
            return

        osv_fixed_in = osv_vuln.get("FixedIn")
        if osv_fixed_in is None:
            osv_fixed_in = []
            osv_vuln["FixedIn"] = osv_fixed_in
        if not isinstance(osv_fixed_in, list):
            return

        legacy_item = legacy_envelope.get("item") if isinstance(legacy_envelope, dict) else None
        legacy_vuln = legacy_item.get("Vulnerability") if isinstance(legacy_item, dict) else None
        legacy_fixed_in = legacy_vuln.get("FixedIn") if isinstance(legacy_vuln, dict) else None
        if not isinstance(legacy_fixed_in, list):
            return

        osv_packages = {entry.get("Name") for entry in osv_fixed_in if isinstance(entry, dict)}
        namespace = osv_vuln.get("NamespaceName")

        additions: list[dict[str, Any]] = []
        for entry in legacy_fixed_in:
            if not isinstance(entry, dict):
                continue
            name = entry.get("Name")
            if not name or name in osv_packages:
                continue
            merged = dict(entry)
            # The identifier matched, so the namespaces already agree — but the OSV
            # record is the one being emitted, so its namespace is authoritative.
            merged["NamespaceName"] = namespace
            additions.append(merged)

        osv_fixed_in.extend(additions)

    def _load_usn_overlay(self) -> USNFixDateOverlay | None:
        """Build the (eco, src-pkg, fixed-ver) → USN-published-date index.

        Streams `osv/usn/**` out of the downloaded OSV tarball. If the archive
        is missing or unreadable, log and proceed without an overlay — fix-date
        annotations fall back to first-observed + CVE.published, same as before
        the USN overlay was added. No regression on miss.
        """
        if not os.path.isfile(self.archive_path):
            self.logger.warning(
                f"OSV archive missing at {self.archive_path}; USN fix-date overlay unavailable, fix dates will fall back to first-observed",
            )
            return None
        try:
            return USNFixDateOverlay.from_archive(self.archive_path, logger=self.logger)
        except Exception:
            self.logger.exception("failed to build USN fix-date overlay; falling back to first-observed")
            return None

    def _load_vex_overlay(self) -> VEXOverlay | None:
        """Build the won't-fix overlay from the downloaded VEX archive.

        If the archive is missing or unreadable, log a warning and proceed
        without an overlay — the fragments still get written with full OSV
        data, just without won't-fix annotations on this run. Frozen
        fragments from prior runs retain whatever they were written with.
        """
        if not os.path.isfile(self.vex_archive_path):
            self.logger.warning(
                f"VEX archive missing at {self.vex_archive_path}; won't-fix annotations will be absent on this run",
            )
            return None
        try:
            return VEXOverlay.from_archive(self.vex_archive_path, logger=self.logger)
        except Exception:
            self.logger.exception("failed to build VEX overlay; won't-fix annotations will be absent on this run")
            return None
