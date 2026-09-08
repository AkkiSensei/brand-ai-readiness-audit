"""
tec_audit.py
============
Domain sub-skill: Trust & Entity Corroboration (TC-001 -> TC-006)

Validates sameAs entity graph linkage, NAP consistency, claim corroboration,
and brand disambiguation across the crawl frontier.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import urllib.parse
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Optional

_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "crawl-render-access"
    / "scripts"
)
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from http_client import HttpClient, PageResult, normalise_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_THRESH_PATH = (
    Path(__file__).resolve().parents[2]
    / "audit-orchestrator"
    / "references"
    / "thresholds.json"
)


def _load_thresholds() -> dict:
    try:
        return json.loads(_THRESH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_T = _load_thresholds()
_ENT = _T.get("entity", {})

NAP_MIN_RATIO: float = float(_ENT.get("nap_consistency_min_ratio", 0.80))
SAMEAS_MIN: int = int(_ENT.get("sameas_min_external_links", 1))
MAX_CORROBORATION_QUERIES: int = int(_ENT.get("corroboration_max_queries", 3))
MAX_NAME_VARIANTS: int = int(_ENT.get("brand_name_max_variations", 2))
ADDR_SIM_THRESH: float = float(_ENT.get("address_similarity_threshold", 0.85))
PHONE_RE_PATTERN: str = _ENT.get(
    "phone_normalization_pattern",
    r"^\+?[0-9\s\-\(\)]{7,20}$",
)

_PHONE_EXTRACT = re.compile(
    r"(?:\+?\d{1,3}[\s\-\.]?)?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}"
)
_ADDRESS_EXTRACT = re.compile(
    r"\d{1,5}\s+[\w\s]{3,40}"
    r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Suite|Ste)"
    r"[\w\s,\.#\-]{0,80}",
    re.IGNORECASE,
)

# Known authoritative sameAs domains
_AUTHORITATIVE_DOMAINS = {
    "wikipedia.org", "wikidata.org", "linkedin.com", "crunchbase.com",
    "facebook.com", "twitter.com", "x.com", "instagram.com", "youtube.com",
    "github.com", "bloomberg.com", "bbb.org", "yelp.com",
    "google.com",  # Google Knowledge Panel
}

# Generic dictionary words that cause brand ambiguity
_GENERIC_WORDS = {
    "apple", "amazon", "shell", "mercury", "oracle", "target", "dove",
    "champion", "delta", "united", "frontier", "prime", "pioneer",
    "summit", "compass", "crown", "liberty", "eagle", "patriot", "horizon",
    "atlas", "genesis", "icon", "spark", "nova", "element", "core",
}


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------
def _finding(
    local_id: str,
    title: str,
    severity: str,
    evidence: str,
    action: str,
    related: list[str] | None = None,
    pages_affected: int | None = None,
    pages_checked: int | None = None,
) -> dict:
    d = {
        "local_id": local_id,
        "title": title,
        "severity": severity,
        "category": "discoverability",
        "evidence": evidence,
        "suggested_action": {"summary": action, "priority": severity},
        "related_to": related or [],
    }
    if pages_affected is not None:
        d["pages_affected"] = pages_affected
    if pages_checked is not None:
        d["pages_checked"] = pages_checked
    return d


# ---------------------------------------------------------------------------
# JSON-LD helpers
# ---------------------------------------------------------------------------
def _extract_jsonld_blocks(soup: Any) -> list[dict]:
    """Extract all JSON-LD blocks from a page."""
    blocks: list[dict] = []
    if soup is None:
        return blocks
    for script in soup.find_all("script", type="application/ld+json"):
        raw = script.string
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        blocks.append(item)
            elif isinstance(data, dict):
                if "@graph" in data:
                    graph = data["@graph"]
                    if isinstance(graph, list):
                        for item in graph:
                            if isinstance(item, dict):
                                blocks.append(item)
                    elif isinstance(graph, dict):
                        blocks.append(graph)
                else:
                    blocks.append(data)
        except (json.JSONDecodeError, TypeError):
            pass
    return blocks


def _get_types(block: Any) -> list[str]:
    if not isinstance(block, dict):
        return []
    t = block.get("@type", "")
    if isinstance(t, list):
        return [str(x).strip() for x in t if x]
    return [str(t).strip()] if t else []


def _is_org_type(types: list[str]) -> bool:
    return any(
        t.lower() in ("organization", "localbusiness", "corporation",
                       "ngo", "governmentorganization", "educationalorganization")
        for t in types
    )


def _normalise_phone(phone: str) -> str:
    """Strip a phone string to digits only for comparison."""
    return re.sub(r"[^\d]", "", phone)


def _similarity(a: str, b: str) -> float:
    """Return SequenceMatcher ratio between two strings."""
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a.lower().strip(), b.lower().strip()).ratio()


# ===================================================================
# CHECK FUNCTIONS
# ===================================================================

def _check_tc001(
    frontier: list[str],
    page_results: dict[str, PageResult],
    http_client: HttpClient,
) -> list[dict]:
    """TC-001 (high): sameAs entity graph linkage validation."""
    findings: list[dict] = []
    try:
        all_sameas: list[str] = []
        has_any_sameas = False

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                types = _get_types(block)
                if not _is_org_type(types):
                    continue
                sameas = block.get("sameAs", [])
                if isinstance(sameas, str):
                    sameas = [sameas]
                if isinstance(sameas, list) and sameas:
                    has_any_sameas = True
                    all_sameas.extend(sameas)

        if not has_any_sameas:
            findings.append(_finding(
                "TC-001",
                "No sameAs links in Organization schema",
                "high",
                "No Organization JSON-LD block contains a sameAs property. "
                "AI engines cannot corroborate your brand identity against "
                "authoritative external profiles.",
                "Add a sameAs array to your Organization JSON-LD with links "
                "to your official Wikipedia page, Wikidata entry, LinkedIn "
                "company page, and verified social media profiles.",
                related=["SF-001"],
            ))
            return findings

        # Validate sameAs URLs
        unique_sameas = list(set(all_sameas))
        invalid_urls: list[str] = []
        non_authoritative: list[str] = []

        for sa_url in unique_sameas:
            # Basic URL validation
            try:
                parsed = urllib.parse.urlparse(sa_url)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    invalid_urls.append(sa_url)
                    continue
            except Exception:
                invalid_urls.append(sa_url)
                continue

            # Check if domain is authoritative
            domain = parsed.hostname.lower()
            is_auth = any(domain == ad or domain.endswith("." + ad) for ad in _AUTHORITATIVE_DOMAINS)
            if not is_auth:
                non_authoritative.append(sa_url)

        if invalid_urls:
            findings.append(_finding(
                "TC-001",
                "Invalid sameAs URLs in Organization schema",
                "medium",
                f"{len(invalid_urls)} sameAs URL(s) are malformed: "
                + "; ".join(invalid_urls[:5]),
                "Fix or remove invalid sameAs URLs. Each must be a valid "
                "HTTP/HTTPS URL pointing to an authoritative profile.",
            ))

        if len(unique_sameas) < SAMEAS_MIN and not invalid_urls:
            findings.append(_finding(
                "TC-001",
                "Insufficient sameAs external links",
                "medium",
                f"Only {len(unique_sameas)} sameAs link(s) found; "
                f"minimum recommended is {SAMEAS_MIN}.",
                "Add more sameAs links to authoritative external profiles "
                "(Wikipedia, Wikidata, LinkedIn, Crunchbase) to strengthen "
                "entity corroboration.",
            ))

    except Exception as exc:
        logger.debug("TC-001 error: %s", exc)
    return findings


def _check_tc002(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """TC-002 (medium): NAP consistency across pages."""
    findings: list[dict] = []
    try:
        names: list[tuple[str, str]] = []   # (name, source_url)
        addresses: list[tuple[str, str]] = []
        phones: list[tuple[str, str]] = []

        # Priority pages: homepage and /contact
        priority_urls = []
        for url in frontier:
            lower = url.lower()
            if any(seg in lower for seg in ("/contact", "/about", "/location")):
                priority_urls.append(url)
        if frontier:
            priority_urls.insert(0, frontier[0])

        # Extract NAP from JSON-LD
        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                if not _is_org_type(_get_types(block)):
                    continue
                name = block.get("name", "")
                if name and isinstance(name, str):
                    names.append((name.strip(), url))

                addr = block.get("address", {})
                if isinstance(addr, dict):
                    street = addr.get("streetAddress", "")
                    locality = addr.get("addressLocality", "")
                    region = addr.get("addressRegion", "")
                    addr_str = f"{street}, {locality}, {region}".strip(", ")
                    if len(addr_str) > 5:
                        addresses.append((addr_str, url))
                elif isinstance(addr, str) and len(addr) > 5:
                    addresses.append((addr, url))

                phone = block.get("telephone", "")
                if phone and isinstance(phone, str):
                    phones.append((phone.strip(), url))

        # Extract NAP from visible text (priority pages only)
        for url in priority_urls[:5]:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            text = pr.soup.get_text(separator=" ", strip=True)

            # Phones from text
            found_phones = _PHONE_EXTRACT.findall(text)
            for p in found_phones[:3]:
                if len(_normalise_phone(p)) >= 7:
                    phones.append((p.strip(), url))

            # Addresses from text
            found_addrs = _ADDRESS_EXTRACT.findall(text)
            for a in found_addrs[:3]:
                addresses.append((a.strip(), url))

        # Evaluate consistency
        # Names
        if len(names) >= 2:
            name_values = [n[0] for n in names]
            unique_names = set(n.lower().strip() for n in name_values)
            if len(unique_names) > MAX_NAME_VARIANTS:
                findings.append(_finding(
                    "TC-002",
                    "Inconsistent brand name across pages",
                    "high",
                    f"Brand name appears as {len(unique_names)} distinct "
                    f"variants: {', '.join(sorted(unique_names)[:5])}",
                    "Standardise the brand name across all pages and JSON-LD. "
                    "Use alternateName for legitimate variations.",
                    related=["TC-004"],
                ))

        # Phones
        if len(phones) >= 2:
            norm_phones = [_normalise_phone(p[0]) for p in phones]
            unique_phones = set(n for n in norm_phones if n)
            if len(unique_phones) > 1:
                total = len(norm_phones)
                most_common = Counter(norm_phones).most_common(1)[0][1]
                ratio = most_common / total
                if ratio < NAP_MIN_RATIO:
                    findings.append(_finding(
                        "TC-002",
                        "Inconsistent phone numbers across pages",
                        "medium",
                        f"{len(unique_phones)} distinct phone number(s) "
                        f"found with {ratio:.0%} consistency ratio "
                        f"(threshold: {NAP_MIN_RATIO:.0%}).",
                        "Standardise phone number format across all pages. "
                        "Use E.164 format (+1-555-123-4567) in JSON-LD "
                        "contactPoint.telephone.",
                    ))

        # Addresses
        if len(addresses) >= 2:
            addr_values = [a[0] for a in addresses]
            # Pairwise similarity
            mismatches = 0
            comparisons = 0
            for i in range(len(addr_values)):
                for j in range(i + 1, min(i + 5, len(addr_values))):
                    sim = _similarity(addr_values[i], addr_values[j])
                    comparisons += 1
                    if sim < ADDR_SIM_THRESH:
                        mismatches += 1
            if comparisons > 0 and mismatches / comparisons > (1 - NAP_MIN_RATIO):
                findings.append(_finding(
                    "TC-002",
                    "Inconsistent address information across pages",
                    "medium",
                    f"{mismatches}/{comparisons} address comparisons below "
                    f"similarity threshold ({ADDR_SIM_THRESH}).",
                    "Standardise address formatting across all pages and "
                    "JSON-LD. Use PostalAddress structured data with "
                    "consistent field values.",
                ))

    except Exception as exc:
        logger.debug("TC-002 error: %s", exc)
    return findings


def _check_tc003_tc005(
    frontier: list[str],
    page_results: dict[str, PageResult],
    http_client: HttpClient,
) -> list[dict]:
    """TC-003/TC-005 (high): Rate-limited claim corroboration.

    Performs up to 3 HEAD requests to verify third-party presence claims
    (e.g., sameAs URLs) or flag stale claims.
    """
    findings: list[dict] = []
    try:
        # Collect sameAs URLs for corroboration
        sameas_urls: list[str] = []
        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                if _is_org_type(_get_types(block)):
                    sa = block.get("sameAs", [])
                    if isinstance(sa, str):
                        sa = [sa]
                    if isinstance(sa, list):
                        sameas_urls.extend(sa)

        # Deduplicate and take up to 3 for verification
        seen: set[str] = set()
        unique: list[str] = []
        for u in sameas_urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)

        verified = 0
        failed: list[str] = []
        for sa_url in unique[:MAX_CORROBORATION_QUERIES]:
            try:
                head = http_client.head(sa_url)
                is_walled_garden = any(d in sa_url.lower() for d in ("linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com"))
                if head.status_code and 200 <= head.status_code < 400:
                    verified += 1
                elif is_walled_garden and (head.status_code == 999 or head.status_code in (401, 403)):
                    # Anti-bot response confirms the external profile endpoint exists
                    verified += 1
                else:
                    code = head.status_code or "no response"
                    failed.append(f"{sa_url} (HTTP {code})")
            except Exception as exc:
                failed.append(f"{sa_url} (error: {exc})")

        if failed:
            findings.append(_finding(
                "TC-003",
                "Third-party entity claims could not be corroborated",
                "high",
                f"{len(failed)} sameAs/external claim(s) failed verification: "
                + "; ".join(failed),
                "Update or remove broken external profile links. Ensure all "
                "claimed third-party presences (Wikipedia, LinkedIn, etc.) "
                "are active and accessible.",
                related=["TC-001", "TC-005"],
            ))

        # TC-005: Check if any claims reference outdated profiles
        if unique and verified == 0 and not failed:
            findings.append(_finding(
                "TC-005",
                "No external entity claims could be verified",
                "medium",
                "None of the sameAs URLs could be verified via HEAD request.",
                "Verify that external profile URLs are correct and publicly "
                "accessible. Consider adding more authoritative sameAs links.",
                related=["TC-001", "TC-003"],
            ))

    except Exception as exc:
        logger.debug("TC-003/005 error: %s", exc)
    return findings


def _check_tc004_tc006(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """TC-004 (critical): Brand name ambiguity.
    TC-006 (medium): Missing Organization disambiguators."""
    findings: list[dict] = []
    try:
        brand_names: list[str] = []
        org_blocks: list[dict] = []

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                if _is_org_type(_get_types(block)):
                    org_blocks.append(block)
                    name = block.get("name", "")
                    if name and isinstance(name, str):
                        brand_names.append(name.strip())

        # TC-004: Check brand name against generic dictionary words
        if brand_names:
            primary_name = brand_names[0].lower().strip()
            words = set(primary_name.split())
            generic_hits = words & _GENERIC_WORDS

            if generic_hits:
                # Check if disambiguation is present
                has_disambig = False
                for block in org_blocks:
                    if block.get("foundingDate") or block.get("address") or \
                       block.get("knowsAbout") or block.get("description"):
                        has_disambig = True
                        break

                if not has_disambig:
                    findings.append(_finding(
                        "TC-004",
                        "Brand name is ambiguous without disambiguation",
                        "critical",
                        f"Brand name '{brand_names[0]}' contains generic "
                        f"word(s) ({', '.join(generic_hits)}) that collide "
                        "with common dictionary terms. No JSON-LD "
                        "disambiguators (foundingDate, address, knowsAbout, "
                        "description) are present.",
                        "Add disambiguating properties to your Organization "
                        "schema: foundingDate, address, knowsAbout, and a "
                        "detailed description. Consider adding alternateName "
                        "with your legal/full brand name.",
                        related=["TC-006"],
                    ))

        # TC-004: Capitalisation variants
        if len(brand_names) >= 2:
            cap_variants: set[str] = set()
            for n in brand_names:
                cap_variants.add(n)
            if len(cap_variants) > MAX_NAME_VARIANTS:
                findings.append(_finding(
                    "TC-004",
                    "Brand name appears in too many capitalisation variants",
                    "medium",
                    f"{len(cap_variants)} distinct name spellings: "
                    + ", ".join(sorted(cap_variants)[:5]),
                    "Standardise brand name capitalisation across all pages "
                    "and structured data. Use alternateName for legitimate "
                    "abbreviations or translations.",
                    related=["TC-002"],
                ))

        # TC-006: Missing Organization disambiguators
        if org_blocks:
            missing_disambig: list[str] = []
            for block in org_blocks:
                if not block.get("foundingDate"):
                    missing_disambig.append("foundingDate")
                if not block.get("address"):
                    missing_disambig.append("address")
                if not block.get("knowsAbout"):
                    missing_disambig.append("knowsAbout")
                if not block.get("legalName"):
                    missing_disambig.append("legalName")
                break  # Check primary org block only

            if missing_disambig:
                unique_missing = list(dict.fromkeys(missing_disambig))
                findings.append(_finding(
                    "TC-006",
                    "Organization schema missing disambiguation properties",
                    "medium",
                    f"Primary Organization block is missing: "
                    + ", ".join(unique_missing),
                    "Add foundingDate, address, legalName, and knowsAbout "
                    "to your Organization JSON-LD to help AI engines "
                    "distinguish your brand from others with similar names.",
                    related=["TC-004"],
                ))
        else:
            findings.append(_finding(
                "TC-006",
                "No Organization schema found for entity disambiguation",
                "medium",
                "No JSON-LD Organization block was found across the site. "
                "AI engines have no structured disambiguation signals.",
                "Add an Organization JSON-LD block to your homepage with "
                "name, url, foundingDate, address, and description.",
                related=["SF-001"],
            ))

    except Exception as exc:
        logger.debug("TC-004/006 error: %s", exc)
    return findings


# ---------------------------------------------------------------------------
# Proactive recommendations
# ---------------------------------------------------------------------------
def _proactive(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    recs: list[dict] = []
    try:
        # Suggest Wikidata entry if not in sameAs
        has_wikidata = False
        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                sa = block.get("sameAs", [])
                if isinstance(sa, str):
                    sa = [sa]
                if isinstance(sa, list):
                    for s in sa:
                        if "wikidata.org" in str(s):
                            has_wikidata = True

        if not has_wikidata:
            recs.append({
                "title": "Create or link to a Wikidata entity",
                "rationale": "Wikidata is the primary knowledge base for many "
                             "AI systems. A verified Wikidata entry with sameAs "
                             "linking significantly improves entity recognition.",
                "priority": "medium",
            })

        # Suggest contactPoint if not present
        has_contact = False
        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                if _is_org_type(_get_types(block)) and block.get("contactPoint"):
                    has_contact = True

        if not has_contact:
            recs.append({
                "title": "Add contactPoint to Organization schema",
                "rationale": "ContactPoint structured data helps AI engines "
                             "surface your customer service details in responses.",
                "priority": "low",
            })

    except Exception as exc:
        logger.debug("Proactive recs error: %s", exc)
    return recs


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================
def run_audit(target_url: str, http_client: HttpClient, **kwargs: Any) -> dict:
    """Execute Trust & Entity Corroboration checks TC-001 -> TC-006."""
    frontier: list[str] = kwargs.get("crawl_frontier", [target_url])
    page_results: dict[str, PageResult] = kwargs.get("page_results", {})

    if not page_results:
        for url in frontier:
            try:
                pr = http_client.get(url)
                page_results[pr.url or url] = pr
            except Exception as exc:
                page_results[url] = PageResult(url=url, error=str(exc))

    errors: list[str] = []
    findings: list[dict] = []

    findings.extend(_check_tc001(frontier, page_results, http_client))
    findings.extend(_check_tc002(frontier, page_results))
    findings.extend(_check_tc003_tc005(frontier, page_results, http_client))
    findings.extend(_check_tc004_tc006(frontier, page_results))

    proactive = _proactive(frontier, page_results)

    return {
        "domain": "trust-entity-corroboration",
        "pages_analyzed": sum(
            1 for u in frontier if u in page_results and
            page_results[u].status_code and
            200 <= page_results[u].status_code < 400
        ),
        "pages_discovered": len(frontier),
        "errors": errors,
        "findings": findings,
        "proactive_candidates": proactive,
    }
