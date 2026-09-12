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
import time
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

from http_client import HttpClient, PageResult, normalise_url, is_same_origin

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
MAX_CLAIM_VERIFICATION_URLS: int = int(
    _ENT.get("max_claim_verification_urls", _ENT.get("corroboration_max_queries", 3))
)
MAX_NAME_VARIANTS: int = int(_ENT.get("brand_name_max_variations", 2))
ADDR_SIM_THRESH: float = float(_ENT.get("address_similarity_threshold", 0.85))
PHONE_RE_PATTERN: str = _ENT.get(
    "phone_normalization_pattern",
    r"^\+?[0-9\s\-\(\)]{7,20}$",
)

_PHONE_EXTRACT = re.compile(
    r"(?:\+?\d{1,3}[\s\-\.]?)?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}"
)
# Layered address extractors
# 1. Commonwealth / US / India Street-First pattern (number/unit, road name, suffix, optional locality/code)
_ADDR_STREET_FIRST = re.compile(
    r"\b(?:\d{1,5}[A-Za-z0-9\/\-]*|\b(?:Plot|Unit|Block|Flat|Shop|No\.?)\s+\d{1,5})[,\s]+"
    r"[\w\s\.\-]{2,40}\b"
    r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Suite|Ste|"
    r"Close|Gardens|Square|Park|Walk|Place|Pl|Crescent|Sector|Marg|Nagar|Colony|Enclave|Bhavan)\b"
    r"(?:[,\s]+[\w\s,\.\#\-]{2,80})?",
    re.IGNORECASE,
)

# 2. European Street-Name-First pattern (e.g. Speicherstrasse 55, 60327 Frankfurt am Main)
_ADDR_EU = re.compile(
    r"\b(?:[A-Z][\w\s\.\-äöüßéèêàáíóú]{3,40}\s+\d{1,4}[A-Za-z]?)[,\s]+"
    r"(?:[A-Z]{1,2}[-\s])?\d{4,5}\s+[A-Z][\w\s\.\-äöüßéèêàáíóú]{2,30}"
    r"(?:[,\s]+[A-Z][\w\s]{2,30})?\b",
    re.UNICODE,
)

# 3. UK Postcode address pattern (e.g. 10 Downing Street, London SW1A 2AA)
_ADDR_UK_POSTCODE = re.compile(
    r"\b\d{1,5}\s+[\w\s,\.\-]{3,60}[,\s]+[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b"
    r"(?:[,\s]+(?:United Kingdom|UK|England|Scotland|Wales))?",
    re.IGNORECASE,
)

# Backwards-compatibility alias
_ADDRESS_EXTRACT = _ADDR_STREET_FIRST

# Known authoritative sameAs domains
_AUTHORITATIVE_DOMAINS = {
    "wikipedia.org", "wikidata.org", "linkedin.com", "crunchbase.com",
    "facebook.com", "twitter.com", "x.com", "instagram.com", "youtube.com",
    "github.com", "bloomberg.com", "bbb.org", "yelp.com",
    "google.com",  # Google Knowledge Panel
}

# Authority / certification / partnership claim detection heuristics
_CLAIM_RE = re.compile(
    r"\b(?:"
    r"(?:certified|accredited|endorsed|approved|recognized|licensed|verified)\s+by|"
    r"(?:official|authorized|certified|accredited|premier|gold|platinum|strategic)\s+(?:partner|reseller|distributor|member)|"
    r"(?:partnered\s+with|in\s+partnership\s+with|partnership\s+with)|"
    r"(?:member\s+of|membership\s+in|accredited\s+member)|"
    r"(?:iso\s*\d+|soc[\s-]?\d+|hipaa|pci[\s-]dss|gdpr)\s+(?:certified|compliant|accredited)|"
    r"(?:we\s+are|is|our\s+company\s+is)\s+(?:an?\s+)?(?:officially\s+)?(?:certified|accredited|endorsed|approved|recognized|licensed|verified)"
    r")\b",
    re.IGNORECASE,
)

# Ordinary non-authority usages that should NOT trigger claim checks
_FP_RE = re.compile(
    r"\b(?:"
    r"partner\s+with\s+us|become\s+a\s+partner|partner\s+portal|partner\s+login|"
    r"partner\s+program|channel\s+partner\s+program|"
    r"certification\s+(?:course|exam|training|program|class)|"
    r"professional\s+certification\s+training|"
    r"(?:get|earn)\s+(?:your\s+)?certified|"
    r"become\s+a\s+member|member\s+(?:login|portal|area|sign\s*in)"
    r")\b",
    re.IGNORECASE,
)


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
    source: str = "static",
) -> dict:
    d = {
        "local_id": local_id,
        "title": title,
        "severity": severity,
        "category": "discoverability",
        "evidence": evidence,
        "suggested_action": {"summary": action, "priority": severity},
        "related_to": related or [],
        "source": source,
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


def _format_postal_address(addr: Any) -> str:
    """Format a Schema.org PostalAddress dictionary or string into a canonical string."""
    if isinstance(addr, str):
        return addr.strip()
    if not isinstance(addr, dict):
        return ""
    street = addr.get("streetAddress", "")
    locality = addr.get("addressLocality", "")
    region = addr.get("addressRegion", "")
    postal_code = addr.get("postalCode", "")
    country = addr.get("addressCountry", "")
    if isinstance(country, dict):
        country = country.get("name", "")
    parts = [str(p).strip() for p in [street, locality, region, postal_code, country] if p and str(p).strip()]
    return ", ".join(parts)


def _is_kg_entity_link(url: str) -> bool:
    """Check whether a URL points to an authoritative knowledge-graph node
    capable of uniquely disambiguating an entity (Wikidata, Wikipedia, Crunchbase)."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        # Wikidata entity: e.g. wikidata.org/wiki/Q... or /entity/Q...
        if "wikidata.org" in host and ("/wiki/q" in path or "/entity/q" in path):
            return True
        # Wikipedia article: e.g. en.wikipedia.org/wiki/...
        if "wikipedia.org" in host and "/wiki/" in path:
            return True
        # Crunchbase organization node: crunchbase.com/organization/...
        if "crunchbase.com" in host and "/organization/" in path:
            return True
    except Exception:
        pass
    return False


def _has_disambiguating_evidence(block: dict, primary_name: str) -> bool:
    """Determine whether an Organization block provides sufficient structural
    evidence to resolve entity ambiguity.

    Evidence sources:
    1. Knowledge graph identity linkage: sameAs link to Wikidata, Wikipedia, or Crunchbase
    2. Explicit Schema.org disambiguatingDescription
    3. Distinct legalName that specifies legal corporate identity
    4. Physical grounding: structured or non-empty PostalAddress/address
    5. Temporal grounding: foundingDate
    6. Formal corporate identity: taxID, vatID, leiCode, duns, or iso6523Code
    7. Substantive contextual description: description (>= 30 chars) or knowsAbout
    """
    if not isinstance(block, dict):
        return False

    # 1. Knowledge Graph Linkage
    sameas = block.get("sameAs", [])
    if isinstance(sameas, str):
        sameas = [sameas]
    if isinstance(sameas, list):
        if any(_is_kg_entity_link(sa) for sa in sameas):
            return True

    # 2. Schema.org disambiguatingDescription
    disambig_desc = block.get("disambiguatingDescription")
    if disambig_desc and isinstance(disambig_desc, str) and len(disambig_desc.strip()) > 5:
        return True

    # 3. Distinct legalName
    legal_name = block.get("legalName")
    if legal_name and isinstance(legal_name, str) and len(legal_name.strip()) > 2:
        if legal_name.strip().lower() != primary_name.lower():
            return True

    # 4. Physical grounding: address
    addr = block.get("address")
    if isinstance(addr, dict):
        if any(addr.get(k) for k in ("streetAddress", "addressLocality", "postalCode", "addressCountry", "addressRegion")):
            return True
    elif isinstance(addr, str) and len(addr.strip()) > 5:
        return True

    # 5. Temporal grounding: foundingDate
    founding = block.get("foundingDate")
    if founding and str(founding).strip():
        return True

    # 6. Corporate registry identifiers
    for reg_id in ("taxID", "vatID", "leiCode", "duns", "iso6523Code"):
        val = block.get(reg_id)
        if val and str(val).strip():
            return True

    # 7. Substantive topical/domain description
    desc = block.get("description")
    if desc and isinstance(desc, str) and len(desc.strip()) >= 30:
        return True
    if block.get("knowsAbout"):
        return True

    return False


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
                types = _get_types(block)
                if _is_org_type(types):
                    name = block.get("name", "")
                    if name and isinstance(name, str):
                        names.append((name.strip(), url))

                    addr = block.get("address", {})
                    addr_str = _format_postal_address(addr)
                    if len(addr_str) > 5:
                        addresses.append((addr_str, url))

                    phone = block.get("telephone", "")
                    if phone and isinstance(phone, str):
                        phones.append((phone.strip(), url))
                elif any(t.lower() == "postaladdress" for t in types):
                    addr_str = _format_postal_address(block)
                    if len(addr_str) > 5:
                        addresses.append((addr_str, url))

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

            # Addresses from text: layered extraction across international patterns
            found_addrs: list[str] = []
            for pat in (_ADDR_STREET_FIRST, _ADDR_EU, _ADDR_UK_POSTCODE):
                for match in pat.finditer(text):
                    candidate = match.group(0).strip().strip(".,")
                    if len(candidate) >= 10 and not any(candidate in a for a in found_addrs):
                        found_addrs.append(candidate)

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


def _extract_authority_claims(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """Search crawled page content for structural evidence of authority,
    accreditation, certification, or partnership claims and their associated
    outbound verification links.
    """
    claims: list[dict] = []
    seen_snippets: set[tuple[str, str]] = set()

    for url in frontier:
        pr = page_results.get(url)
        if not pr or not pr.soup:
            continue
        page_url = pr.url or url

        for el in pr.soup.find_all(
            ["p", "li", "h1", "h2", "h3", "h4", "h5", "h6", "div", "span", "a", "blockquote", "figcaption", "td"]
        ):
            # Skip broad container elements if they contain child paragraphs or blocks
            if el.name in ("div", "section", "article", "main", "footer", "header", "td"):
                if el.find(["p", "li", "h1", "h2", "h3", "h4", "h5", "h6", "div", "section", "article"]):
                    continue

            text = el.get_text(" ", strip=True)
            if not text or len(text) > 400:
                continue

            if not _CLAIM_RE.search(text) or _FP_RE.search(text):
                continue

            # Deduplicate similar claim snippets on the same page
            norm_key = (page_url, text[:80].lower())
            if norm_key in seen_snippets:
                continue
            seen_snippets.add(norm_key)

            # Extract associated anchors
            if el.name == "a" and el.get("href"):
                anchors = [el]
            else:
                anchors = el.find_all("a", href=True)
                if not anchors and el.parent and len(el.parent.get_text(strip=True)) < 250:
                    anchors = el.parent.find_all("a", href=True)

            external_urls: list[str] = []
            for a in anchors:
                href = (a.get("href") or "").strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                abs_url = normalise_url(href, page_url)
                if not abs_url:
                    continue
                try:
                    parsed = urllib.parse.urlparse(abs_url)
                    if parsed.scheme in ("http", "https") and not is_same_origin(abs_url, page_url):
                        if abs_url not in external_urls:
                            external_urls.append(abs_url)
                except Exception:
                    continue

            claims.append({
                "text": text[:120],
                "external_links": external_urls,
                "source_url": page_url,
            })

    return claims


def _check_tc003(
    frontier: list[str],
    page_results: dict[str, PageResult],
    http_client: HttpClient,
    t_start: float | None = None,
    timeout_s: float | None = None,
) -> list[dict]:
    """TC-003 (high): Claimed external partner or accreditation links broken.

    Searches page content for structural evidence of accreditation, certification,
    or partnership claims with outbound verification links, and checks them via HEAD
    requests. Fires if the external verification resource returns 4xx/5xx or errors.
    """
    findings: list[dict] = []
    try:
        claims = _extract_authority_claims(frontier, page_results)
        # Only inspect claims that provide external verification links
        linked_claims = [c for c in claims if c["external_links"]]
        if not linked_claims:
            return findings

        # Collect unique verification URLs
        seen_urls: set[str] = set()
        unique_urls: list[tuple[str, str]] = []  # (url, source_page)
        for c in linked_claims:
            for link in c["external_links"]:
                if link not in seen_urls:
                    seen_urls.add(link)
                    unique_urls.append((link, c["source_url"]))

        failed: list[str] = []
        affected_pages: set[str] = set()

        for target_url, src_page in unique_urls[:MAX_CLAIM_VERIFICATION_URLS]:
            if t_start is not None and timeout_s is not None:
                if time.monotonic() - t_start >= timeout_s:
                    break
            try:
                head = http_client.head(target_url)
                is_walled_garden = any(
                    d in target_url.lower()
                    for d in ("linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com")
                )
                if head.status_code and 200 <= head.status_code < 400:
                    continue
                elif is_walled_garden and (head.status_code == 999 or head.status_code in (401, 403)):
                    # Anti-bot response confirms endpoint exists
                    continue
                else:
                    code = head.status_code or "no response"
                    failed.append(f"{target_url} (HTTP {code})")
                    affected_pages.add(src_page)
            except Exception as exc:
                failed.append(f"{target_url} (error: {exc})")
                affected_pages.add(src_page)

        if failed:
            findings.append(_finding(
                "TC-003",
                "Claimed external partner or accreditation links are broken",
                "high",
                f"{len(failed)} outbound verification link(s) for claimed "
                f"credentials returned broken HTTP status: "
                + "; ".join(failed[:5]),
                "Audit and update outbound accreditation and trust verification "
                "links to ensure all targets resolve cleanly.",
                related=[],
                pages_affected=len(affected_pages),
                pages_checked=len(frontier),
            ))
    except Exception as exc:
        logger.debug("TC-003 error: %s", exc)
    return findings


def _check_tc005(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """TC-005 (medium): Authority or partnership claims lack external verification links.

    Fires when authority, certification, or partnership claims are presented on the
    page without any accompanying external outbound verification link.
    """
    findings: list[dict] = []
    try:
        claims = _extract_authority_claims(frontier, page_results)
        # Find claims that have zero outbound verification links
        unlinked = [c for c in claims if not c["external_links"]]
        if not unlinked:
            return findings

        sample_claims = ['"' + c["text"] + '"' for c in unlinked[:3]]
        affected_pages = len(set(c["source_url"] for c in unlinked))

        findings.append(_finding(
            "TC-005",
            "Authority or partnership claims lack external verification links",
            "medium",
            f"Site presents {len(unlinked)} authority or partnership claim(s) "
            f"without verifiable outbound links: " + "; ".join(sample_claims),
            "Add verifiable outbound links to authoritative registries, industry "
            "bodies, or official partner directories so AI engines can corroborate claims.",
            related=[],
            pages_affected=affected_pages,
            pages_checked=len(frontier),
        ))
    except Exception as exc:
        logger.debug("TC-005 error: %s", exc)
    return findings


def _check_tc003_tc005(
    frontier: list[str],
    page_results: dict[str, PageResult],
    http_client: HttpClient,
    t_start: float | None = None,
    timeout_s: float | None = None,
) -> list[dict]:
    """Dispatch to distinct TC-003 and TC-005 claim checks."""
    return _check_tc003(frontier, page_results, http_client, t_start=t_start, timeout_s=timeout_s) + _check_tc005(frontier, page_results)


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

        # TC-004: Brand entity ambiguity detection via structural evidence
        if brand_names:
            primary_name = brand_names[0].strip()

            # Check if disambiguation is present in any Organization block
            has_disambig = any(
                _has_disambiguating_evidence(block, primary_name)
                for block in org_blocks
            )

            if not has_disambig:
                findings.append(_finding(
                    "TC-004",
                    "Brand name is ambiguous without disambiguation",
                    "critical",
                    f"Brand entity '{primary_name}' lacks unique knowledge "
                    "graph linkage (Wikidata/Wikipedia sameAs) and provides "
                    "no structural disambiguation (legalName, disambiguatingDescription, "
                    "address, foundingDate, or description). AI engines cannot "
                    "disambiguate this brand from potential entity collisions.",
                    "Add disambiguating properties to your Organization schema: "
                    "connect to a Wikidata entity in sameAs, specify legalName, "
                    "address, foundingDate, and a detailed description.",
                    related=["TC-006", "TC-001"],
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


def _check_rendered_trust_signals(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """Detect trust and entity corroboration signals appearing post-rendering."""
    findings: list[dict] = []
    rendered_sameas_pages: list[str] = []

    for url in frontier:
        pr = page_results.get(url)
        if pr and pr.rendered_soup:
            static_links = set()
            if pr.soup:
                for a in pr.soup.find_all("a", href=True):
                    static_links.add(a.get("href", ""))
            rendered_links = set()
            for a in pr.rendered_soup.find_all("a", href=True):
                rendered_links.add(a.get("href", ""))

            new_links = rendered_links - static_links
            has_auth = any(
                any(dom in link for dom in _AUTHORITATIVE_DOMAINS)
                for link in new_links
            )
            if has_auth:
                rendered_sameas_pages.append(url)

    if rendered_sameas_pages:
        findings.append(_finding(
            "TC-001",
            "Dynamic sameAs social/entity graph links detected post-rendering",
            "info",
            f"Authoritative entity links appear in post-JS rendered DOM on "
            f"{len(rendered_sameas_pages)} page(s): " + "; ".join(rendered_sameas_pages[:3]) +
            ", but are absent in raw static HTML.",
            "Ensure authoritative entity and social links are present in static HTML "
            "markup to guarantee discovery by non-JS crawlers.",
            pages_affected=len(rendered_sameas_pages),
            pages_checked=len(frontier),
            source="rendered",
        ))
    return findings


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

    t_start: float | None = kwargs.get("t_start")
    timeout_s: float | None = kwargs.get("timeout_s")

    errors: list[str] = []
    findings: list[dict] = []

    findings.extend(_check_tc001(frontier, page_results, http_client))
    findings.extend(_check_tc002(frontier, page_results))
    findings.extend(_check_tc003(frontier, page_results, http_client, t_start=t_start, timeout_s=timeout_s))
    findings.extend(_check_tc005(frontier, page_results))
    findings.extend(_check_tc004_tc006(frontier, page_results))
    findings.extend(_check_rendered_trust_signals(frontier, page_results))

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
