"""
Sandbox Browser Worker
Executes isolated, disposable web inspections under strict network and resource limits.
Never submits forms, enters credentials, or executes downloaded files.
Applies environment variable scrubbing, disposable profiles, and subresource SSRF interception.
"""
from typing import Dict, Any, List, Optional
import httpx
import re
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlsplit

from sandbox.target_validator import TargetValidator
from sandbox.redirect_validator import RedirectValidator
from sandbox.resource_limits import ResourceLimits
from sandbox.isolation import EnvironmentScrubber, EphemeralProfileManager, SubresourceInterceptor
from risk_engine.exceptions import TargetProhibitedException, EngineTimeoutException

logger = logging.getLogger("thelix.sandbox_worker")

# Check for Playwright availability
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class BrowserWorker:
    """
    Executes isolated website inspection with per-hop redirect and SSRF validation.
    Provides dual-engine execution: Playwright Chromium (when available) with subresource interception,
    falling back to hardened HTTP client inspection.
    """

    def __init__(self, limits: Optional[ResourceLimits] = None, use_playwright: bool = False):
        self.limits = limits or ResourceLimits()
        self.use_playwright = use_playwright and PLAYWRIGHT_AVAILABLE

    async def inspect(self, url: str) -> Dict[str, Any]:
        """
        Safely inspects a website, following validated redirects up to resource limits.
        """
        # 1. Pre-flight Target Validation
        is_valid, reason, resolved_ips = TargetValidator.validate_target(url)
        if not is_valid:
            raise TargetProhibitedException(
                f"Inspection blocked by security policy: {reason}",
                details={"target_url": url, "resolved_ips": resolved_ips}
            )

        if self.use_playwright:
            try:
                return await self._inspect_with_playwright(url)
            except Exception as e:
                logger.warning(f"Playwright dynamic inspection failed ({e}), falling back to static HTTP: {e}")

        return await self._inspect_with_http(url)

    async def _inspect_with_http(self, url: str) -> Dict[str, Any]:
        """
        Hardened static HTTP inspection with manual hop-by-hop redirect validation
        and DOM analysis without script execution.
        """
        current_url = url
        redirect_chain: List[str] = [url]
        headers: Dict[str, str] = {}
        status_code = 0
        html_content = ""
        blocked_subresources: List[Dict[str, str]] = []

        timeout = httpx.Timeout(self.limits.timeout_seconds)

        async with httpx.AsyncClient(
            headers={"User-Agent": self.limits.user_agent},
            timeout=timeout,
            follow_redirects=False,  # We validate every redirect hop manually!
        ) as client:
            for hop in range(self.limits.max_redirect_hops + 1):
                try:
                    resp = await client.get(current_url)
                except httpx.TimeoutException:
                    raise EngineTimeoutException(
                        f"Inspection timed out after {self.limits.timeout_seconds}s",
                        engine_name="sandbox_worker",
                        timeout_seconds=self.limits.timeout_seconds,
                    )
                except Exception as e:
                    logger.warning(f"Failed to fetch {current_url}: {e}")
                    break

                status_code = resp.status_code
                headers = dict(resp.headers)

                # Check if response is a redirect (301, 302, 303, 307, 308)
                if resp.is_redirect and "location" in resp.headers:
                    next_loc = resp.headers["location"]
                    is_allowed, resolved_next, err = RedirectValidator.validate_redirect(
                        current_url=current_url,
                        redirect_target=next_loc,
                        hop_count=len(redirect_chain),
                    )
                    if not is_allowed:
                        raise TargetProhibitedException(
                            f"Redirect destination prohibited: {err}",
                            details={"redirect_source": current_url, "redirect_target": next_loc}
                        )

                    current_url = resolved_next
                    redirect_chain.append(current_url)
                    continue
                else:
                    # Final destination reached, extract up to max body limit
                    content_bytes = resp.content[: self.limits.max_body_bytes]
                    html_content = content_bytes.decode("utf-8", errors="replace")
                    break

        # Parse DOM metadata safely with BeautifulSoup
        dom_meta = self._parse_dom(html_content, current_url)

        # Inspect static subresources for SSRF attempts
        for sub_url in dom_meta.get("subresource_urls", []):
            allowed, denial_reason = SubresourceInterceptor.validate_subresource(sub_url)
            if not allowed:
                blocked_subresources.append({"url": sub_url, "reason": denial_reason})

        return {
            "initial_url": url,
            "final_url": current_url,
            "status_code": status_code,
            "redirect_chain": redirect_chain,
            "headers": headers,
            "body_bytes_read": len(content_bytes),
            "page_title": dom_meta.get("title", ""),
            "forms": dom_meta.get("forms", []),
            "meta_tags": dom_meta.get("meta_tags", {}),
            "scripts_count": dom_meta.get("scripts_count", 0),
            "blocked_subresources": blocked_subresources,
            "engine": "hardened_http",
        }

    async def _inspect_with_playwright(self, url: str) -> Dict[str, Any]:
        """
        Hardened headless Chromium inspection with request routing SSRF interception,
        environment scrubbing, disposable profile directory, and download blocking.
        """
        scrubbed_env = EnvironmentScrubber.get_scrubbed_env()
        redirect_chain: List[str] = [url]
        blocked_subresources: List[Dict[str, str]] = []
        network_request_count = 0
        final_url = url
        status_code = 0
        page_title = ""
        html_content = ""

        with EphemeralProfileManager() as profile_dir:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    env=scrubbed_env,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--disable-extensions",
                    ],
                )

                try:
                    context = await browser.new_context(
                        user_agent=self.limits.user_agent,
                        viewport={"width": self.limits.viewport_width, "height": self.limits.viewport_height},
                        accept_downloads=False,  # Block all downloaded files
                        ignore_https_errors=False,
                        permissions=[],  # Deny all camera, mic, geolocation permissions
                    )

                    page = await context.new_page()
                    page.set_default_navigation_timeout(int(self.limits.timeout_seconds * 1000))

                    # Intercept ALL subresource requests to enforce SSRF network policy
                    async def handle_route(route):
                        nonlocal network_request_count
                        req_url = route.request.url

                        network_request_count += 1
                        if network_request_count > self.limits.max_network_requests:
                            logger.warning(f"Exceeded max network requests limit ({self.limits.max_network_requests})")
                            await route.abort("blockedbyclient")
                            return

                        # Validate subresource URL
                        allowed, denial_reason = SubresourceInterceptor.validate_subresource(req_url)
                        if not allowed:
                            logger.warning(f"Blocked SSRF subresource request: {req_url} ({denial_reason})")
                            blocked_subresources.append({"url": req_url, "reason": denial_reason})
                            await route.abort("blockedbyclient")
                            return

                        await route.continue_()

                    await page.route("**/*", handle_route)

                    # Track navigation redirects
                    page.on("framenavigated", lambda frame: redirect_chain.append(frame.url) if frame == page.main_frame and frame.url not in redirect_chain else None)

                    # Navigate to target
                    response = await page.goto(url, wait_until="domcontentloaded")
                    if response:
                        status_code = response.status
                        final_url = page.url

                    page_title = await page.title()
                    html_content = await page.content()

                finally:
                    await browser.close()

        dom_meta = self._parse_dom(html_content, final_url)

        return {
            "initial_url": url,
            "final_url": final_url,
            "status_code": status_code,
            "redirect_chain": redirect_chain,
            "headers": {},
            "body_bytes_read": len(html_content.encode("utf-8")),
            "page_title": page_title or dom_meta.get("title", ""),
            "forms": dom_meta.get("forms", []),
            "meta_tags": dom_meta.get("meta_tags", {}),
            "scripts_count": dom_meta.get("scripts_count", 0),
            "blocked_subresources": blocked_subresources,
            "engine": "hardened_playwright",
        }

    def _parse_dom(self, html: str, base_url: str) -> Dict[str, Any]:
        """Extracts structural indicators from HTML without executing scripts."""
        if not html:
            return {"title": "", "forms": [], "meta_tags": {}, "scripts_count": 0, "subresource_urls": []}

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {"title": "", "forms": [], "meta_tags": {}, "scripts_count": 0, "subresource_urls": []}

        title = soup.title.string.strip() if soup.title and soup.title.string else ""

        forms_data = []
        for form in soup.find_all("form"):
            has_password = bool(form.find("input", {"type": re.compile(r"^password$", re.I)}))
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            forms_data.append({
                "action": action,
                "method": method,
                "has_password": has_password,
            })

        meta_tags = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property")
            content = meta.get("content")
            if name and content:
                meta_tags[name.lower()] = content[:200]

        scripts = soup.find_all("script")
        scripts_count = len(scripts)

        # Collect embedded subresource URLs for static SSRF checks
        subresource_urls = []
        for tag, attr in [("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")]:
            for el in soup.find_all(tag):
                src = el.get(attr)
                if src and (src.startswith("http://") or src.startswith("https://")):
                    subresource_urls.append(src)

        return {
            "title": title[:200],
            "forms": forms_data,
            "meta_tags": meta_tags,
            "scripts_count": scripts_count,
            "subresource_urls": subresource_urls,
        }
