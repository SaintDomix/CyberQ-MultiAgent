"""Ported from first_branch_v22; see docs/BRANCH1_PIPELINE.md for changes."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import urljoin, urlparse

from .html import Document as BeautifulSoup

from .models import Finding
from .utils import join, trunc


class MoodleRules:
    def __init__(self, client, target):
        self.c = client
        self.target = target

    def _same_origin(self, url):
        a = urlparse(self.target)
        b = urlparse(urljoin(self.target, url))
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)

    def _extract_components(self, soups):
        components = defaultdict(set)

        direct_patterns = [
            ("mod", re.compile(r"/mod/([^/?#]+)/", re.I)),
            ("blocks", re.compile(r"/blocks/([^/?#]+)/", re.I)),
            ("auth", re.compile(r"/auth/([^/?#]+)/", re.I)),
            ("local", re.compile(r"/local/([^/?#]+)/", re.I)),
            ("repository", re.compile(r"/repository/([^/?#]+)/", re.I)),
            ("filter", re.compile(r"/filter/([^/?#]+)/", re.I)),
            ("enrol", re.compile(r"/enrol/([^/?#]+)/", re.I)),
            ("report", re.compile(r"/report/([^/?#]+)/", re.I)),
        ]

        theme_direct = re.compile(r"/theme/([^/?#]+)/", re.I)
        theme_image = re.compile(r"/theme/image\.php/([^/?#]+)/", re.I)
        theme_styles = re.compile(r"/theme/styles\.php/([^/?#]+)/", re.I)

        for soup in soups:
            tags = soup.find_all(src=True) + soup.find_all(href=True)
            for tag in tags:
                value = tag.get("src") or tag.get("href") or ""

                m = theme_image.search(value) or theme_styles.search(value)
                if m:
                    components["theme"].add(m.group(1))
                else:
                    m = theme_direct.search(value)
                    if m and m.group(1).lower() not in {"image.php", "styles.php"}:
                        components["theme"].add(m.group(1))

                for typ, pattern in direct_patterns:
                    m = pattern.search(value)
                    if m:
                        name = m.group(1)
                        if not name.lower().endswith(".php"):
                            components[typ].add(name)

        return {k: sorted(v) for k, v in components.items()}

    def _access_finding(self, fid, rel, name):
        r = self.c.get(join(self.target, rel))
        final = r.url.lower()
        body = r.text[:6000].lower()

        if r.status_code == 404:
            return Finding(
                fid, "Access Control",
                f"Unauthenticated protection: {name}",
                "NOT_APPLICABLE", "INFO", "CONFIRMED", "ACCESS_CONTROL",
                f"status=404; final_url={r.url}",
                f"{name} should not be anonymously accessible if present.",
                r.url,
                "The tested endpoint is not present at this path, so no access-control failure can be inferred.",
                "No action required for this path."
            )

        protected = (
            "login/index.php" in final
            or r.status_code in {401, 403}
            or ("log in" in body and "password" in body)
            or any(marker in body for marker in ("nopermissions", "access denied", "you do not have permission", "not permitted"))
        )

        return Finding(
            fid, "Access Control",
            f"Unauthenticated protection: {name}",
            "PASS" if protected else "PARTIAL",
            "INFO" if protected else "MEDIUM",
            "HEURISTIC", "ACCESS_CONTROL",
            f"status={r.status_code}; final_url={r.url}",
            f"{name} should require authentication/authorization.",
            r.url,
            "Unauthenticated access is redirected/restricted."
            if protected
            else "No obvious barrier observed; content/capability comparison is required before asserting unauthorized access.",
            "Maintain access control."
            if protected
            else "Review endpoint authorization immediately."
        )

    def run(self):
        findings = []

        home = self.c.get(self.target)
        login = self.c.get(join(self.target, "login/index.php"))
        course = self.c.get(join(self.target, "course/"))

        soups = [
            BeautifulSoup(home.text, "html.parser"),
            BeautifulSoup(login.text, "html.parser"),
            BeautifulSoup(course.text, "html.parser"),
        ]
        home_soup, login_soup, course_soup = soups

        combined_text = (
            home.text + "\n" + login.text + "\n" + course.text
        ).lower()

        moodle_detected = (
            "moodle" in combined_text
            or "moodlesession" in str(home.headers).lower()
            or "/lib/ajax/" in combined_text
        )

        findings.append(Finding(
            "MOODLE-001", "Moodle Platform",
            "Moodle fingerprint",
            "PASS" if moodle_detected else "PARTIAL",
            "INFO", "HEURISTIC", "PLATFORM",
            "Moodle markers observed"
            if moodle_detected
            else "No strong Moodle marker observed",
            "Target should be identifiable as the intended Moodle platform.",
            self.target,
            "Moodle-specific markers were observed."
            if moodle_detected
            else "The scanner could not confidently fingerprint Moodle.",
            "No action required."
            if moodle_detected
            else "Confirm target and base path."
        ))

        login_form = login_soup.find(
            "form",
            attrs={"method": re.compile("post", re.I)},
        )
        method_ok = bool(login_form)

        findings.append(Finding(
            "AUTH-001", "Authentication & Session",
            "Login form uses POST",
            "PASS" if method_ok else "FAIL",
            "INFO" if method_ok else "MEDIUM",
            "CONFIRMED", "AUTH",
            "POST login form observed"
            if method_ok
            else "POST login form not observed",
            "Credentials should be submitted using POST.",
            login.url,
            "Login form uses POST."
            if method_ok
            else "Expected POST login form not found.",
            "Maintain POST credential submission."
            if method_ok
            else "Review authentication form implementation."
        ))

        if login_form:
            action = login_form.get("action") or login.url
            action_abs = urljoin(login.url, action)
            same_origin = self._same_origin(action_abs)
            target_https = urlparse(self.target).scheme == "https"
            action_https = urlparse(action_abs).scheme == "https"

            status = "PASS"
            severity = "INFO"
            reason = "Login form posts to the same assessed origin."

            if not same_origin:
                status, severity = "PARTIAL", "MEDIUM"
                reason = "Login form action points to another origin."
            elif target_https and not action_https:
                status, severity = "FAIL", "HIGH"
                reason = "HTTPS page submits credentials to a non-HTTPS action."

            findings.append(Finding(
                "AUTH-006", "Authentication & Session",
                "Login form action integrity",
                status, severity, "CONFIRMED", "AUTH",
                f"action={action_abs}",
                "Credentials should post to an expected same-origin HTTPS endpoint.",
                login.url,
                reason,
                "Review login form action and transport protection."
                if status != "PASS"
                else "No action required."
            ))

        token = login_soup.find("input", attrs={"name": "logintoken"})
        token_present = token is not None

        findings.append(Finding(
            "AUTH-002", "Authentication & Session",
            "Login CSRF/logintoken mechanism",
            "PASS" if token_present else "PARTIAL",
            "INFO" if token_present else "MEDIUM",
            "CONFIRMED", "AUTH",
            "logintoken input present"
            if token_present
            else "logintoken input not observed",
            "Moodle login flow should include its anti-CSRF token mechanism.",
            login.url,
            "Login token mechanism observed."
            if token_present
            else "Expected login token was not observed.",
            "Maintain token validation."
            if token_present
            else "Verify Moodle login CSRF protection/configuration."
        ))

        login_text = login_soup.get_text(" ", strip=True).lower()

        guest_visible = (
            "log in as a guest" in login_text
            or "guest access" in login_text
        )
        findings.append(Finding(
            "AUTH-003", "Authentication & Session",
            "Guest-login visibility",
            "PARTIAL" if guest_visible else "PASS",
            "LOW" if guest_visible else "INFO",
            "HEURISTIC", "AUTH",
            "Guest login option visible"
            if guest_visible
            else "Guest login option not observed",
            "Guest access should be enabled only when explicitly required.",
            login.url,
            "Guest access appears available or advertised."
            if guest_visible
            else "Guest-login option was not observed.",
            "Review whether guest access is intended."
            if guest_visible
            else "No action required."
        ))

        signup = login_soup.find("a", href=re.compile(r"signup\.php", re.I))
        selfreg = signup is not None

        findings.append(Finding(
            "AUTH-004", "Authentication & Session",
            "Self-registration exposure",
            "PARTIAL" if selfreg else "PASS",
            "MEDIUM" if selfreg else "INFO",
            "CONFIRMED", "AUTH",
            f"signup link={signup.get('href')}"
            if signup
            else "No signup link observed",
            "Self-registration should be enabled only by policy.",
            login.url,
            "A self-registration link is exposed."
            if selfreg
            else "No self-registration link was observed.",
            "Confirm self-registration is required and properly controlled."
            if selfreg
            else "No action required."
        ))

        reset = login_soup.find(
            "a",
            href=re.compile(r"forgot_password\.php", re.I),
        )

        findings.append(Finding(
            "AUTH-005", "Authentication & Session",
            "Password-reset workflow",
            "PASS" if reset else "PARTIAL",
            "INFO", "CONFIRMED", "AUTH",
            f"reset link={reset.get('href')}"
            if reset
            else "Reset link not observed",
            "Password recovery should follow institutional policy.",
            login.url,
            "Password-reset workflow is exposed as expected."
            if reset
            else "Password-reset link was not observed.",
            "Review recovery policy and anti-enumeration controls."
        ))

        access_targets = [
            ("ACCESS-001", "my/", "User dashboard (/my/)"),
            ("ACCESS-002", "admin/", "Administration area (/admin/)"),
            ("ACCESS-004", "admin/environment.php", "Environment report"),
            ("ACCESS-005", "report/security/index.php", "Security report"),
            ("ACCESS-006", "admin/tool/health/", "Site health tool"),
        ]

        for fid, rel, name in access_targets:
            findings.append(self._access_finding(fid, rel, name))

        visible_course_index = (
            course.status_code == 200
            and "login/index.php" not in course.url.lower()
        )

        findings.append(Finding(
            "ACCESS-003", "Access Control",
            "Public course-index visibility",
            "PARTIAL" if visible_course_index else "PASS",
            "LOW" if visible_course_index else "INFO",
            "HEURISTIC", "ACCESS_CONTROL",
            f"status={course.status_code}; final_url={course.url}",
            "Public course/catalog visibility should follow institutional policy.",
            course.url,
            "Course index appears reachable without authentication."
            if visible_course_index
            else "Course index appears restricted or redirected.",
            "Review whether public course visibility is intended."
            if visible_course_index
            else "No action required."
        ))

        artifact_checks = [
            ("DISC-004", "README.txt", "Moodle README", "LOW"),
            ("DISC-005", "lib/upgrade.txt", "Moodle upgrade notes", "LOW"),
            ("DISC-006", "composer.json", "Composer manifest", "LOW"),
            ("DISC-007", "package.json", "Node package manifest", "LOW"),
            ("DISC-008", "phpunit.xml.dist", "PHPUnit configuration template", "MEDIUM"),
            ("DISC-009", "Gruntfile.js", "Grunt build file", "LOW"),
        ]

        for fid, rel, label, severity in artifact_checks:
            r = self.c.get(join(self.target, rel))
            signatures = {
                "README.txt": ("moodle",), "lib/upgrade.txt": ("upgrade", "moodle"),
                "composer.json": ('"require"', '"name"'), "package.json": ('"name"', '"scripts"'),
                "phpunit.xml.dist": ("<phpunit",), "Gruntfile.js": ("grunt", "module.exports"),
            }
            body = r.text.lower()
            exposed = (
                r.status_code == 200
                and len(r.text.strip()) > 40
                and "login/index.php" not in r.url.lower()
                and "<html" not in body and "<!doctype html" not in body
                and all(token in body for token in signatures[rel])
            )

            findings.append(Finding(
                fid, "Information Disclosure",
                f"Public {label}",
                "PARTIAL" if exposed else "PASS",
                severity if exposed else "INFO",
                "CONFIRMED" if exposed else "HEURISTIC",
                "PLATFORM_DISCLOSURE",
                f"status={r.status_code}; "
                f"sample={trunc(r.text[:180]) if exposed else 'not exposed'}",
                f"{label} need not be publicly readable unless required.",
                r.url,
                f"{label} is publicly readable."
                if exposed
                else f"{label} not confirmed publicly readable.",
                "Consider restricting unnecessary deployment/development artifacts."
                if exposed
                else "No action required."
            ))

        installer = self.c.get(join(self.target, "install.php"))
        install_body = installer.text[:8000].lower()
        installer_live = (
            installer.status_code == 200
            and ("installation" in install_body or "moodle" in install_body)
            and "login/index.php" not in installer.url.lower()
        )

        findings.append(Finding(
            "EXPOSURE-007", "Exposure",
            "Moodle installer exposure",
            "PARTIAL" if installer_live else "PASS",
            "MEDIUM" if installer_live else "INFO",
            "HEURISTIC", "EXPOSURE",
            f"status={installer.status_code}; final_url={installer.url}",
            "Post-installation deployment should not expose an operational installer workflow.",
            installer.url,
            "Installer-related page appears reachable."
            if installer_live
            else "No operational installer exposure was confirmed.",
            "Verify install.php behavior and restrict/remove installer exposure."
            if installer_live
            else "No action required."
        ))

        parsed = urlparse(self.target)
        server_root = f"{parsed.scheme}://{parsed.netloc}/"
        data_candidates = [
            urljoin(server_root, "moodledata/"),
            join(self.target, "moodledata/"),
        ]

        seen = set()
        exposed_candidates = []
        evidence = []

        for url in data_candidates:
            if url in seen:
                continue
            seen.add(url)

            r = self.c.get(url)
            evidence.append(f"{url} -> {r.status_code}")

            if r.status_code == 200 and "login/index.php" not in r.url.lower():
                body = r.text[:5000].lower()
                if "index of" in body:
                    exposed_candidates.append(url)

        findings.append(Finding(
            "EXPOSURE-008", "Exposure",
            "Potential web-accessible moodledata path",
            "FAIL" if exposed_candidates else "PASS",
            "HIGH" if exposed_candidates else "INFO",
            "HEURISTIC", "EXPOSURE",
            "; ".join(evidence),
            "Moodle dataroot must not be web-accessible.",
            "Selected conventional moodledata locations",
            "A candidate moodledata directory listing appears reachable."
            if exposed_candidates
            else "No selected conventional moodledata path exposed a directory listing.",
            "Move/restrict dataroot outside the web root immediately."
            if exposed_candidates
            else "No action required."
        ))

        if urlparse(self.target).scheme == "https":
            mixed = []
            insecure_forms = []

            for soup, page_url in [
                (home_soup, home.url),
                (login_soup, login.url),
                (course_soup, course.url),
            ]:
                for tag in soup.find_all(src=True) + soup.find_all(href=True):
                    value = tag.get("src") or tag.get("href") or ""
                    if value.lower().startswith("http://"):
                        mixed.append(value)

                for form in soup.find_all("form"):
                    action = form.get("action") or page_url
                    action_abs = urljoin(page_url, action)
                    if action_abs.lower().startswith("http://"):
                        insecure_forms.append(action_abs)

            findings.append(Finding(
                "TRANSPORT-004", "Transport Security",
                "Mixed-content references",
                "FAIL" if mixed else "PASS",
                "MEDIUM" if mixed else "INFO",
                "HEURISTIC", "TRANSPORT",
                json.dumps(mixed[:20], ensure_ascii=False),
                "HTTPS pages should not reference insecure HTTP resources.",
                "Public Moodle pages",
                "HTTP resource references were found on HTTPS pages."
                if mixed
                else "No selected mixed-content references were observed.",
                "Replace insecure resource URLs with HTTPS."
                if mixed
                else "No action required."
            ))

            findings.append(Finding(
                "AUTH-007", "Authentication & Session",
                "Insecure form actions on HTTPS pages",
                "FAIL" if insecure_forms else "PASS",
                "HIGH" if insecure_forms else "INFO",
                "CONFIRMED", "TRANSPORT",
                json.dumps(insecure_forms[:20], ensure_ascii=False),
                "Forms on HTTPS pages should not submit to HTTP endpoints.",
                "Public Moodle forms",
                "One or more forms submit from HTTPS to HTTP."
                if insecure_forms
                else "No HTTP form actions were observed on assessed HTTPS pages.",
                "Use HTTPS form actions."
                if insecure_forms
                else "No action required."
            ))

        components = self._extract_components(soups)
        count = sum(len(v) for v in components.values())

        findings.append(Finding(
            "MOODLE-002", "Moodle Platform",
            "Public component identifiers",
            "PARTIAL" if count else "PASS",
            "INFO", "HEURISTIC", "PLATFORM_DISCLOSURE",
            json.dumps(components, ensure_ascii=False),
            "Public component names may be observable; vulnerable-version claims require separate version evidence.",
            "Public home/login/course HTML asset URLs",
            "Component identifiers were observed in public asset paths."
            if count
            else "No selected component identifiers were extracted.",
            "Use the inventory as reconnaissance evidence only; "
            "do not infer vulnerable versions without version data."
        ))

        return findings, components
