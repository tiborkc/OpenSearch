from __future__ import annotations

import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


def upsert_env_value(env_path: Path, key: str, value: str) -> None:
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    new_line = f"{key}={value}"
    replaced = False

    updated_lines: list[str] = []
    for line in lines:
        if pattern.match(line):
            updated_lines.append(new_line)
            replaced = True
        else:
            updated_lines.append(line)

    if not replaced:
        updated_lines.append(new_line)

    env_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")


def refresh_security_cookie_silently(
    base_url: str,
    env_path: Path | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout_seconds: int = 60,
    ignore_https_errors: bool = True,
) -> str:
    """Háttérben (headless) bejelentkezik, kiszedi a security_authentication cookie-t, és menti a .env-be."""
    target_url = base_url.strip().rstrip("/")
    if not target_url:
        raise ValueError("Hiányzik a Dashboards URL.")

    resolved_env = env_path or (Path(__file__).resolve().parent / ".env")
    user_val = (username if username is not None else os.getenv("OS_LOGIN_USER", "")).strip()
    pass_val = (password if password is not None else os.getenv("OS_LOGIN_PASS", "")).strip()

    if not user_val or not pass_val:
        raise RuntimeError(
            "Automatikus 401-es frissítéshez add meg az OS_LOGIN_USER és OS_LOGIN_PASS értékeket a .env fájlban!"
        )

    host_domain = urlparse(target_url).hostname or ""
    cookie_value: str | None = None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=ignore_https_errors)
        page = context.new_page()
        page.goto(target_url, wait_until="domcontentloaded", timeout=60000)

        # Megvárjuk a login mezők megjelenését és kitöltjük
        user_input = page.locator(
            "input[name='username'], input[type='email'], input[id*='user' i], input[type='text']"
        ).first
        pass_input = page.locator("input[type='password']").first

        user_input.wait_for(state="visible", timeout=20000)
        user_input.fill(user_val)
        pass_input.fill(pass_val)

        submit_btn = page.locator("button[type='submit'], input[type='submit']").first
        if submit_btn.count() > 0:
            submit_btn.click()
        else:
            pass_input.press("Enter")

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            cookies = context.cookies([target_url])
            for c in cookies:
                if c.get("name") == "security_authentication" and c.get("value"):
                    if not host_domain or host_domain in (c.get("domain") or ""):
                        cookie_value = str(c["value"]).strip()
                        break
            if cookie_value:
                break
            time.sleep(0.4)

        context.close()
        browser.close()

    if not cookie_value:
        raise TimeoutError(
            f"{timeout_seconds} másodperc alatt nem sikerült megszerezni a 'security_authentication' cookie-t."
        )

    upsert_env_value(resolved_env, "OS_SECURITY_COOKIE", cookie_value)
    os.environ["OS_SECURITY_COOKIE"] = cookie_value
    return cookie_value