import base64
from typing import Any


async def _carregar_pagina(url: str) -> dict[str, Any]:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright nao esta instalado") from exc

    erros_console: list[str] = []
    erros_pagina: list[str] = []
    avisos: list[str] = []

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        page.on("console", lambda message: erros_console.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: erros_pagina.append(str(error)))
        try:
            response = await page.goto(url, wait_until="networkidle", timeout=30000)
            return {
                "page": page,
                "browser": browser,
                "response_code": response.status if response else None,
                "console_errors": erros_console,
                "page_errors": erros_pagina,
                "warnings": avisos,
            }
        except Exception as exc:
            avisos.append(str(exc))
            return {
                "page": page,
                "browser": browser,
                "response_code": None,
                "console_errors": erros_console,
                "page_errors": erros_pagina,
                "warnings": avisos,
            }


async def capturar_screenshot(url: str, motor: str = "playwright") -> str | None:
    try:
        if motor.lower() != "playwright":
            raise ValueError("Motor inválido. Esta captura usa Playwright.")
        from playwright.async_api import async_playwright

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(url, wait_until="networkidle", timeout=30000)
                screenshot = await page.screenshot(type="png", full_page=True)
            finally:
                await browser.close()
        return base64.b64encode(screenshot).decode("ascii")
    except Exception:
        return None


async def diagnosticar_visualmente(url: str) -> dict[str, Any] | None:
    try:
        dados = await _carregar_pagina(url)
        resultado = {chave: valor for chave, valor in dados.items() if chave not in {"page", "browser"}}
        await dados["browser"].close()
        return resultado
    except Exception as exc:
        return {
            "response_code": None,
            "console_errors": [],
            "page_errors": [],
            "warnings": [str(exc)],
        }
