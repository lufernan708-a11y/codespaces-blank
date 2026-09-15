import asyncio
import time
from typing import Any

from playwright.async_api import async_playwright


def diagnosticar_com_selenium(url: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(timeout_sec)
        try:
            driver.get(url)
            return {"url": driver.current_url, "title": driver.title, "status": "ok"}
        finally:
            driver.quit()
    except Exception as exc:
        return {"url": url, "status": "erro", "error": str(exc)}


async def diagnosticar_com_playwright(url: str) -> dict[str, Any]:
    inicio = time.perf_counter()
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            resposta = await page.goto(url, wait_until="networkidle")
            return {
                "motor": "Playwright",
                "url": url,
                "status": resposta.status if resposta else 500,
                "titulo": await page.title(),
                "tempo_resposta_s": round(time.perf_counter() - inicio, 2),
            }
        finally:
            await browser.close()


async def executar_diagnostico(url: str, mecanic: str = "playwright") -> dict[str, Any]:
    motor = mecanic.lower()
    if motor == "playwright":
        return await diagnosticar_com_playwright(url)
    if motor == "selenium":
        return await asyncio.to_thread(diagnosticar_com_selenium, url)
    raise ValueError("Motor inválido. Escolha 'playwright' ou 'selenium'.")
