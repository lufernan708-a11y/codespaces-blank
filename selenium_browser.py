import asyncio
import time
from typing import Any, Dict
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from playwright.async_api import async_playwright

async def diagnosticar_com_playwright(url: str) -> Dict[str, Any]:
    """Executa diagnóstico web utilizando Playwright (Modo Assíncrono Nativo)."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        inicio = asyncio.get_event_loop().time()
        resposta = await page.goto(url, wait_until="networkidle")
        tempo_carregamento = asyncio.get_event_loop().time() - inicio
        
        status_code = resposta.status if resposta else 500
        titulo = await page.title()
        
        await browser.close()
        
        return {
            "motor": "Playwright",
            "url": url,
            "status": status_code,
            "titulo": titulo,
            "tempo_resposta_s": round(tempo_carregamento, 2)
        }

def diagnosticar_com_selenium(url: str) -> Dict[str, Any]:
    """Executa diagnóstico web utilizando Selenium Webdriver (Modo Síncrono/Threaded)."""
    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    driver = webdriver.Chrome(options=options)
    
    inicio = time.perf_counter()
    try:
        driver.get(url)
        titulo = driver.title
        url_final = driver.current_url
    finally:
        driver.quit()
    tempo_resposta = time.perf_counter() - inicio
    
    return {
        "motor": "Selenium",
        "url": url_final,
        "titulo": titulo,
        "tempo_resposta_s": round(tempo_resposta, 2),
    }

async def executar_diagnostico(url: str, mecanic: str = "playwright") -> Dict[str, Any]:
    """Função principal para alternar entre os motores de automação."""
    if mecanic.lower() == "playwright":
        return await diagnosticar_com_playwright(url)
    elif mecanic.lower() == "selenium":
        # Executa a chamada síncrona do Selenium em uma thread para não bloquear o loop do asyncio
        return await asyncio.to_thread(diagnosticar_com_selenium, url)
    else:
        raise ValueError("Motor inválido. Escolha 'playwright' ou 'selenium'.")