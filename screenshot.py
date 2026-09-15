import asyncio
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, Any
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from playwright.async_api import async_playwright

async def capturar_screenshot_playwright(url: str, caminho_saida: Optional[str] = None) -> bytes:
    """Captura screenshot de alta velocidade usando Playwright (Assíncrono)."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        # Ajusta a viewport para resoluções padrão de desktop
        await page.set_viewport_size({"width": 1280, "height": 800})
        await page.goto(url, wait_until="networkidle")
        
        # Captura em memória ou salva direto no disco
        bytes_imagem = await page.screenshot(full_page=True, path=caminho_saida)
        await browser.close()
        return bytes_imagem

def capturar_screenshot_selenium(url: str, caminho_saida: Optional[str] = None) -> bytes:
    """Captura screenshot usando Selenium (Síncrono)."""
    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1280, 800)
    driver.get(url)
    
    bytes_imagem = driver.get_screenshot_as_png()
    driver.quit()
    
    if caminho_saida:
        Path(caminho_saida).write_bytes(bytes_imagem)
        
    return bytes_imagem

async def capturar_screenshot(url: str, caminho_saida: Optional[str] = None, motor: str = "playwright") -> bytes:
    """Função principal para captura de tela unificada."""
    if motor.lower() == "playwright":
        return await capturar_screenshot_playwright(url, caminho_saida)
    elif motor.lower() == "selenium":
        return await asyncio.to_thread(capturar_screenshot_selenium, url, caminho_saida)
    else:
        raise ValueError("Motor inválido. Escolha 'playwright' ou 'selenium'.")

def diagnosticar_visualmente(bytes_imagem: bytes) -> Dict[str, Any]:
    """Analisa a imagem capturada usando a biblioteca Pillow (PIL)."""
    imagem = Image.open(BytesIO(bytes_imagem))
    largura, altura = imagem.size
    modo = imagem.mode
    
    return {
        "largura_px": largura,
        "altura_px": altura,
        "modo_cor": modo,
        "tamanho_bytes": len(bytes_imagem)
    }