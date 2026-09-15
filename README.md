# ⚡ LOAD & SEC STUDIO (Spectrum Engine)

> Platforma unificada de testes de carga, análise DAST (vulnerabilidades OWASP), diagnóstico visual e geração automatizada de relatórios em PDF.

---

## 📋 Sobre o Projeto

O **LOAD & SEC STUDIO** é uma solução de auditoria web projetada para executar varreduras de segurança DAST, métricas de volumetria/concorrência e geração de evidências visuais e documentais de páginas web. 

A ferramenta foi construída utilizando **FastAPI** no backend, automação híbrida de navegação (**Playwright** + **Selenium**) e uma interface moderna em **HTML5, Tailwind CSS e JavaScript**.

---

## 🚀 Arquitetura e Tecnologias

* **Backend:** Python 3.10+, FastAPI, Uvicorn, HTTPX (assíncrono)
* **Automação & Scraping:** Playwright, Selenium WebDriver, BeautifulSoup4
* **Processamento de Imagem & Relatórios:** Pillow (PIL), ReportLab, FPDF2
* **Frontend:** HTML5, Tailwind CSS, JavaScript (ES6+)
* **Ambiente Virtual:** Linux / VS Code Codespaces (`venv`)

---

## 🛠️ Desafios Técnicos Superados & Experiências

### 1. Bypass de Restrições de iFrame (X-Frame-Options & CSP)
* **Desafio:** Ao tentar espelhar sites externos no dashboard utilizando tags `<iframe>` tradicionais, o navegador bloqueava a exibição devido às políticas de segurança (`X-Frame-Options` e `Content-Security-Policy`) dos alvos.
* **Solução:** Implementação de um fluxo de renderização Headless via **Playwright**. Em vez de carregar a página diretamente no iFrame do cliente, a API em FastAPI executa a renderização no lado do servidor e retorna o estado visual em tempo real (imagem/stream), contornando 100% dos bloqueios de segurança do navegador.

### 2. Renderização de Aplicações SPA (React / Vite)
* **Desafio:** Requisições HTTP simples via scraping (`requests`/`httpx`) retornavam telas brancas para aplicações modernas baseadas em Single Page Applications (React/Vite), pois os arquivos de bundle `.js` e rotas virtuais não eram executados.
* **Solução:** Integração assíncrona do **Playwright Chromium Engine** no pipeline de captura. O servidor aguarda o evento `networkidle` para garantir que todo o ciclo de vida do JavaScript da SPA seja executado antes da geração de relatórios e evidências.

### 3. Concorrência e Processamento de Relatórios em Tempo Real
* **Desafio:** Integrar a captura de telas pesadas, análise de rede e geração de PDFs com ReportLab sem bloquear o loop de eventos (*event loop*) do FastAPI.
* **Solução:** Uso do `asyncio.to_thread` para isolar chamadas síncronas pesadas (como Selenium e geração de PDFs do ReportLab) e adoção nativa de funções assíncronas para chamadas de rede com `httpx` e `playwright.async_api`.

---

## 📁 Estrutura do Projeto

```text
.
├── Spectrum.py                 # Aplicação principal FastAPI (Rotas & Servidor)
├── services/
│   ├── __init__.py             # Identificador de pacote Python
│   ├── reporting.py            # Geração de PDFs e relatórios (ReportLab)
│   ├── screenshot.py           # Captura visual e análise com Pillow (Playwright/Selenium)
│   ├── security.py             # Varreduras DAST e verificação OWASP
│   └── selenium_browser.py     # Automação de navegadores e métricas de latência
├── requirements.txt            # Dependências do projeto
└── README.md                   # Documentação do projeto
