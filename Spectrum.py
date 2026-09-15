import asyncio
import base64
from html import escape
import json
import math
import time
from pathlib import Path
from typing import Optional
import httpx
import uvicorn
from fastapi import FastAPI, Form, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from screenshot import (
    capturar_screenshot as capturar_screenshot_bytes,
    diagnosticar_visualmente as diagnosticar_imagem,
)
from reporting import gerar_relatorio_pdf as gerar_relatorio_pdf_evidencia
from services.reporting import gerar_relatorio_evidencia, gerar_relatorio_pdf
from services.screenshot import capturar_screenshot, diagnosticar_visualmente
from services.security import testar_vulnerabilidades
from services.selenium_browser import diagnosticar_com_selenium, executar_diagnostico

app = FastAPI(title="Enterprise Load & Security Diagnostic Studio")
# ---------------------------------------------------------------------
# MOTOR DE TESTES DE CARGA E PERFORMANCE
# ---------------------------------------------------------------------
async def executar_suite_completa(
    url: str,
    method: str,
    total_requests: int,
    concurrency: int,
    timeout_sec: float,
    ramp_up: bool,
    cache_buster: bool,
    user_agent: str,
    target_sla_ms: float,
    run_sec_scan: bool,
    custom_headers_str: str,
    payload_str: str
):
    sem = asyncio.Semaphore(concurrency)

    headers = {
        "User-Agent": user_agent or "EnterpriseLoadAndSecTester/3.0",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }
    
    if custom_headers_str and custom_headers_str.strip():
        try:
            headers.update(json.loads(custom_headers_str))
        except Exception:
            pass

    body_data = None
    if payload_str and payload_str.strip() and method in ["POST", "PUT", "PATCH"]:
        try:
            body_data = json.loads(payload_str)
        except Exception:
            body_data = payload_str

    tempos_totais = []
    status_codes = {}
    erros_detalhados = {"timeout": 0, "connection_refused": 0, "dns_failure": 0, "ssl_error": 0, "http_4xx": 0, "http_5xx": 0, "outros": 0}
    series_tempo = []

    inicio_global = time.perf_counter()
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency * 2)
    timeout_config = httpx.Timeout(timeout_sec)

    vulnerabilidades = []
    screenshot_base64 = None
    visual_diagnosis = None

    # Executa a captura visual e a varredura em paralelo/isolado
    if method == "GET":
        screenshot_base64 = await capturar_screenshot(url)
        visual_diagnosis = await diagnosticar_visualmente(url)

    async with httpx.AsyncClient(limits=limits, timeout=timeout_config, follow_redirects=True, verify=False) as client:
        
        if run_sec_scan:
            try:
                vulnerabilidades = await testar_vulnerabilidades(client, url)
            except Exception:
                vulnerabilidades = [{
                    "severidade": "BAIXO",
                    "titulo": "Falha no DAST",
                    "descricao": "Não foi possível concluir a varredura automatizada."
                }]

        async def worker_requisicao(index: int):
            if ramp_up and concurrency > 1:
                delay = (index % concurrency) * (2.0 / concurrency)
                await asyncio.sleep(delay)

            url_final = url
            if cache_buster:
                sep = "&" if "?" in url else "?"
                url_final = f"{url}{sep}_cb={time.time_ns()}_{index}"

            async with sem:
                inicio_req = time.perf_counter()
                timestamp_relativo = round(inicio_req - inicio_global, 2)

                try:
                    req_kwargs = {"url": url_final, "headers": headers}
                    if body_data:
                        if isinstance(body_data, dict):
                            req_kwargs["json"] = body_data
                        else:
                            req_kwargs["content"] = body_data

                    resposta = await client.request(method, **req_kwargs)
                    duracao_total = (time.perf_counter() - inicio_req) * 1000

                    tempos_totais.append(duracao_total)
                    code = resposta.status_code
                    status_codes[code] = status_codes.get(code, 0) + 1

                    if 400 <= code < 500:
                        erros_detalhados["http_4xx"] += 1
                    elif code >= 500:
                        erros_detalhados["http_5xx"] += 1

                    series_tempo.append({
                        "id": index + 1,
                        "time": timestamp_relativo,
                        "latency": round(duracao_total, 2),
                        "status": code
                    })

                except httpx.TimeoutException:
                    erros_detalhados["timeout"] += 1
                except httpx.ConnectTimeout:
                    erros_detalhados["connection_refused"] += 1
                except httpx.ConnectError:
                    erros_detalhados["dns_failure"] += 1
                except httpx.SSLError:
                    erros_detalhados["ssl_error"] += 1
                except Exception:
                    erros_detalhados["outros"] += 1

        tasks = [worker_requisicao(i) for i in range(total_requests)]
        await asyncio.gather(*tasks)
        tempo_total_execucao = time.perf_counter() - inicio_global

    sucessos = len(tempos_totais)
    erros_totais = sum(erros_detalhados.values())
    tempos_ordenados = sorted(tempos_totais)

    def calcular_percentil(p):
        if not tempos_ordenados: return 0
        k = (len(tempos_ordenados) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c: return round(tempos_ordenados[int(k)], 2)
        return round(tempos_ordenados[int(f)] * (c - k) + tempos_ordenados[int(c)] * (k - f), 2)

    p50 = calcular_percentil(50)
    p75 = calcular_percentil(75)
    p90 = calcular_percentil(90)
    p95 = calcular_percentil(95)
    p99 = calcular_percentil(99)

    satisfeitos = sum(1 for t in tempos_totais if t <= target_sla_ms)
    tolerando = sum(1 for t in tempos_totais if target_sla_ms < t <= (target_sla_ms * 4))
    apdex_score = round((satisfeitos + (tolerando / 2)) / total_requests, 2) if total_requests > 0 else 0

    media_latencia = sum(tempos_totais) / sucessos if sucessos > 0 else 0
    variancia = sum((x - media_latencia) ** 2 for x in tempos_totais) / sucessos if sucessos > 0 else 0
    desvio_padrao = round(math.sqrt(variancia), 2)
    rps_efetivo = round(total_requests / tempo_total_execucao, 2) if tempo_total_execucao > 0 else 0

    diagnosticos = []
    if apdex_score >= 0.94:
        diagnosticos.append(f"🟢 **SLA / Apdex Excelente ({apdex_score}):** Sistema atende a meta de {target_sla_ms}ms com alta estabilidade.")
    elif apdex_score >= 0.85:
        diagnosticos.append(f"🟡 **SLA / Apdex Aceitável ({apdex_score}):** Pequena degradação perceptível sob carga.")
    else:
        diagnosticos.append(f"🔴 **SLA Violado (Apdex {apdex_score}):** Nível de serviço inaceitável para a meta de {target_sla_ms}ms.")

    if erros_detalhados["timeout"] > 0:
        diagnosticos.append(f"🔴 **Timeouts Socket ({erros_detalhados['timeout']} reqs):** Sobrecarga no servidor ou estouro na pool de banco de dados.")

    if visual_diagnosis:
        if visual_diagnosis["response_code"] and visual_diagnosis["response_code"] >= 400:
            diagnosticos.append(f"🟠 **Diagnóstico Visual:** resposta HTTP {visual_diagnosis['response_code']} observada pelo navegador invisível.")
        if visual_diagnosis["page_errors"] or visual_diagnosis["console_errors"]:
            diagnosticos.append("🔴 **Diagnóstico Visual:** erros de página ou console detectados pelo navegador headless.")
        if not visual_diagnosis["warnings"]:
            diagnosticos.append("🟢 **Diagnóstico Visual:** navegador invisível sem falhas de rede ou carregamento aparente.")

    return {
        "total_requests": total_requests,
        "sucessos": sucessos,
        "erros": erros_totais,
        "tempo_total_execucao": round(tempo_total_execucao, 2),
        "rps": rps_efetivo,
        "media_ms": round(media_latencia, 2),
        "desvio_padrao_ms": desvio_padrao,
        "apdex_score": apdex_score,
        "target_sla_ms": target_sla_ms,
        "p50": p50, "p75": p75, "p90": p90, "p95": p95, "p99": p99,
        "status_codes": status_codes,
        "erros_detalhados": erros_detalhados,
        "series_tempo": series_tempo,
        "diagnosticos": diagnosticos,
        "vulnerabilidades": vulnerabilidades,
        "screenshot": screenshot_base64,
        "visual_diagnosis": visual_diagnosis
    }


# ---------------------------------------------------------------------
# INTERFACE DASHBOARD UNIFICADA (HTML / CSS / JS)
# ---------------------------------------------------------------------
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Load & Security Studio</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #090d16;
            --panel: #111827;
            --panel-border: #1f2937;
            --input: #1f2937;
            --accent: #06b6d4;
            --accent-hover: #0891b2;
            --text-main: #f3f4f6;
            --text-sub: #9ca3af;
            --border: #374151;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #a855f7;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: var(--bg); color: var(--text-main); padding: 1.5rem; display: flex; justify-content: center; }
        .app-container { width: 100%; max-width: 1400px; display: grid; grid-template-columns: 420px 1fr; gap: 1.5rem; }

        .sidebar { background: var(--panel); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--panel-border); }
        .sidebar-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; border-bottom: 1px solid var(--panel-border); padding-bottom: 1rem; }
        .sidebar-header h1 { font-size: 1.1rem; color: var(--accent); font-weight: 700; letter-spacing: 0.5px; }
        .badge-enterprise { background: rgba(6, 182, 212, 0.15); color: var(--accent); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; border: 1px solid var(--accent); }

        .form-section-title { font-size: 0.75rem; text-transform: uppercase; color: var(--accent); font-weight: 700; margin: 1.2rem 0 0.6rem 0; letter-spacing: 0.8px; }
        .form-group { margin-bottom: 0.85rem; }
        label { display: block; margin-bottom: 0.35rem; font-size: 0.8rem; font-weight: 600; color: var(--text-sub); }
        input, select, textarea { width: 100%; padding: 0.6rem 0.75rem; border-radius: 6px; border: 1px solid var(--border); background: var(--input); color: #fff; font-size: 0.85rem; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); }
        textarea { resize: vertical; min-height: 55px; font-family: monospace; font-size: 0.75rem; }

        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
        .checkbox-container { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem; }
        .checkbox-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: var(--text-main); cursor: pointer; }
        .checkbox-label input { width: auto; }

        .btn-execute { width: 100%; padding: 0.85rem; background: var(--accent); color: #000; border: none; border-radius: 6px; font-size: 0.95rem; font-weight: 800; cursor: pointer; margin-top: 1.2rem; transition: background 0.2s; }
        .btn-execute:hover { background: var(--accent-hover); color: #fff; }
        .btn-execute:disabled { background: var(--border); color: var(--text-sub); cursor: not-allowed; }

        .main-dashboard { display: flex; flex-direction: column; gap: 1.5rem; }
        #placeholder { background: var(--panel); border: 1px dashed var(--border); border-radius: 12px; padding: 5rem 2rem; text-align: center; color: var(--text-sub); }
        #loading { display: none; background: var(--panel); border-radius: 12px; padding: 4rem; text-align: center; color: var(--accent); font-weight: 600; border: 1px solid var(--panel-border); }
        #results { display: none; flex-direction: column; gap: 1.5rem; }

        .results-header { display: flex; justify-content: space-between; align-items: center; background: var(--panel); padding: 1rem 1.5rem; border-radius: 12px; border: 1px solid var(--panel-border); }
        .results-title h2 { font-size: 1.1rem; color: #fff; }
        .results-title p { font-size: 0.8rem; color: var(--text-sub); }

        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }
        .metric-card { background: var(--panel); padding: 1rem 1.2rem; border-radius: 10px; border: 1px solid var(--panel-border); }
        .metric-card.highlight { border-left: 4px solid var(--accent); }
        .metric-card.sec-card { border-left: 4px solid var(--purple); }
        .metric-card h3 { font-size: 0.7rem; text-transform: uppercase; color: var(--text-sub); letter-spacing: 0.5px; margin-bottom: 0.4rem; }
        .metric-card .value { font-size: 1.6rem; font-weight: 800; color: #fff; }
        .metric-card .subtext { font-size: 0.75rem; color: var(--accent); margin-top: 0.2rem; }

        /* PAINEL DE PREVIEW DA APLICAÇÃO ALVO */
        .preview-wrapper { background: var(--panel); padding: 1.2rem; border-radius: 12px; border: 1px solid var(--panel-border); display: none; }
        .preview-wrapper h2 { font-size: 0.9rem; color: var(--text-sub); margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .preview-container { width: 100%; border-radius: 8px; overflow: hidden; border: 1px solid var(--border); background: #000; }
        .preview-container img { width: 100%; height: auto; display: block; object-fit: cover; }

        .percentiles-wrapper { background: var(--panel); padding: 1.2rem; border-radius: 12px; border: 1px solid var(--panel-border); }
        .percentiles-wrapper h2 { font-size: 0.9rem; color: var(--text-sub); margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .percentile-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
        .percentile-table th { background: var(--input); padding: 0.6rem 1rem; color: var(--text-sub); font-weight: 600; }
        .percentile-table td { padding: 0.6rem 1rem; border-bottom: 1px solid var(--panel-border); color: #fff; }

        .charts-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem; }
        .chart-card { background: var(--panel); padding: 1.2rem; border-radius: 12px; border: 1px solid var(--panel-border); }
        .chart-card h2 { font-size: 0.9rem; color: var(--text-sub); margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.5px; }

        .sec-wrapper { background: var(--panel); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--panel-border); }
        .sec-wrapper h2 { font-size: 1.05rem; color: var(--purple); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        .sec-list { display: flex; flex-direction: column; gap: 0.75rem; }
        .sec-item { background: var(--bg); padding: 1rem; border-radius: 8px; border: 1px solid var(--border); }
        .sec-item.ALTO { border-left: 4px solid var(--danger); }
        .sec-item.MEDIO { border-left: 4px solid var(--warning); }
        .sec-item.BAIXO { border-left: 4px solid var(--accent); }
        .sec-item.INFO { border-left: 4px solid var(--text-sub); }
        .sec-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem; }
        .sec-title { font-weight: 700; font-size: 0.9rem; color: #fff; }
        .sec-badge { font-size: 0.65rem; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 800; text-transform: uppercase; }
        .sec-badge.ALTO { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .sec-badge.MEDIO { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        .sec-badge.BAIXO { background: rgba(6, 182, 212, 0.2); color: var(--accent); }
        .sec-badge.INFO { background: rgba(156, 163, 175, 0.2); color: var(--text-sub); }
        .sec-desc { font-size: 0.8rem; color: var(--text-sub); line-height: 1.4; }

        .diag-wrapper { background: var(--panel); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--panel-border); }
        .diag-wrapper h2 { font-size: 1.05rem; color: var(--warning); margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        .diag-list { list-style: none; display: flex; flex-direction: column; gap: 0.6rem; }
        .diag-item { background: var(--bg); padding: 0.85rem 1rem; border-radius: 6px; border-left: 4px solid var(--accent); font-size: 0.85rem; line-height: 1.5; }

        @media (max-width: 1100px) {
            .app-container { grid-template-columns: 1fr; }
            .charts-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- SIDEBAR -->
        <div class="sidebar">
            <div class="sidebar-header">
                <h1>LOAD & SEC STUDIO</h1>
                <span class="badge-enterprise">ENTERPRISE 3.0</span>
            </div>

            <form id="suiteForm">
                <div class="form-section-title">Parâmetros do Alvo</div>
                <div class="form-group">
                    <label>Endpoint / URL Target</label>
                    <div style="display: flex; gap: 0.5rem;">
                        <select name="method" style="width: 100px;">
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                        </select>
                        <input type="url" name="url" required value="https://censo.dotal.com.br/">
                    </div>
                </div>

                <div class="form-section-title">Volumetria & Concorrência</div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>Total Requisições</label>
                        <input type="number" name="requests" value="100" min="1" max="50000" required>
                    </div>
                    <div class="form-group">
                        <label>Usuários Virtuais</label>
                        <input type="number" name="concurrency" value="15" min="1" max="500" required>
                    </div>
                </div>

                <div class="grid-2">
                    <div class="form-group">
                        <label>Timeout Socket (s)</label>
                        <input type="number" step="0.5" name="timeout_sec" value="5.0">
                    </div>
                    <div class="form-group">
                        <label>SLA Target (ms)</label>
                        <input type="number" name="target_sla_ms" value="500">
                    </div>
                </div>

                <div class="form-section-title">Injeção & Módulos</div>
                <div class="checkbox-container">
                    <label class="checkbox-label">
                        <input type="checkbox" name="run_sec_scan" checked>
                        <strong>Executar Varredura DAST (Vulnerabilidades)</strong>
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" name="ramp_up" checked>
                        Ramp-Up Gradual
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" name="cache_buster" checked>
                        Cache Buster (Bypass CDN)
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" name="confirm_high_load">
                        Confirmo que tenho autorização para carga acima de 10.000 requisições
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" name="run_selenium">
                        Executar diagnóstico adicional no Chrome via Selenium
                    </label>
                </div>

                <div class="form-section-title">Cabeçalhos & Payload</div>
                <div class="form-group">
                    <label>User-Agent Customizado</label>
                    <input type="text" name="user_agent" value="EnterpriseLoadAndSecTester/3.0">
                </div>

                <div class="form-group">
                    <label>Headers JSON</label>
                    <textarea name="custom_headers" placeholder='{"Authorization": "Bearer token..."}'></textarea>
                </div>

                <div class="form-group">
                    <label>Body Payload</label>
                    <textarea name="payload" placeholder='{"cart_id": "123"}'></textarea>
                </div>

                <button type="submit" class="btn-execute" id="btnExecute">DISPARAR TESTE INTEGRADO</button>
            </form>
        </div>

        <!-- MAIN DASHBOARD -->
        <div class="main-dashboard">
            <div id="placeholder">
                <h2 style="font-size: 1.3rem; color: var(--text-main); margin-bottom: 0.5rem;">Pronto para iniciar</h2>
                <p>O sistema renderizará a interface da aplicação e executará a suíte de performance e segurança.</p>
            </div>

            <div id="loading">
                <div style="font-size: 1.2rem; margin-bottom: 0.5rem;">⚙️ Renderizando aplicação & Executando Testes...</div>
                <p style="font-size: 0.85rem; color: var(--text-sub);">Capturando screenshot visual via Playwright, testando SLA e vulnerabilidades DAST</p>
            </div>

            <div id="results">
                <div class="results-header">
                    <div class="results-title">
                        <h2>Relatório Unificado de Performance e Segurança</h2>
                        <p id="resTimestamp">Executado em: --</p>
                        <a id="reportLink" href="#" target="_blank" rel="noopener">Abrir relatório PDF</a>
                    </div>
                </div>

                <div class="metrics-grid">
                    <div class="metric-card highlight">
                        <h3>Apdex Score (SLA)</h3>
                        <div class="value" id="cardApdex">0.00</div>
                        <div class="subtext" id="cardSlaMeta">Meta: 500ms</div>
                    </div>
                    <div class="metric-card sec-card">
                        <h3>Vulnerabilidades</h3>
                        <div class="value" id="cardVulnCount" style="color: var(--purple);">0</div>
                        <div class="subtext" id="cardVulnSub">0 Críticas/Altas</div>
                    </div>
                    <div class="metric-card">
                        <h3>Vazão (RPS)</h3>
                        <div class="value" id="cardRps">0</div>
                        <div class="subtext">reqs/segundo</div>
                    </div>
                    <div class="metric-card">
                        <h3>Latência Média</h3>
                        <div class="value" id="cardAvg">0 ms</div>
                        <div class="subtext" id="cardDesvio">Desvio: ±0 ms</div>
                    </div>
                </div>

                <!-- PAINEL VISUAL DA APLICAÇÃO -->
                <div class="preview-wrapper" id="previewWrapper">
                    <h2>🌐 Renderização Visual da Aplicação (Headless Browser)</h2>
                    <div class="preview-container">
                        <img id="appScreenshot" src="" alt="Interface da Aplicação Target">
                    </div>
                </div>

                <!-- Container de Espelhamento do Alvo -->
                <div class="bg-gray-900 border border-gray-800 rounded-lg p-4 mt-6">
                    <div class="flex justify-between items-center mb-3">
                        <h3 class="text-gray-100 font-semibold text-sm flex items-center gap-2">
                            <span>🌐</span> Espelhamento do Alvo (Mirror Preview)
                        </h3>
                        <a id="btn-abrir-nova-aba" href="#" target="_blank" class="text-blue-400 hover:text-blue-300 text-xs text-decoration-none">
                            Abrir em nova aba ↗
                        </a>
                    </div>

                    <!-- Área de Exibição do Preview -->
                    <div class="relative w-full h-[450px] bg-black/50 border border-gray-800 rounded-md overflow-hidden flex items-center justify-center">
                        <!-- Elemento de Loading (Tailwind) -->
                        <div id="espelho-loading" class="hidden absolute flex flex-col items-center gap-2 text-gray-400 text-xs">
                            <div class="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                            <span>Renderizando preview do alvo...</span>
                        </div>

                        <!-- Tag de Imagem que recebe o Render -->
                        <img
                            id="img-espelho-preview"
                            src=""
                            alt="Preview do Espelho"
                            class="hidden w-full h-full object-contain"
                        />

                        <!-- Placeholder Inicial -->
                        <span id="espelho-placeholder" class="text-gray-500 text-xs">
                            Aguardando execução do teste para carregar o espelho.
                        </span>
                    </div>
                </div>

                <div class="sec-wrapper">
                    <h2>🛡️ Diagnóstico de Segurança (DAST - OWASP)</h2>
                    <div class="sec-list" id="secList"></div>
                </div>

                <div class="percentiles-wrapper">
                    <h2>Distribuição Estatística de Latência</h2>
                    <table class="percentile-table">
                        <thead>
                            <tr>
                                <th>p50 (Mediana)</th>
                                <th>p75</th>
                                <th>p90</th>
                                <th>p95</th>
                                <th>p99 (Pico)</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td id="p50">0 ms</td>
                                <td id="p75">0 ms</td>
                                <td id="p90">0 ms</td>
                                <td id="p95">0 ms</td>
                                <td id="p99">0 ms</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="charts-grid">
                    <div class="chart-card">
                        <h2>Linha do Tempo de Latência (ms)</h2>
                        <canvas id="scatterChart"></canvas>
                    </div>
                    <div class="chart-card">
                        <h2>Status HTTP & Respostas</h2>
                        <canvas id="pieChart"></canvas>
                    </div>
                </div>

                <div class="diag-wrapper">
                    <h2>📋 Diagnóstico de Performance & Infraestrutura</h2>
                    <ul class="diag-list" id="diagList"></ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        let scatterChartInstance = null;
        let pieChartInstance = null;

        document.getElementById('suiteForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const btn = document.getElementById('btnExecute');
            const placeholder = document.getElementById('placeholder');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');

            btn.disabled = true;
            placeholder.style.display = 'none';
            results.style.display = 'none';
            loading.style.display = 'block';

            const formData = new FormData(e.target);
            atualizarEspelho(formData.get('url'));

            try {
                const response = await fetch('/run-test', { method: 'POST', body: formData });
                if (!response.ok) {
                    let detail = `HTTP Error ${response.status}`;
                    try {
                        const errorData = await response.json();
                        detail = errorData.detail || detail;
                    } catch (_) {
                        // Mantém o status HTTP quando a resposta não for JSON.
                    }
                    throw new Error(detail);
                }

                const data = await response.json();

                // Renderiza o Screenshot se capturado
                const previewWrapper = document.getElementById('previewWrapper');
                const imgTag = document.getElementById('appScreenshot');
                if (data.screenshot) {
                    imgTag.src = `data:image/png;base64,${data.screenshot}`;
                    previewWrapper.style.display = 'block';
                } else {
                    previewWrapper.style.display = 'none';
                }

                // Métricas
                document.getElementById('cardApdex').innerText = data.apdex_score;
                document.getElementById('cardSlaMeta').innerText = `Meta SLA: <= ${data.target_sla_ms}ms`;
                document.getElementById('cardRps').innerText = data.rps;
                document.getElementById('cardAvg').innerText = data.media_ms + ' ms';
                document.getElementById('cardDesvio').innerText = `Desvio: ±${data.desvio_padrao_ms} ms`;

                // Vulnerabilidades
                const vulns = data.vulnerabilidades || [];
                document.getElementById('cardVulnCount').innerText = vulns.length;
                const altas = vulns.filter(v => v.severidade === 'ALTO').length;
                document.getElementById('cardVulnSub').innerText = `${altas} de Severidade Alta`;

                const secList = document.getElementById('secList');
                secList.innerHTML = '';
                if (vulns.length === 0) {
                    secList.innerHTML = '<div style="color: var(--success); font-size: 0.9rem;">🟢 Nenhuma vulnerabilidade básica encontrada nos testes automatizados.</div>';
                } else {
                    vulns.forEach(v => {
                        const div = document.createElement('div');
                        div.className = `sec-item ${v.severidade}`;
                        div.innerHTML = `
                            <div class="sec-header">
                                <span class="sec-title">${v.titulo}</span>
                                <span class="sec-badge ${v.severidade}">${v.severidade}</span>
                            </div>
                            <div class="sec-desc">${v.descricao}</div>
                        `;
                        secList.appendChild(div);
                    });
                }

                // Percentis
                document.getElementById('p50').innerText = data.p50 + ' ms';
                document.getElementById('p75').innerText = data.p75 + ' ms';
                document.getElementById('p90').innerText = data.p90 + ' ms';
                document.getElementById('p95').innerText = data.p95 + ' ms';
                document.getElementById('p99').innerText = data.p99 + ' ms';

                document.getElementById('resTimestamp').innerText = `Executado em: ${new Date().toLocaleString('pt-BR')}`;
                if (data.pdf_report_path) {
                    document.getElementById('reportLink').href = `/reports/file/${encodeURIComponent(data.pdf_report_path.split('/').pop())}`;
                }

                // Diagnósticos
                const diagList = document.getElementById('diagList');
                diagList.innerHTML = '';
                data.diagnosticos.forEach(item => {
                    const li = document.createElement('li');
                    li.className = 'diag-item';
                    li.innerHTML = item.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
                    diagList.appendChild(li);
                });

                renderScatterChart(data.series_tempo);
                renderPieChart(data.status_codes, data.erros_detalhados);

                loading.style.display = 'none';
                results.style.display = 'flex';

            } catch (err) {
                alert('Erro na execução da suíte: ' + err.message);
                loading.style.display = 'none';
                placeholder.style.display = 'block';
            } finally {
                btn.disabled = false;
            }
        });

        function atualizarEspelho(urlAlvo) {
            if (!urlAlvo) return;
            const imgElement = document.getElementById('img-espelho-preview');
            const loadingElement = document.getElementById('espelho-loading');
            const placeholderElement = document.getElementById('espelho-placeholder');
            const linkNovaAba = document.getElementById('btn-abrir-nova-aba');
            const endpointEspelho = `/espelho-live?url=${encodeURIComponent(urlAlvo)}&t=${new Date().getTime()}`;

            placeholderElement.classList.add('hidden');
            imgElement.classList.add('hidden');
            loadingElement.classList.remove('hidden');
            linkNovaAba.href = urlAlvo;
            imgElement.src = endpointEspelho;

            imgElement.onload = () => {
                loadingElement.classList.add('hidden');
                imgElement.classList.remove('hidden');
            };

            imgElement.onerror = () => {
                loadingElement.classList.add('hidden');
                placeholderElement.textContent = 'Falha ao carregar o espelho da URL.';
                placeholderElement.classList.remove('hidden');
            };
        }

        function renderScatterChart(series) {
            const ctx = document.getElementById('scatterChart').getContext('2d');
            if (scatterChartInstance) scatterChartInstance.destroy();

            const points = series.map(s => ({ x: s.time, y: s.latency, status: s.status }));

            scatterChartInstance = new Chart(ctx, {
                type: 'scatter',
                data: {
                    datasets: [{
                        label: 'Latência (ms)',
                        data: points,
                        backgroundColor: points.map(p => p.status >= 400 ? '#ef4444' : '#06b6d4'),
                        pointRadius: 3.5
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        x: { title: { display: true, text: 'Decorrido (s)', color: '#9ca3af' }, grid: { color: '#1f2937' }, ticks: { color: '#9ca3af' } },
                        y: { title: { display: true, text: 'Latência (ms)', color: '#9ca3af' }, grid: { color: '#1f2937' }, ticks: { color: '#9ca3af' } }
                    },
                    plugins: { legend: { labels: { color: '#9ca3af' } } }
                }
            });
        }

        function renderPieChart(statusCodes, erros) {
            const ctx = document.getElementById('pieChart').getContext('2d');
            if (pieChartInstance) pieChartInstance.destroy();

            const labels = [];
            const dataValues = [];
            const backgroundColors = [];

            Object.keys(statusCodes).forEach(code => {
                labels.push(`HTTP ${code}`);
                dataValues.push(statusCodes[code]);
                backgroundColors.push(code.startsWith('2') ? '#10b981' : code.startsWith('3') ? '#f59e0b' : '#ef4444');
            });

            if (erros.timeout > 0) { labels.push('Timeout'); dataValues.push(erros.timeout); backgroundColors.push('#b91c1c'); }

            pieChartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{ data: dataValues, backgroundColor: backgroundColors, borderColor: '#111827' }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af' } } }
                }
            });
        }
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------
# ROTAS API FASTAPI
# ---------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(content=HTML_TEMPLATE)


@app.get("/espelho-live")
async def espelhar_site_live(url: str = Query(...)):
    """Renderiza a aplicação alvo via Playwright e retorna a imagem PNG."""
    if not url.startswith("http"):
        url = f"https://{url}"
    try:
        imagem_base64 = await capturar_screenshot(url, motor="playwright")
        if not imagem_base64:
            raise RuntimeError("Não foi possível capturar a imagem da URL.")
        return Response(
            content=base64.b64decode(imagem_base64),
            media_type="image/png",
        )
    except Exception as exc:
        return HTMLResponse(
            content=f"<div style='color:#EF4444;padding:20px;font-family:sans-serif;'>Erro ao espelhar URL: {escape(str(exc))}</div>",
            status_code=500,
        )


@app.post("/run-test")
async def run_test(
    url: str = Form(...),
    method: str = Form("GET"),
    requests: int = Form(...),
    concurrency: int = Form(...),
    timeout_sec: float = Form(5.0),
    target_sla_ms: float = Form(500.0),
    run_sec_scan: Optional[str] = Form(None),
    ramp_up: Optional[str] = Form(None),
    cache_buster: Optional[str] = Form(None),
    confirm_high_load: Optional[str] = Form(None),
    run_selenium: Optional[str] = Form(None),
    user_agent: Optional[str] = Form(""),
    custom_headers: Optional[str] = Form(""),
    payload: Optional[str] = Form("")
):
    if requests < 1 or requests > 50000:
        return JSONResponse({"detail": "O total de requisições deve estar entre 1 e 50.000."}, status_code=400)
    if requests > 10000 and not confirm_high_load:
        return JSONResponse({"detail": "Carga acima de 10.000 requer confirmação de autorização."}, status_code=400)
    concurrency = max(1, min(concurrency, 500))
    resultado = await executar_suite_completa(
        url=url,
        method=method,
        total_requests=requests,
        concurrency=concurrency,
        timeout_sec=timeout_sec,
        ramp_up=bool(ramp_up),
        cache_buster=bool(cache_buster),
        user_agent=user_agent or "",
        target_sla_ms=target_sla_ms,
        run_sec_scan=bool(run_sec_scan),
        custom_headers_str=custom_headers or "",
        payload_str=payload or ""
    )
    if run_selenium:
        resultado["selenium"] = await asyncio.to_thread(diagnosticar_com_selenium, url, timeout_sec)
    report_path = gerar_relatorio_evidencia(resultado, url, method)
    pdf_report_path = gerar_relatorio_pdf(resultado, url, method)
    resultado["report_path"] = str(report_path)
    resultado["pdf_report_path"] = str(pdf_report_path)
    return resultado


@app.post("/diagnostico")
async def rodar_diagnostico(url: str = Form(...), motor: str = Form("playwright")):
    try:
        resultado = await executar_diagnostico(url, mecanic=motor)
        return JSONResponse(content=resultado)
    except Exception as exc:
        return JSONResponse(status_code=500, content={"erro": str(exc)})


@app.post("/screenshot")
async def gerar_screenshot(url: str = Form(...), motor: str = Form("playwright")):
    try:
        bytes_img = await capturar_screenshot_bytes(url, motor=motor)
        diagnostico = diagnosticar_imagem(bytes_img)
        return JSONResponse(content={
            "status": "sucesso",
            "motor_utilizado": motor,
            "diagnostico_imagem": diagnostico,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"erro": str(exc)})


@app.post("/gerar-evidencia")
async def gerar_evidencia_completa(url: str = Form(...), motor: str = Form("playwright")):
    nome_pdf = f"evidencia_{int(time.time())}.pdf"
    try:
        dados_diag = await executar_diagnostico(url, mecanic=motor)
        bytes_img = await capturar_screenshot_bytes(url, motor=motor)
        gerar_relatorio_pdf_evidencia(
            dados_diag,
            bytes_imagem=bytes_img,
            caminho_saida=nome_pdf,
        )
        return FileResponse(
            path=nome_pdf,
            filename=nome_pdf,
            media_type="application/pdf",
        )
    except Exception as exc:
        return JSONResponse(status_code=500, content={"erro": str(exc)})


@app.get("/reports")
async def report_index():
    files = sorted(Path("reports").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    payload = [{"name": p.name, "path": str(p), "size": p.stat().st_size} for p in files[:20]]
    return JSONResponse(payload)


@app.get("/reports/latest")
async def latest_report():
    report_path = Path("reports/latest_report.json")
    if not report_path.exists():
        return JSONResponse({"message": "Nenhum relatório disponível."}, status_code=404)
    return JSONResponse(json.loads(report_path.read_text(encoding="utf-8")))


@app.get("/reports/file/{filename}")
async def report_file(filename: str):
    report_path = Path("reports") / filename
    if report_path.parent != Path("reports") or not report_path.is_file() or report_path.suffix.lower() != ".pdf":
        return JSONResponse({"message": "Relatório PDF não encontrado."}, status_code=404)
    return FileResponse(report_path, media_type="application/pdf", filename=report_path.name)


if __name__ == "__main__":
    uvicorn.run("Spectrum:app", host="127.0.0.1", port=8000, reload=True)