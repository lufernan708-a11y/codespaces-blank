import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


REPORTS_DIR = Path("reports")


def _nome_relatorio(url: str, method: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"report_{method.lower()}_{timestamp}"


def gerar_relatorio_evidencia(resultado: dict[str, Any], url: str, method: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    caminho = REPORTS_DIR / f"{_nome_relatorio(url, method)}.json"
    documento = {"url": url, "method": method, "created_at": datetime.now(timezone.utc).isoformat(), "resultado": resultado}
    caminho.write_text(json.dumps(documento, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (REPORTS_DIR / "latest_report.json").write_text(caminho.read_text(encoding="utf-8"), encoding="utf-8")
    return caminho


def gerar_relatorio_pdf(resultado: dict[str, Any], url: str, method: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    caminho = REPORTS_DIR / f"{_nome_relatorio(url, method)}.pdf"
    documento = canvas.Canvas(str(caminho), pagesize=A4)
    largura, altura = A4
    documento.setFont("Helvetica-Bold", 16)
    documento.drawString(40, altura - 50, "Relatorio de diagnostico")
    documento.setFont("Helvetica", 10)
    linhas = [
        f"URL: {url}",
        f"Metodo: {method}",
        f"Requisicoes: {resultado.get('total_requests', 0)}",
        f"Sucessos: {resultado.get('sucessos', 0)} | Erros: {resultado.get('erros', 0)}",
        f"RPS: {resultado.get('rps', 0)}",
        f"Latencia media: {resultado.get('media_ms', 0)} ms",
        f"Apdex: {resultado.get('apdex_score', 0)}",
    ]
    y = altura - 80
    for linha in linhas:
        documento.drawString(40, y, linha[:120])
        y -= 18
    documento.save()
    return caminho
