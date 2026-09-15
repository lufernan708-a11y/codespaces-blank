from typing import Any

import httpx


async def testar_vulnerabilidades(client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
    vulnerabilidades: list[dict[str, Any]] = []
    try:
        response = await client.get(url)
        headers = {nome.lower(): valor for nome, valor in response.headers.items()}
        recomendados = {
            "content-security-policy": "Content-Security-Policy",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "strict-transport-security": "Strict-Transport-Security",
        }
        ausentes = [nome for nome, cabecalho in recomendados.items() if nome not in headers]
        if ausentes:
            vulnerabilidades.append({
                "severidade": "BAIXO",
                "titulo": "Headers de seguranca ausentes",
                "descricao": "Headers ausentes: " + ", ".join(recomendados[nome] for nome in ausentes),
            })
        if url.lower().startswith("http://"):
            vulnerabilidades.append({
                "severidade": "MEDIO",
                "titulo": "Transporte sem HTTPS",
                "descricao": "O endpoint informado usa HTTP e nao protege o trafego em transito.",
            })
    except Exception as exc:
        vulnerabilidades.append({
            "severidade": "INFO",
            "titulo": "Falha na verificacao HTTP",
            "descricao": f"Nao foi possivel concluir a verificacao: {exc}",
        })
    return vulnerabilidades
