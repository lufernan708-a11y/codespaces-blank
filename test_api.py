import asyncio
import httpx

API_URL = "http://localhost:8000/gerar-evidencia"
URL_ALVO = "https://example.com"
MOTOR = "playwright"  # Pode alternar para "selenium"

async def testar_endpoint_evidencia():
    print(f"[*] Enviando requisição para {API_URL}...")
    print(f"[*] Alvo: {URL_ALVO} | Motor: {MOTOR}")
    
    # Define um timeout mais longo para permitir o tempo de renderização do navegador
    timeout = httpx.Timeout(60.0, connect=10.0)
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            # Envia os dados como Form (application/x-www-form-urlencoded)
            resposta = await client.post(
                API_URL,
                data={
                    "url": URL_ALVO,
                    "motor": MOTOR
                }
            )
            
            # Valida se a resposta HTTP foi 200 OK
            if resposta.status_code == 200:
                arquivo_saida = "resultado_teste.pdf"
                
                # Salva os bytes do PDF recebidos da API
                with open(arquivo_saida, "wb") as f:
                    f.write(resposta.content)
                    
                print(f"[✓] Sucesso! Relatório salvo em: {arquivo_saida}")
            else:
                print(f"[X] Erro na API (Status {resposta.status_code}): {resposta.text}")
                
        except httpx.RequestError as e:
            print(f"[X] Falha na comunicação com a API: {e}")

if __name__ == "__main__":
    asyncio.run(testar_endpoint_evidencia())