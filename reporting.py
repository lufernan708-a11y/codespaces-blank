from io import BytesIO
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image as ReportImage
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def gerar_relatorio_pdf(
    dados_diagnostico: dict[str, Any],
    bytes_imagem: Optional[bytes] = None,
    caminho_saida: str = "relatorio_evidencia.pdf",
) -> str:
    documento = SimpleDocTemplate(
        caminho_saida,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    estilos = getSampleStyleSheet()
    titulo = ParagraphStyle(
        "TituloRelatorio",
        parent=estilos["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#1A365D"),
        spaceAfter=12,
    )
    elementos = [
        Paragraph("Relatório de Evidência e Segurança Web", titulo),
        Spacer(1, 0.1 * inch),
    ]
    tabela = Table([
        ["URL Analisada:", dados_diagnostico.get("url", "N/A")],
        ["Motor de Automação:", dados_diagnostico.get("motor", "N/A")],
        ["Status Code:", str(dados_diagnostico.get("status", "N/A"))],
        ["Tempo de Resposta:", f"{dados_diagnostico.get('tempo_resposta_s', 'N/A')} s"],
    ], colWidths=[2.0 * inch, 4.5 * inch])
    tabela.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EDF2F7")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#2D3748")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
    ]))
    elementos.extend([tabela, Spacer(1, 0.2 * inch)])
    if bytes_imagem:
        elementos.extend([
            Paragraph("<b>Captura de Tela:</b>", estilos["Normal"]),
            Spacer(1, 0.1 * inch),
        ])
        imagem = ReportImage(BytesIO(bytes_imagem))
        largura_maxima = 6.5 * inch
        proporcao = largura_maxima / float(imagem.drawWidth)
        imagem.drawWidth = largura_maxima
        imagem.drawHeight = float(imagem.drawHeight) * proporcao
        elementos.append(imagem)
    documento.build(elementos)
    return caminho_saida
