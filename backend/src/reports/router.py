from datetime import datetime
from io import BytesIO
from typing import Dict, List

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.auth.dependencies import get_current_user, require_admin_or_moderator
from src.db import execute, fetch_all, fetch_one
from src.security_logger import log_security_event


router = APIRouter()


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def build_pdf(title: str, elements: List) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=title,
        rightMargin=40,
        leftMargin=40,
        topMargin=50,
        bottomMargin=40,
    )
    doc.build(elements)
    buffer.seek(0)
    return buffer


def pdf_response(buffer: BytesIO, filename: str) -> StreamingResponse:
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


def audit_pdf(
    current_user: Dict,
    target_player_id,
    report_type: str,
    ip_address: str,
):
    execute(
        """
        INSERT INTO pdf_audit_logs
        (generated_by, target_player_id, report_type, ip_address)
        VALUES (%s, %s, %s, %s)
        """,
        (
            current_user["id"],
            target_player_id,
            report_type,
            ip_address,
        ),
    )


@router.get("/me/profile")
def my_profile_pdf(
    request: Request,
    current_user: Dict = Depends(get_current_user),
):
    ip_address = get_client_ip(request)

    player = fetch_one(
        """
        SELECT id, nickname, email, role, tokens_balance, created_at, is_active
        FROM jugadores
        WHERE id = %s
        """,
        (current_user["id"],),
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Reporte de perfil del jugador", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("PixelForge Studio - Makoper", styles["Heading2"]))
    elements.append(Spacer(1, 12))

    table_data = [
        ["Campo", "Valor"],
        ["ID", str(player["id"])],
        ["Nickname", player["nickname"]],
        ["Email", player["email"]],
        ["Rol", player["role"]],
        ["Saldo de tokens", str(player["tokens_balance"])],
        ["Estado activo", str(player["is_active"])],
        ["Fecha de registro", str(player["created_at"])],
    ]

    table = Table(table_data, colWidths=[160, 320])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    elements.append(table)
    elements.append(Spacer(1, 16))
    elements.append(
        Paragraph(
            "Nota: este reporte no incluye contraseñas, hashes, CVV, números completos de tarjeta ni secretos MFA.",
            styles["Normal"],
        )
    )

    audit_pdf(current_user, player["id"], "player_profile", ip_address)

    log_security_event(
        event_type="pdf_generated",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="player_profile_pdf",
        extra={"report_type": "player_profile"},
    )

    buffer = build_pdf("Reporte de perfil", elements)
    return pdf_response(buffer, "perfil_jugador.pdf")


@router.get("/me/scores")
def my_scores_pdf(
    request: Request,
    current_user: Dict = Depends(get_current_user),
):
    ip_address = get_client_ip(request)

    scores = fetch_all(
        """
        SELECT id, score, level_reached, estado, created_at
        FROM puntuaciones
        WHERE jugador_id = %s
        ORDER BY created_at DESC
        LIMIT 100
        """,
        (current_user["id"],),
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Reporte de historial de puntuaciones", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Jugador: {current_user['nickname']}", styles["Heading2"]))
    elements.append(Spacer(1, 12))

    table_data = [["ID", "Score", "Nivel", "Estado", "Fecha"]]

    if scores:
        for row in scores:
            table_data.append(
                [
                    str(row["id"]),
                    str(row["score"]),
                    str(row["level_reached"]),
                    row["estado"],
                    str(row["created_at"]),
                ]
            )
    else:
        table_data.append(["-", "Sin puntuaciones", "-", "-", "-"])

    table = Table(table_data, colWidths=[45, 80, 70, 90, 220])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    elements.append(table)

    audit_pdf(current_user, current_user["id"], "player_scores", ip_address)

    log_security_event(
        event_type="pdf_generated",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="player_scores_pdf",
        extra={"report_type": "player_scores"},
    )

    buffer = build_pdf("Historial de puntuaciones", elements)
    return pdf_response(buffer, "historial_puntuaciones.pdf")


@router.get("/admin/global-stats")
def global_stats_pdf(
    request: Request,
    current_user: Dict = Depends(require_admin_or_moderator),
):
    ip_address = get_client_ip(request)

    totals = fetch_one(
        """
        SELECT
            (SELECT COUNT(*) FROM jugadores) AS total_players,
            (SELECT COUNT(*) FROM partidas) AS total_matches,
            (SELECT COUNT(*) FROM puntuaciones WHERE estado = 'valida') AS valid_scores,
            (SELECT COALESCE(MAX(score), 0) FROM puntuaciones WHERE estado = 'valida') AS best_score,
            (SELECT COUNT(*) FROM token_transactions WHERE status = 'approved') AS approved_transactions,
            (SELECT COALESCE(SUM(amount_tokens), 0)
             FROM token_transactions
             WHERE transaction_type = 'purchase' AND status = 'approved') AS purchased_tokens
        """
    )

    top_players = fetch_all(
        """
        SELECT j.nickname, MAX(p.score) AS best_score, MAX(p.level_reached) AS max_level
        FROM puntuaciones p
        JOIN jugadores j ON j.id = p.jugador_id
        WHERE p.estado = 'valida'
        GROUP BY j.id, j.nickname
        ORDER BY best_score DESC
        LIMIT 10
        """
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Reporte estadístico global", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("PixelForge Studio - Makoper", styles["Heading2"]))
    elements.append(Paragraph(f"Generado: {datetime.utcnow().isoformat()} UTC", styles["Normal"]))
    elements.append(Spacer(1, 12))

    summary_data = [
        ["Indicador", "Valor"],
        ["Jugadores registrados", str(totals["total_players"])],
        ["Partidas creadas", str(totals["total_matches"])],
        ["Puntuaciones válidas", str(totals["valid_scores"])],
        ["Mejor score", str(totals["best_score"])],
        ["Transacciones aprobadas", str(totals["approved_transactions"])],
        ["Tokens comprados", str(totals["purchased_tokens"])],
    ]

    summary_table = Table(summary_data, colWidths=[220, 220])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 18))
    elements.append(Paragraph("Top jugadores", styles["Heading2"]))

    top_data = [["Posición", "Nickname", "Mejor score", "Nivel máximo"]]

    if top_players:
        for index, row in enumerate(top_players, start=1):
            top_data.append(
                [
                    str(index),
                    row["nickname"],
                    str(row["best_score"]),
                    str(row["max_level"]),
                ]
            )
    else:
        top_data.append(["-", "Sin datos", "-", "-"])

    top_table = Table(top_data, colWidths=[70, 180, 120, 120])
    top_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )

    elements.append(top_table)

    audit_pdf(current_user, None, "global_stats", ip_address)

    log_security_event(
        event_type="pdf_generated",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="global_stats_pdf",
        extra={"report_type": "global_stats"},
    )

    buffer = build_pdf("Reporte estadístico global", elements)
    return pdf_response(buffer, "reporte_estadistico_global.pdf")