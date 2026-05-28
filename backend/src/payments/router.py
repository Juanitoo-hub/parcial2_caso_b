from typing import Dict, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.auth.dependencies import require_player
from src.db import fetch_all, fetch_one, get_connection
from src.security_logger import log_security_event


router = APIRouter()


TOKEN_PACKAGES = {
    "basico": {"tokens": 10, "price_cop": 10000, "name": "Paquete Básico"},
    "estandar": {"tokens": 50, "price_cop": 45000, "name": "Paquete Estándar"},
    "premium": {"tokens": 120, "price_cop": 100000, "name": "Paquete Premium"},
}


APPROVED_CARDS = {
    "4111111111111111": {"brand": "visa", "status": "approved"},
    "5500000000000004": {"brand": "mastercard", "status": "approved"},
}

REJECTED_CARDS = {
    "4000000000000002": "fondos_insuficientes",
    "4000000000000069": "tarjeta_vencida",
}


class CardRegisterBody(BaseModel):
    card_number: str = Field(..., min_length=13, max_length=19)
    exp_month: int = Field(..., ge=1, le=12)
    exp_year: int = Field(..., ge=2026, le=2040)
    cvv: str = Field(..., min_length=3, max_length=4)


class TokenPurchaseBody(BaseModel):
    card_token: str = Field(..., min_length=20, max_length=255)
    package_code: str = Field(..., min_length=3, max_length=30)


class StorePurchaseBody(BaseModel):
    item_code: str = Field(..., min_length=3, max_length=80)


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def normalize_card_number(card_number: str) -> str:
    return "".join(char for char in card_number if char.isdigit())


def detect_card_brand(card_number: str) -> str:
    if card_number.startswith("4"):
        return "visa"
    if card_number.startswith("5"):
        return "mastercard"
    return "unknown"


@router.get("/packages")
def list_token_packages():
    return {
        "packages": [
            {
                "package_code": code,
                "name": package["name"],
                "tokens": package["tokens"],
                "price_cop": package["price_cop"],
            }
            for code, package in TOKEN_PACKAGES.items()
        ]
    }


@router.post("/cards", status_code=status.HTTP_201_CREATED)
def register_card(
    body: CardRegisterBody,
    request: Request,
    current_user: Dict = Depends(require_player),
):
    ip_address = get_client_ip(request)
    card_number = normalize_card_number(body.card_number)

    if card_number in REJECTED_CARDS:
        reason = REJECTED_CARDS[card_number]

        log_security_event(
            event_type="card_register_failed",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason=reason,
            extra={"last4": card_number[-4:]},
        )

        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Tarjeta rechazada: {reason}",
        )

    if card_number not in APPROVED_CARDS:
        log_security_event(
            event_type="card_register_failed",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="test_card_not_allowed",
            extra={"last4": card_number[-4:] if len(card_number) >= 4 else "0000"},
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Solo se aceptan tarjetas de prueba definidas para el caso",
        )

    brand = APPROVED_CARDS[card_number]["brand"]
    last4 = card_number[-4:]
    card_token = f"card_{uuid4().hex}"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO payment_cards
                (jugador_id, card_token, brand, last4, exp_month, exp_year)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, card_token, brand, last4, exp_month, exp_year, created_at
                """,
                (
                    current_user["id"],
                    card_token,
                    brand,
                    last4,
                    body.exp_month,
                    body.exp_year,
                ),
            )
            card = cur.fetchone()

    log_security_event(
        event_type="card_registered",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="simulated_card_tokenized",
        extra={"last4": last4, "brand": brand},
    )

    return {
        "message": "Tarjeta registrada y tokenizada correctamente",
        "card": {
            "card_token": card["card_token"],
            "brand": card["brand"],
            "last4": card["last4"],
            "exp_month": card["exp_month"],
            "exp_year": card["exp_year"],
            "created_at": card["created_at"],
        },
    }


@router.get("/cards")
def list_cards(current_user: Dict = Depends(require_player)):
    cards = fetch_all(
        """
        SELECT card_token, brand, last4, exp_month, exp_year, is_active, created_at
        FROM payment_cards
        WHERE jugador_id = %s
        ORDER BY created_at DESC
        """,
        (current_user["id"],),
    )

    return {"cards": cards}


@router.post("/tokens/purchase")
def purchase_tokens(
    body: TokenPurchaseBody,
    request: Request,
    current_user: Dict = Depends(require_player),
):
    ip_address = get_client_ip(request)
    package = TOKEN_PACKAGES.get(body.package_code)

    if not package:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Paquete no encontrado",
        )

    card = fetch_one(
        """
        SELECT id, card_token, brand, last4, is_active
        FROM payment_cards
        WHERE jugador_id = %s AND card_token = %s
        """,
        (current_user["id"], body.card_token),
    )

    if not card or not card["is_active"]:
        log_security_event(
            event_type="tokens_purchase_failed",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="invalid_card_token",
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tarjeta inválida o inactiva",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE jugadores
                SET tokens_balance = tokens_balance + %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING tokens_balance
                """,
                (package["tokens"], current_user["id"]),
            )
            balance = cur.fetchone()

            cur.execute(
                """
                INSERT INTO token_transactions
                (jugador_id, transaction_type, amount_tokens, amount_cop, status, reason)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, amount_tokens, amount_cop, status, created_at
                """,
                (
                    current_user["id"],
                    "purchase",
                    package["tokens"],
                    package["price_cop"],
                    "approved",
                    "simulated_purchase_approved",
                ),
            )
            transaction = cur.fetchone()

    log_security_event(
        event_type="tokens_purchased",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="simulated_purchase_approved",
        extra={
            "package_code": body.package_code,
            "tokens": package["tokens"],
            "price_cop": package["price_cop"],
            "last4": card["last4"],
        },
    )

    return {
        "message": "Compra de tokens aprobada",
        "transaction": transaction,
        "tokens_balance": balance["tokens_balance"],
    }


@router.get("/me/tokens")
def get_token_balance(current_user: Dict = Depends(require_player)):
    user = fetch_one(
        """
        SELECT id, nickname, email, tokens_balance
        FROM jugadores
        WHERE id = %s
        """,
        (current_user["id"],),
    )

    return {
        "nickname": user["nickname"],
        "email": user["email"],
        "tokens_balance": user["tokens_balance"],
    }


@router.get("/store/items")
def list_store_items():
    items = fetch_all(
        """
        SELECT item_code, name, description, price_tokens
        FROM store_items
        WHERE is_active = TRUE
        ORDER BY price_tokens ASC
        """
    )

    return {"items": items}


@router.post("/store/purchase")
def purchase_store_item(
    body: StorePurchaseBody,
    request: Request,
    current_user: Dict = Depends(require_player),
):
    ip_address = get_client_ip(request)

    item = fetch_one(
        """
        SELECT id, item_code, name, price_tokens, is_active
        FROM store_items
        WHERE item_code = %s
        """,
        (body.item_code,),
    )

    if not item or not item["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ítem no encontrado",
        )

    user = fetch_one(
        """
        SELECT id, tokens_balance
        FROM jugadores
        WHERE id = %s
        """,
        (current_user["id"],),
    )

    if user["tokens_balance"] < item["price_tokens"]:
        log_security_event(
            event_type="item_purchase_failed",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="insufficient_tokens",
            extra={
                "item_code": item["item_code"],
                "price_tokens": item["price_tokens"],
                "tokens_balance": user["tokens_balance"],
            },
        )

        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Tokens insuficientes",
        )

    already_owned = fetch_one(
        """
        SELECT id
        FROM player_items
        WHERE jugador_id = %s AND item_id = %s
        """,
        (current_user["id"], item["id"]),
    )

    if already_owned:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El jugador ya posee este ítem",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE jugadores
                SET tokens_balance = tokens_balance - %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING tokens_balance
                """,
                (item["price_tokens"], current_user["id"]),
            )
            balance = cur.fetchone()

            cur.execute(
                """
                INSERT INTO player_items (jugador_id, item_id)
                VALUES (%s, %s)
                RETURNING id, purchased_at
                """,
                (current_user["id"], item["id"]),
            )
            purchase = cur.fetchone()

            cur.execute(
                """
                INSERT INTO token_transactions
                (jugador_id, transaction_type, amount_tokens, amount_cop, status, reason)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    current_user["id"],
                    "spend",
                    item["price_tokens"],
                    0,
                    "approved",
                    "tokens_spent",
                ),
            )

    log_security_event(
        event_type="item_purchased",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="tokens_spent",
        extra={
            "item_code": item["item_code"],
            "tokens_spent": item["price_tokens"],
        },
    )

    return {
        "message": "Ítem comprado correctamente",
        "item": {
            "item_code": item["item_code"],
            "name": item["name"],
            "price_tokens": item["price_tokens"],
        },
        "purchase": purchase,
        "tokens_balance": balance["tokens_balance"],
    }