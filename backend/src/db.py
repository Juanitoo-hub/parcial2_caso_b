import psycopg2
import psycopg2.extras

from .settings import settings


def get_connection():
    return psycopg2.connect(
        settings.database_url,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def fetch_one(query: str, params: tuple = ()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()


def fetch_all(query: str, params: tuple = ()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()


def execute(query: str, params: tuple = ()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            try:
                return cur.fetchone()
            except psycopg2.ProgrammingError:
                return None


def execute_many(queries):
    with get_connection() as conn:
        with conn.cursor() as cur:
            result = None
            for query, params in queries:
                cur.execute(query, params)
                try:
                    result = cur.fetchone()
                except psycopg2.ProgrammingError:
                    result = None
            return result