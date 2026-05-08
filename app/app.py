"""JWT-authenticated S3 Proxy.

Flow:
  1. POST /auth/token  → получить JWT (нужен username + password)
  2. Использовать JWT в заголовке Authorization: Bearer <jwt>
  3. Proxy проверяет подпись JWT, срок действия, роль (role)
  4. Проксирует запрос в MinIO (S3)
"""

import os
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from pydantic import BaseModel
import httpx

# ---------------------------------------------------------------------------
# Конфигурация из переменных окружения
# ---------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-s3-proxy-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

S3_ENDPOINT = os.getenv("S3_ENDPOINT", "http://minio.jwt-s3-proxy.svc.cluster.local:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin123")

# Пользователи: {username: {password, role}}
# В production — из БД / LDAP / Keycloak
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "writer": {"password": "writer123", "role": "writer"},
    "reader": {"password": "reader123", "role": "reader"},
}

# Права по ролям
ROLE_PERMISSIONS = {
    "admin":  {"read", "write", "delete", "list"},
    "writer": {"read", "write", "list"},
    "reader": {"read", "list"},
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("jwt-s3-proxy")

app = FastAPI(title="JWT S3 Proxy", version="1.0")
security = HTTPBearer()

# ---------------------------------------------------------------------------
# JWT утилиты
# ---------------------------------------------------------------------------

def create_token(username: str, role: str) -> str:
    """Создать JWT-токен."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,        # Subject — кто владелец токена
        "role": role,           # Роль — определяет права
        "iat": now,             # Issued At — когда выдан
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),  # Expiration — срок действия
        "jti": os.urandom(8).hex(),  # JWT ID — уникальный идентификатор токена
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Декодировать и проверить JWT-токен."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Извлечь и проверить пользователя из JWT."""
    return decode_token(credentials.credentials)


def require_permission(permission: str):
    """Dependency: проверить, что у пользователя есть указанное право."""
    def checker(user: dict = Depends(get_current_user)):
        role = user.get("role", "")
        perms = ROLE_PERMISSIONS.get(role, set())
        if permission not in perms:
            raise HTTPException(status_code=403, detail=f"Permission denied: '{permission}' required (role={role})")
        return user
    return checker


# ---------------------------------------------------------------------------
# HTTP-клиент для MinIO
# ---------------------------------------------------------------------------
s3_client = httpx.AsyncClient(
    base_url=S3_ENDPOINT,
    timeout=httpx.Timeout(30.0, connect=10.0),
)

# Для S3-авторизации (AWS Signature v4) используем простую inline-реализацию
# В production лучше boto3, но для демо достаточно direct proxy с public bucket


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    username: str


@app.post("/auth/token", response_model=TokenResponse, tags=["auth"])
def login(req: LoginRequest):
    """Получить JWT-токен по username/password.

    Возвращает JWT, который нужно передавать в заголовке:
        Authorization: Bearer <access_token>
    """
    user = USERS.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(req.username, user["role"])
    return TokenResponse(
        access_token=token,
        expires_in=JWT_EXPIRE_MINUTES * 60,
        role=user["role"],
        username=req.username,
    )


@app.get("/auth/me", tags=["auth"])
def whoami(user: dict = Depends(get_current_user)):
    """Показать информацию о текущем пользователе из JWT."""
    return {
        "username": user["sub"],
        "role": user["role"],
        "issued_at": datetime.fromtimestamp(user["iat"], tz=timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(user["exp"], tz=timezone.utc).isoformat(),
        "jti": user.get("jti"),
    }


# ---------------------------------------------------------------------------
# S3 Proxy endpoints
# ---------------------------------------------------------------------------

@app.get("/files/{bucket}/{path:path}", tags=["files"])
async def download_file(
    bucket: str,
    path: str,
    user: dict = Depends(require_permission("read")),
):
    """Скачать файл из S3."""
    url = f"/{bucket}/{path}"
    resp = await s3_client.get(url)
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"File not found: {bucket}/{path}")
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"S3 error: {resp.text[:200]}")

    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    return Response(
        content=resp.content,
        media_type=content_type,
        headers={
            "X-Bucket": bucket,
            "X-Key": path,
            "X-Size": str(len(resp.content)),
            "X-Requested-By": user["sub"],
        },
    )


@app.put("/upload/{bucket}/{path:path}", tags=["files"])
async def upload_file(
    bucket: str,
    path: str,
    request: Request,
    user: dict = Depends(require_permission("write")),
):
    """Загрузить файл в S3."""
    body = await request.body()
    url = f"/{bucket}/{path}"
    content_type = request.headers.get("Content-Type", "application/octet-stream")
    resp = await s3_client.put(url, content=body, headers={"Content-Type": content_type})
    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=f"S3 error: {resp.text[:200]}")

    return {
        "status": "uploaded",
        "bucket": bucket,
        "key": path,
        "size": len(body),
        "uploaded_by": user["sub"],
    }


@app.delete("/delete/{bucket}/{path:path}", tags=["files"])
async def delete_file(
    bucket: str,
    path: str,
    user: dict = Depends(require_permission("delete")),
):
    """Удалить файл из S3."""
    url = f"/{bucket}/{path}"
    resp = await s3_client.delete(url)
    if resp.status_code == 204 or resp.status_code == 200:
        return {"status": "deleted", "bucket": bucket, "key": path, "deleted_by": user["sub"]}
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"File not found: {bucket}/{path}")
    raise HTTPException(status_code=resp.status_code, detail=f"S3 error: {resp.text[:200]}")


@app.get("/list/{bucket}", tags=["files"])
async def list_bucket(
    bucket: str,
    user: dict = Depends(require_permission("list")),
):
    """Список файлов в бакете."""
    resp = await s3_client.get(f"/{bucket}")
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"S3 error: {resp.text[:200]}")

    # Парсим XML ответ S3 — простой вариант
    import re
    keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
    sizes = re.findall(r"<Size>(\d+)</Size>", resp.text)
    files = [{"key": k, "size": int(s)} for k, s in zip(keys, sizes)]
    return {"bucket": bucket, "files": files, "count": len(files), "requested_by": user["sub"]}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"])
async def health():
    """Health check (без авторизации)."""
    return {"status": "healthy"}
