# JWT S3 Proxy — проект с JWT-авторизацией для S3

---

## Содержание

1. [Что такое JWT и зачем он нужен](#1-что-такое-jwt-и-зачем-он-нужен)
2. [Архитектура проекта](#2-архитектура-проекта)
3. [Установка и запуск](#3-установка-и-запуск)
4. [Работа с API (curl)](#4-работа-с-api-curl)
5. [RBAC — роли и права](#5-rbac--роли-и-права)
6. [Как работает JWT в этом проекте](#6-как-работает-jwt-в-этом-проекте)
7. [Структура проекта](#7-структура-проекта)

---

## 1. Что такое JWT и зачем он нужен

### JSON Web Token (JWT)

JWT — это открытый стандарт (RFC 7519) для передачи утверждений (claims) между сторонами в виде JSON-объекта. Токен подписан и поэтому может быть проверен без обращения к серверу авторизации.

**Формат JWT:** `header.payload.signature` — три части, разделённые точкой, закодированные в Base64.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9    ← Header (алгоритм, тип)
.
eyJzdWIiOiJhZG1pbiIsInJvbGUi6ImFkbWluImlhdCI6MTc3NzYwNTU2NX0  ← Payload (данные)
.
WKN5EfhaK_uo4FaSwn3GQQtmPXSSI_8SR0Qrs9yWJJs    ← Signature (подпись)
```

**Header (заголовок):**
```json
{
  "alg": "HS256",    // Алгоритм подписи (HMAC-SHA256)
  "typ": "JWT"       // Тип токена
}
```

**Payload (данные):**
```json
{
  "sub": "admin",                // Subject — пользователь
  "role": "admin",               // Custom claim — роль
  "iat": 1777605565,             // Issued At — когда выдан (Unix timestamp)
  "exp": 1777609165,             // Expiration — срок действия
  "jti": "6177a596c4fd4ae0"      // JWT ID — уникальный идентификатор
}
```

**Signature (подпись):**
```
HMACSHA256(base64(header) + "." + base64(payload), secret_key)
```

### Почему JWT, а не статический токен

| Аспект | Статический Bearer | JWT |
|--------|-------------------|-----|
| **Срок действия** | Бессрочный (или меняется вручную) | Автоматический (`exp` claim) |
| **Данные о пользователе** | Нет (только строка) | Есть (`sub`, `role`, и любые claims) |
| **Проверка без БД** | Нужен доступ к списку токенов | Достаточно секретного ключа (self-contained) |
| **Роли / RBAC** | Нужен внешний механизм | Встроены в payload (`role` claim) |
| **Отзыв** | Просто удалить из списка | Нужен blacklist или короткий TTL |
| **Масштабируемость** | Централизованный список | Stateless — любая replicas может проверить |

### Сравнение типов авторизации

```
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│   Статический Bearer │  │        JWT           │  │   AWS S3 Signature  │
│                     │  │                     │  │                     │
│  Client → "secret1" │  │  Client → POST login│  │  Client подписывает │
│                     │  │  → получает JWT     │  │  каждый запрос      │
│  Server:            │  │                     │  │  AccessKey+Secret   │
│   "secret1" == cfg? │  │  Server:            │  │                     │
│                     │  │   verify_signature  │  │  Server:            │
│  + Простота         │  │   check exp         │  │   verify_signature  │
│  - Нет expiry       │  │   read claims       │  │                     │
│  - Нет данных о юзе│  │  + Self-contained   │  │  + Стандарт S3      │
│  - Небезопасно      │  │  + RBAC встроен     │  │  - Сложная подпись  │
│                     │  │  + Expiry автоматом │  │  - Per-request расчёт│
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘
```

---

## 2. Архитектура проекта

```
Namespace: jwt-s3-proxy
┌───────────────────────────────────────────────────────────────────┐
│                                                                   │
│  ┌──────────────────────┐         ┌──────────────────┐           │
│  │   jwt-s3-proxy       │         │     minio         │           │
│  │   (FastAPI)          │  HTTP   │   (S3 storage)    │           │
│  │                      │───────► │                   │           │
│  │   Endpoints:         │         │   :9000 API       │           │
│  │   POST /auth/token   │         │   :9001 Console   │           │
│  │   GET  /auth/me      │         │                   │           │
│  │   PUT  /upload/...   │         │   Bucket: demo    │           │
│  │   GET  /files/...    │         │   PVC: 2Gi        │           │
│  │   DEL  /delete/...   │         └──────────────────┘           │
│  │   GET  /list/...     │                                         │
│  │                      │                                         │
│  │   JWT проверка:      │  ┌──────────────────────┐              │
│  │   • подпись HS256    │  │  Secret:             │              │
│  │   • срок действия    │  │  jwt-s3-proxy-secret │              │
│  │   • роль → права     │  │  (jwt-secret)        │              │
│  └──────────────────────┘  └──────────────────────┘              │
└───────────────────────────────────────────────────────────────────┘
```

**Поток запроса:**

```
1. Клиент: POST /auth/token  {"username":"admin","password":"admin123"}
   Proxy: проверяет credentials → генерирует JWT (HS256 + secret)
   → Ответ: {"access_token": "eyJ...", "role": "admin", "expires_in": 3600}

2. Клиент: PUT /upload/demo/file.txt
   Заголовок: Authorization: Bearer eyJ...
   Proxy:
     a) Декодирует JWT → проверяет подпись (secret)
     b) Проверяет exp (не истёк ли?)
     c) Читает role="admin" → проверяет право "write"
     d) Проксирует запрос → MinIO: PUT /demo/file.txt
   → Ответ: {"status": "uploaded", "size": 123, "uploaded_by": "admin"}

3. Клиент: GET /files/demo/file.txt
   Заголовок: Authorization: Bearer eyJ...
   Proxy: JWT валиден → роль admin → право "read" → OK
   → Ответ: содержимое файла + заголовки X-Bucket, X-Key, X-Size
```

---

## 3. Установка и запуск

### 3.1 Предварительные требования

- Kubernetes-кластер (kind / minikube / EKS / GKE)
- kubectl
- Docker (для сборки образа)
- kind (если используется kind)

### 3.2 Создание namespace

```bash
kubectl create namespace jwt-s3-proxy
```

### 3.3 Деплой MinIO

```bash
kubectl apply -f minio.yaml
kubectl -n jwt-s3-proxy wait deployment minio \
  --for=condition=Available --timeout=120s
```

### 3.4 Создание бакета

```bash
kubectl exec -n jwt-s3-proxy deployment/minio -- sh -c "
  mc alias set local http://localhost:9000 minioadmin minioadmin123 && \
  mc mb local/demo && \
  mc anonymous set public local/demo
"
```

### 3.5 Сборка и деплой JWT Proxy

```bash
# Сборка Docker-образа
cd app
docker build -t jwt-s3-proxy:latest .

# Загрузка в kind (если используется kind)
kind load docker-image jwt-s3-proxy:latest --name flux-demo

# Деплой
kubectl apply -f ../proxy-deploy.yaml
kubectl -n jwt-s3-proxy wait deployment jwt-s3-proxy \
  --for=condition=Available --timeout=60s
```

### 3.6 Доступ с хоста

```bash
kubectl port-forward -n jwt-s3-proxy svc/jwt-s3-proxy 18000:8000
# Теперь API доступен на http://127.0.0.1:18000
```

---

## 4. Работа с API (curl)

### 4.1 Получить JWT-токен

```bash
# Авторизация как admin (полный доступ)
curl -s -X POST http://127.0.0.1:18000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Ответ:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc3NzYwNTU2NSwiZXhwIjoxNzc3NjA5MTY1LCJqdGkiOiI2MTc3YTU5NmM0ZmQ0YWUwIn0.WKN5EfhaK_uo4FaSwn3GQQtmPXSSI_8SR0Qrs9yWJJs",
  "token_type": "bearer",
  "expires_in": 3600,
  "role": "admin",
  "username": "admin"
}
```

Сохраняем токен:
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:18000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

### 4.2 Информация о текущем пользователе

```bash
curl -s http://127.0.0.1:18000/auth/me \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Ответ:
```json
{
  "username": "admin",
  "role": "admin",
  "issued_at": "2026-05-01T03:19:25+00:00",
  "expires_at": "2026-05-01T04:19:25+00:00",
  "jti": "6177a596c4fd4ae0"
}
```

### 4.3 Загрузить файл (Upload)

```bash
# Текстовый файл
curl -X PUT "http://127.0.0.1:18000/upload/demo/report.txt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  -d "Annual report 2026 - Q1 results"

# JSON-файл
curl -X PUT "http://127.0.0.1:18000/upload/demo/config.json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"app":"demo","version":"2.0"}'

# Бинарный файл
curl -X PUT "http://127.0.0.1:18000/upload/demo/archive.tar.gz" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/gzip" \
  --data-binary @archive.tar.gz
```

### 4.4 Скачать файл (Download)

```bash
# Скачать и вывести в stdout
curl "http://127.0.0.1:18000/files/demo/report.txt" \
  -H "Authorization: Bearer $TOKEN"
# → Annual report 2026 - Q1 results

# Скачать в файл
curl "http://127.0.0.1:18000/files/demo/config.json" \
  -H "Authorization: Bearer $TOKEN" \
  -o config.json
```

### 4.5 Список файлов в бакете

```bash
curl "http://127.0.0.1:18000/list/demo" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Ответ:
```json
{
  "bucket": "demo",
  "files": [
    {"key": "report.txt", "size": 33},
    {"key": "config.json", "size": 32}
  ],
  "count": 2,
  "requested_by": "admin"
}
```

### 4.6 Удалить файл

```bash
curl -X DELETE "http://127.0.0.1:18000/delete/demo/report.txt" \
  -H "Authorization: Bearer $TOKEN"
```

### 4.7 Попытка без авторизации → 403

```bash
curl -s "http://127.0.0.1:18000/list/demo"
# → {"detail":"Not authenticated"}  (HTTP 403)

curl -s "http://127.0.0.1:18000/list/demo" \
  -H "Authorization: Bearer invalid.token.here"
# → {"detail":"Invalid token: ..."}  (HTTP 401)
```

---

## 5. RBAC — роли и права

### Пользователи

| Username | Password | Роль | Права |
|----------|----------|------|-------|
| `admin` | `admin123` | admin | read, write, delete, list |
| `writer` | `writer123` | writer | read, write, list |
| `reader` | `reader123` | reader | read, list |

### Пример: reader не может писать

```bash
# Получить токен reader
READER_TOKEN=$(curl -s -X POST http://127.0.0.1:18000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"reader","password":"reader123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Попытка загрузить файл → 403 Forbidden
curl -X PUT "http://127.0.0.1:18000/upload/demo/hack.txt" \
  -H "Authorization: Bearer $READER_TOKEN" \
  -H "Content-Type: text/plain" \
  -d "unauthorized"
# → {"detail":"Permission denied: 'write' required (role=reader)"}

# Попытка удалить → 403 Forbidden
curl -X DELETE "http://127.0.0.1:18000/delete/demo/report.txt" \
  -H "Authorization: Bearer $READER_TOKEN"
# → {"detail":"Permission denied: 'delete' required (role=reader)"}

# Скачать — OK (reader имеет право read)
curl "http://127.0.0.1:18000/files/demo/report.txt" \
  -H "Authorization: Bearer $READER_TOKEN"
# → Содержимое файла
```

### Как добавлять новых пользователей

В коде `app.py` добавьте запись в словарь `USERS`:

```python
USERS = {
    "admin":  {"password": "admin123",  "role": "admin"},
    "writer": {"password": "writer123", "role": "writer"},
    "reader": {"password": "reader123", "role": "reader"},
    # Новый пользователь:
    "bob":    {"password": "bob123",    "role": "writer"},
}
```

Для добавления новой роли — добавьте запись в `ROLE_PERMISSIONS`:

```python
ROLE_PERMISSIONS = {
    "admin":    {"read", "write", "delete", "list"},
    "writer":   {"read", "write", "list"},
    "reader":   {"read", "list"},
    # Новая роль:
    "auditor":  {"read", "list"},        # то же что reader
}
```

---

## 6. Как работает JWT в этом проекте

### Жизненный цикл токена

```
                    POST /auth/token
                    {username, password}
                          │
                          ▼
                 ┌─────────────────┐
                 │ Проверка        │
                 │ credentials     │
                 │ USERS[username] │
                 │   .password ==  │
                 └────────┬────────┘
                          │ OK
                          ▼
                 ┌─────────────────┐
                 │ Создание JWT     │
                 │                 │
                 │ payload = {     │
                 │   sub: username │
                 │   role: role    │
                 │   iat: now      │
                 │   exp: now+60m  │
                 │   jti: random   │
                 │ }               │
                 │                 │
                 │ token = JWT     │
                 │   .encode(      │
                 │     payload,    │
                 │     SECRET,     │
                 │     HS256       │
                 │   )             │
                 └────────┬────────┘
                          │
                          ▼
              {"access_token": "eyJ...", "expires_in": 3600}


  Каждый последующий запрос:

  Authorization: Bearer eyJ...

         │
         ▼
  ┌──────────────────────────────┐
  │ get_current_user()           │
  │                              │
  │ 1. jwt.decode(token, SECRET, │
  │      algorithms=[HS256])     │
  │                              │
  │ 2. Если подпись неверна →    │
  │    401 Invalid token         │
  │                              │
  │ 3. Если exp < now →          │
  │    401 Token expired         │
  │                              │
  │ 4. Вернуть payload           │
  │    {sub, role, iat, exp, jti}│
  └──────────────┬───────────────┘
                 │
                 ▼
  ┌──────────────────────────────┐
  │ require_permission("write")  │
  │                              │
  │ role = user["role"]          │
  │ perms = ROLE_PERMISSIONS     │
  │          .get(role, set())   │
  │                              │
  │ if "write" not in perms →    │
  │    403 Permission denied     │
  │                              │
  │ else → OK, выполнить запрос  │
  └──────────────────────────────┘
```

### Стандартные JWT Claims

| Claim | Описание | Использование |
|-------|----------|---------------|
| `sub` (Subject) | Идентификатор пользователя | Логирование, audit |
| `iat` (Issued At) | Время выдачи токена | Вычисление возраста токена |
| `exp` (Expiration) | Время истечения | Автоматическая инвалидация |
| `jti` (JWT ID) | Уникальный ID токена | Blacklist (отзыв конкретного токена) |
| `role` (custom) | Роль пользователя | RBAC — проверка прав доступа |

### Безопасность (что нужно для production)

1. **Сменить JWT_SECRET** на криптостойкую строку (32+ символов)
2. **Хранить пароли в хэшированном виде** (bcrypt / argon2), не plaintext
3. **Использовать HTTPS** (TLS-сертификат, Ingress с TLS)
4. **Короткий TTL токена** (15-30 мин) + refresh token
5. **Хранить JWT_SECRET в Kubernetes Secret**, не в env напрямую
6. **Rate limiting** на `/auth/token` (защита от brute force)
7. **Blacklist токенов** через Redis при logout / компрометации

---

## 7. Структура проекта

```
jwt-s3-proxy/
├── app/
│   ├── app.py               # FastAPI приложение (JWT + S3 proxy)
│   ├── Dockerfile            # Docker-образ
│   └── requirements.txt      # Зависимости Python
├── minio.yaml                # MinIO deployment + PVC + Service
├── proxy-deploy.yaml         # Secret + Proxy Deployment + Service
└── README.md                 # Данная документация
```

### API Endpoints

| Метод | Endpoint | Auth | Описание |
|-------|----------|------|----------|
| `POST` | `/auth/token` | Нет | Получить JWT по username/password |
| `GET` | `/auth/me` | JWT | Информация о текущем пользователе |
| `PUT` | `/upload/{bucket}/{key}` | JWT (write) | Загрузить файл |
| `GET` | `/files/{bucket}/{key}` | JWT (read) | Скачать файл |
| `DELETE` | `/delete/{bucket}/{key}` | JWT (delete) | Удалить файл |
| `GET` | `/list/{bucket}` | JWT (list) | Список файлов |
| `GET` | `/health` | Нет | Health check |
