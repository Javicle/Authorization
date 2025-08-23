# Authorization Service (JWT)

Микросервис для выпуска и проверки JWT-токенов, хранения refresh-токенов и получения текущего пользователя. Построен на FastAPI, SQLAlchemy (async), JOSE и внутренних библиотеках OpenVerse.

## Возможности

- **Выпуск access-токена** по `login/password` (кука `access_token` c флагом HttpOnly).
- **Получение текущего пользователя** по токену из куки.
- **Получение текущего пользователя по «сырому» токену** (query-параметр).
- **Хранение refresh-токенов** (таблица `refresh_tokens`).
- **Готовность к трассировке** (Jaeger) и логированию.

## Архитектура и зависимости

- Веб-фреймворк: `FastAPI`
- JWT: `python-jose`
- ORM: `SQLAlchemy 2.x` (async, `asyncpg`)
- Сервер: `uvicorn`
- Внутренние пакеты:
  - `tools-openverse` — конфигурация, типы, логгер, HTTP-клиент к сервисам
  - `app-starter` — менеджер приложения и Jaeger

Ключевые модули:

- `src/main.py` — создание приложения, регистрация роутов, инициализация БД, Jaeger
- `src/delivery/route/jwt.py` — HTTP-маршруты
- `src/usecases/jwt.py` — бизнес-логика JWT
- `src/usecases/request.py` — запросы в сервис Users
- `src/infra/repository/db/*` — БД-слой (модели и репозиторий)
- `src/entity/jwt/*` — сущности/DTO/исключения домена JWT

## Требования

- Python 3.12+
- PostgreSQL (async драйвер `asyncpg`)
- Poetry (рекомендуется) или установка из `req.txt`

## Переменные окружения

Загружаются через `tools_openverse.common.config.settings`. Минимально необходимые:

- `PROJECT_NAME` — имя сервиса (используется при старте и трассировке)
- `BASE_URL` — host для запуска (например, `0.0.0.0`)
- `PORT_SERVICE_AUTH` — порт сервиса (например, `8080`)
- `JWT_SECRET_KEY` — секрет для подписи JWT
- `JWT_ALGORITHM` — алгоритм подписи JWT (например, `HS256`)
- `DATABASE_URL` — строка подключения к БД в формате SQLAlchemy (async):
  - пример: `postgresql+asyncpg://user:password@host:5432/dbname`

Опционально (если используется):

- `REDIS_URL` — адрес Redis (в коде подключение закомментировано)
- Переменные Jaeger (если требуются библиотекой `app-starter`), см. документацию пакета.

Пример `.env`:

```env
PROJECT_NAME=authorization_service
BASE_URL=0.0.0.0
PORT_SERVICE_AUTH=8080
JWT_SECRET_KEY=dev-secret-change-me
JWT_ALGORITHM=HS256
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/auth_db
```

## Установка и запуск (Poetry)

```bash
# 1) Установить Poetry (если не установлен)
# https://python-poetry.org/docs/

# 2) Создать .venv в каталоге проекта (poetry.toml уже настроен)
poetry install

# 3) Активировать виртуальное окружение и запустить
poetry run python src/main.py
```

После старта OpenAPI-документация будет доступна по адресу: `http://<BASE_URL>:<PORT_SERVICE_AUTH>/docs`.

Альтернатива (без Poetry):

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r req.txt
python src/main.py
```

## База данных и миграции

- Таблицы создаются автоматически при старте (см. `src/infra/repository/db/base.py::init_db`).
- Модель таблицы refresh-токенов: `src/infra/repository/db/models/refresh_token.py`:
  - Таблица: `refresh_tokens`
  - Поля: `id: UUID (PK)`, `user_id: UUID (PK)`, `refresh_token: str`, `expires_at: datetime`, `created_at`, `updated_at`

Примечание: в некоторых методах репозитория используются поля `expires_at` и/или `expiration`. Ориентируйтесь на актуальные имена столбцов в модели БД (`expires_at`).

## Взаимодействие с сервисом Users

`src/usecases/request.JwtRequest` ходит в сервис Users через общий клиент `tools_openverse.common.request.SetRequest` и перечисления `ServiceName.USERS`/`UsersRoutes`. Для успешной работы этот сервис должен быть доступен и корректно сконфигурирован в окружении `tools-openverse` (базовые URL, маршруты и т. п.).

## Маршруты API

Базовые роуты регистрируются в `src/delivery/route/jwt.py`.

### POST /auth/user/log_in

- Назначение: выпуск access-токена на 15 минут и установка куки `access_token` (HttpOnly).
- Тело запроса (JSON):
  ```json
  {
    "login": "user_login",
    "password": "secret"
  }
  ```
- Успешный ответ: `200 OK` и JSON `{ "message": "Login successful" }`, при этом в ответе будет установлена HttpOnly-кука `access_token` со значением `Bearer <JWT>`.

Примечание: модель формы определена как `LoginOAuth2PasswordRequestForm`. В текущей реализации данные читаются как тело запроса (JSON). При необходимости отправки `application/x-www-form-urlencoded` можно адаптировать зависимость на `as_form()`.

### GET /auth/user/info

- Назначение: получить текущего пользователя по токену из куки `access_token`.
- Вход: кука `access_token=Bearer <JWT>`
- Ответ: `{"user": { ... }}` — динамическая модель пользователя, полученная из сервиса Users.
- Ошибки: `401 Unauthorized` (нет/невалидный токен), `404 Not Found` (пользователь не найден).

### GET /auth/user/raw_token

- Назначение: получить текущего пользователя по «сырому» токену без куки.
- Параметры: `raw_token=<JWT>` (query)
- Ответ: `{"user": { ... }}`

## Примеры запросов

С учетом `.env` из примера:

```bash
# Вход (получить куку access_token)
curl -X POST "http://localhost:8080/auth/user/log_in" \
     -H "Content-Type: application/json" \
     -d '{"login": "demo", "password": "demo"}' \
     -i

# Использование /auth/user/info с кукой из ответа выше
curl -X GET "http://localhost:8080/auth/user/info" \
     -H "Cookie: access_token=Bearer <JWT_ИЗ_КУКИ>"

# Получение пользователя по «сырому» токену
curl -X GET "http://localhost:8080/auth/user/raw_token?raw_token=<JWT>"
```

## Коды ошибок (основные)

- `400 Bad Request` — данные не переданы/некорректны (например, формат заголовка Authorization)
- `401 Unauthorized` — невалидные учетные данные/токен
- `404 Not Found` — пользователь не найден
- `500 Internal Server Error` — внутренняя ошибка сервиса

## Логирование и трассировка

- Логи: через `tools_openverse.setup_logger`, вывод в консоль/файлы согласно настройкам окружения.
- Трассировка: при старте включается `JaegerService` (см. `src/main.py`). Необходимые переменные читаются через `settings` (см. документацию `app-starter`).

## Структура проекта (сокр.)

```
authorization_service/
  src/
    delivery/route/jwt.py         # HTTP-роуты
    usecases/jwt.py               # Бизнес-логика JWT
    usecases/request.py           # Клиент к Users
    infra/repository/db/base.py   # Инициализация БД
    infra/repository/db/user.py   # Репозиторий refresh-токенов
    infra/repository/db/models/refresh_token.py  # Модель БД
    entity/jwt/ent.py             # Сущности JWT
    entity/jwt/dto.py             # DTO
    entity/jwt/exc.py             # Исключения домена
    main.py                       # Точка входа
```

## Разработка

- Форматирование: `black`, `isort`
- Линтинг: `flake8`, `pylint`
- Типизация: `mypy`

Команды (через Poetry):

```bash
poetry run black .
poetry run isort .
poetry run flake8
poetry run mypy
```

## Заметки и ограничения

- Сервис опирается на корректную работу внешнего сервиса Users. Без него выдача/проверка токена завершится ошибкой поиска пользователя.
- Поле `BASE_URL` используется как host при запуске Uvicorn. Для локальной разработки установите `BASE_URL=0.0.0.0` или `127.0.0.1`.
- Таблица `refresh_tokens` создается автоматически. Миграций Alembic нет — для продакшена рекомендуется добавить их.

## Лицензия

MIT или по договоренности владельца репозитория.
