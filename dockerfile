FROM python:3.12-slim
WORKDIR /src

COPY pyproject.toml poetry.lock* ./

RUN poetry install --no-interaction --no-ansi --no-root --without dev

COPY . .

CMD ["poetry", "run", "python", "main.py"]