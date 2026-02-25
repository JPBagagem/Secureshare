FROM python:3.12-alpine

RUN apk add --no-cache bash build-base libffi-dev

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY . /app

WORKDIR /app

RUN uv sync --frozen --no-cache

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["/app/.venv/bin/uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "debug"]