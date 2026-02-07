FROM python:3.11-slim

ENV POETRY_VERSION=1.7.1
RUN apt-get update && apt-get install -y curl && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt-get clean
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

COPY . .
RUN poetry install --no-interaction --no-ansi

ENTRYPOINT ["kuberef"]