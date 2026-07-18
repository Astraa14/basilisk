FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY basilisk/ basilisk/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["basilisk"]
CMD ["--help"]
