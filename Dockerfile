FROM python:3.12.7-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY .kintsugi ./.kintsugi

RUN pip install --no-cache-dir --no-deps -e . && kintsugi init

ENTRYPOINT ["kintsugi", "mcp"]
