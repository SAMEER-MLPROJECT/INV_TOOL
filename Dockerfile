# ---- build the web UI ------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- runtime ---------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ backend/
COPY data/sample/ data/sample/
COPY scripts/generate_sample_data.py scripts/
COPY --from=ui /ui/dist frontend/dist
RUN useradd --create-home --uid 10001 agl && mkdir -p data/uploads data/exports && chown -R agl data
USER agl
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["python", "-m", "attackgraph", "serve", "--host", "0.0.0.0", "--port", "8000"]
