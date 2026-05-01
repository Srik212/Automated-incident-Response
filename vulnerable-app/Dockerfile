FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/logs /app/data
ENV LOG_DIR=/app/logs
ENV DATA_DIR=/app/data
COPY app.py .
EXPOSE 5000
ENV FLASK_DEBUG=1
ENV DATABASE_PATH=/app/data/securebank.db
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1
CMD ["python", "app.py"]