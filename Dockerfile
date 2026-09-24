FROM python:3.12-slim

WORKDIR /app

# Install from the repository root so Render does not depend on
# backend/requirements.txt being addressable from the Docker context.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the complete application after dependencies are installed.
COPY . /app

ENV PYTHONUNBUFFERED=1
EXPOSE 10000

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
