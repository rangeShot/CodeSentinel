FROM python:3.11-slim

# HF Spaces runs containers as user ID 1000
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# Install dependencies
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY --chown=user . .

# HF Spaces uses port 7860 by default
EXPOSE 7860

# Reads PORT / HOST / WORKERS from environment (HF Spaces sets PORT automatically)
CMD ["sh", "-c", "uvicorn environment:app --host ${HOST:-0.0.0.0} --port ${PORT:-7860} --workers ${WORKERS:-1}"]
