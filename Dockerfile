FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for pysha3
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Default: run all parts
CMD ["python", "main.py"]
