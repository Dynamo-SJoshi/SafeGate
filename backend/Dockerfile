FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install basic system build tools and scanning engines
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libimage-exiftool-perl \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the backend code
COPY . .

# Expose backend port
EXPOSE 8000

# Start server, listening on all interfaces (0.0.0.0)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
