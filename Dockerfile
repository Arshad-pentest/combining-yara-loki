FROM python:3.11-slim

# ---------------- SYSTEM HARDENING ----------------
RUN useradd -m scanner

# Install system tools
RUN apt-get update && apt-get install -y \
    yara \
    loki \
    && rm -rf /var/lib/apt/lists/*

# ---------------- APP SETUP ----------------
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create required directories
RUN mkdir -p uploads reports yara_rules loki_iocs

# Drop privileges
RUN chown -R scanner:scanner /app
USER scanner

# Expose Flask port
EXPOSE 5000

# Run app
CMD ["python", "app.py"]
