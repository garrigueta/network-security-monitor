FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY attack_simulator.py .
COPY config.yaml .

# Create results directory
RUN mkdir -p /app/results

# Run as non-root user
RUN useradd -m -u 1000 attacker && chown -R attacker:attacker /app
USER attacker

# Default command
CMD ["python", "attack_simulator.py"]
