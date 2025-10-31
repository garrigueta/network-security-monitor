FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir prometheus-client requests

# Copy the exporter script
COPY crypto_exporter.py /app/crypto_exporter.py

# Make it executable
RUN chmod +x /app/crypto_exporter.py

# Expose port
EXPOSE 9101

# Run the exporter
CMD ["python3", "/app/crypto_exporter.py"]
