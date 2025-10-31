#!/usr/bin/env python3
"""
Cryptocurrency Price Exporter for Prometheus
Fetches prices from CoinGecko API and exposes them as Prometheus metrics
"""

import time
import requests
from prometheus_client import start_http_server, Gauge
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Prometheus gauge metric
crypto_price = Gauge('crypto_price_usd', 'Cryptocurrency price in USD', ['name'])

# Cryptocurrency IDs from CoinGecko
CRYPTO_IDS = ['bitcoin', 'ethereum', 'tron']

def fetch_crypto_prices():
    """Fetch cryptocurrency prices from CoinGecko API"""
    try:
        url = 'https://api.coingecko.com/api/v3/simple/price'
        params = {
            'ids': ','.join(CRYPTO_IDS),
            'vs_currencies': 'usd'
        }
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        logger.info(f"Successfully fetched prices: {data}")
        
        # Update Prometheus metrics
        for crypto_id in CRYPTO_IDS:
            if crypto_id in data and 'usd' in data[crypto_id]:
                price = data[crypto_id]['usd']
                crypto_price.labels(name=crypto_id).set(price)
                logger.debug(f"Updated {crypto_id}: ${price}")
        
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching crypto prices: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False

def main():
    """Main function to run the exporter"""
    port = 9101
    
    # Start Prometheus metrics server
    start_http_server(port)
    logger.info(f"Crypto price exporter started on port {port}")
    logger.info(f"Metrics available at http://localhost:{port}/metrics")
    
    # Fetch prices every 60 seconds
    while True:
        fetch_crypto_prices()
        time.sleep(60)

if __name__ == '__main__':
    main()
