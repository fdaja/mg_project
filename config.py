import os
from urllib.parse import urlparse

# Parse DATABASE_URL from environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    parsed_url = urlparse(DATABASE_URL)
    DATABASE_CONFIG = {
        'host': parsed_url.hostname,
        'database': parsed_url.path[1:],  # Remove the leading slash
        'user': parsed_url.username,
        'password': parsed_url.password,
        'port': parsed_url.port,
    }
else:
    # Fallback to local settings (optional for local development)
    DATABASE_CONFIG = {
        'host': 'localhost',
        'database': 'mg_project',
        'user': 'postgres',
        'password': 'Daja2409',
        'port': 5432,
    }
