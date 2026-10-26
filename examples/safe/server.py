import os

REQUIRED = os.environ["SERVICE_ENDPOINT"]
OPTIONAL = os.getenv("LOG_LEVEL", "info")
