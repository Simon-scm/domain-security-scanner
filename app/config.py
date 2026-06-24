import os
from dotenv import load_dotenv

load_dotenv()

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/scanner.db")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")