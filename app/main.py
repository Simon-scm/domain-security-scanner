from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import CORS_ORIGINS
from app import routes_scan
from app import routes_health



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Server running. Listening on port 8000")

app.include_router(routes_health.router, prefix="/api", tags=["health"])
app.include_router(routes_scan.router, prefix="/api", tags=["scan"])

