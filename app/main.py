from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.config import CORS_ORIGINS
from app import routes
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

app.mount("/static", StaticFiles(directory=routes.STATIC_DIR), name="static")

@app.get("/")
def index():
    return FileResponse(routes.STATIC_DIR / "index.html")

app.include_router(routes_health.router, tags=["health"])
app.include_router(routes.router, prefix="/api", tags=["scan"])

