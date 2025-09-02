from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from config import logger, HOST, PORT
from routers import url_analysis_router, text_analysis_router
from models import HealthResponse
from datetime import datetime
import uvicorn
import signal
import sys
import asyncio

# Define lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CatchThePhish backend service...")
    logger.info(f"Starting server on {HOST}:{PORT}")
    yield
    logger.info("CatchThePhish backend service stopped")

# Initialize FastAPI app
app = FastAPI(
    title="CatchThePhish Backend",
    description="Backend service for CatchThePhish browser extension",
    lifespan=lifespan
)

# Add CORS middleware (for development, become stricter in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic health check endpoint to ensure the backend service is running
@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        services={
            "url_analysis": "healthy"
        },
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )

app.include_router(url_analysis_router)
app.include_router(text_analysis_router)

def run_app():
    config = uvicorn.Config(
        app=app,
        host=HOST,
        port=PORT,
        reload=False
    )
    server = uvicorn.Server(config)

    def handle_exit(signum, frame):
        logger.info("Received shutdown signal, stopping server...")
        asyncio.create_task(server.shutdown())
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        server.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt detected, stopping server...")
        sys.exit(0)

if __name__ == "__main__":
    run_app()