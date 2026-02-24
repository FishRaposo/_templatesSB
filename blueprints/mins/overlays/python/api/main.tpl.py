# Template: MINS Blueprint - API Main
# Stack: Python
# Purpose: FastAPI main entry point for MINS backend

"""
{{PROJECT_NAME}} - MINS Backend API

A minimal backend for MINS micro-SaaS applications.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="{{PROJECT_NAME}} API",
    description="MINS micro-SaaS backend",
    version="{{VERSION}}",
)

# CORS for mobile app access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "{{PROJECT_NAME}}"}


@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "{{PROJECT_NAME}}",
        "version": "{{VERSION}}",
        "type": "MINS micro-SaaS",
    }
