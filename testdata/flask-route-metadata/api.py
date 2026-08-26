"""`@router.get` on a FastAPI APIRouter is not Flask.

The framework was being picked once per FILE, from whatever the file imported, so four
FastAPI routes in a JupyterHub example were labelled `flask`. The decorator's RECEIVER is
what says which framework a registration belongs to, and a file is free to hold two.
"""
import os

from fastapi import APIRouter

# The prefix arrives from the environment and is normalised before use. Its default is
# what every unconfigured deployment serves.
router = APIRouter(prefix=os.getenv("API_PREFIX", "/api/v1/").rstrip("/"))


@router.get("/items")
async def list_items():
    return []


@router.post("/items")
async def create_item(name: str):
    return {"name": name}
