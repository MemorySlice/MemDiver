"""FastAPI application factory for MemDiver."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

from api.config import get_settings
from api.dependencies import get_tool_session
from api.services.artifact_store import ArtifactStore
from api.services.oracle_registry import (
    init_oracle_registry,
    reset_oracle_registry,
)
from api.services.progress_bus import ProgressBus
from api.services.task_manager import (
    init_task_manager,
    reset_task_manager,
)

logger = logging.getLogger("memdiver.api.main")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup / shutdown lifecycle for the FastAPI app."""
    settings = get_settings()
    logger.info("MemDiver API starting on %s:%d", settings.host, settings.port)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    if settings.dataset_root:
        session = get_tool_session()
        session.set_dataset(settings.dataset_root)

    # Phase 25 pipeline substrate: artifact store, progress bus, task
    # manager. The manager owns a spawn ProcessPoolExecutor and a single
    # long-lived mp.Manager, both allocated here so the lifetime matches
    # the FastAPI app.
    artifact_store = ArtifactStore(
        settings.task_root,
        max_total_bytes=settings.task_quota_bytes,
    )
    progress_bus = ProgressBus()
    task_manager = init_task_manager(
        task_root=settings.task_root,
        artifact_store=artifact_store,
        progress_bus=progress_bus,
        max_workers=settings.pipeline_max_workers,
    )
    examples_dir = Path(__file__).parent.parent / "docs" / "oracle" / "examples"
    init_oracle_registry(
        oracle_dir=settings.oracle_dir,
        examples_dir=examples_dir,
    )
    try:
        await task_manager.startup(asyncio.get_running_loop())
        logger.info(
            "TaskManager ready (task_root=%s, max_workers=%d)",
            settings.task_root, settings.pipeline_max_workers,
        )
    except Exception:  # pragma: no cover - defensive
        logger.exception("failed to start TaskManager; pipeline endpoints disabled")

    yield

    logger.info("MemDiver API shutting down")
    try:
        task_manager.shutdown()
    except Exception:  # pragma: no cover
        logger.exception("TaskManager shutdown raised")
    reset_task_manager()
    reset_oracle_registry()
    # Close every cached MslReader before the process exits so the live
    # mmaps and file descriptors are released cleanly. Cache entries still
    # in use (refcount > 0 on a concurrent request) are left for the
    # holder to close on release — same deferred-close contract used by
    # normal LRU eviction.
    from api.services.reader_cache import shutdown_default_cache

    shutdown_default_cache()


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="MemDiver",
        description="Memory dump forensic analysis API",
        version="0.1.0",
        lifespan=_lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    from api.routers import (
        analysis,
        architect,
        consensus,
        dataset,
        dumps,
        inspect,
        oracles,
        path,
        pipeline,
        sessions,
        structures,
        tasks,
    )

    app.include_router(dataset.router, prefix="/api/dataset", tags=["dataset"])
    app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
    app.include_router(inspect.router, prefix="/api/inspect", tags=["inspect"])
    app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
    app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"])
    app.include_router(dumps.router, prefix="/api/dumps", tags=["dumps"])
    app.include_router(path.router, prefix="/api/path", tags=["path"])
    app.include_router(structures.router, prefix="/api/structures", tags=["structures"])
    app.include_router(architect.router, prefix="/api/architect", tags=["architect"])
    app.include_router(consensus.router, prefix="/api/consensus", tags=["consensus"])
    app.include_router(oracles.router, prefix="/api/oracles", tags=["oracles"])
    app.include_router(pipeline.router, prefix="/api/pipeline", tags=["pipeline"])

    from api.ws.progress import router as ws_router

    app.include_router(ws_router)

    # Mount Marimo notebook at /notebook (before static files catch-all)
    _notebook_available = False
    _notebook_error: str | None = None
    try:
        import marimo

        notebook_path = str(Path(__file__).parent.parent / "run.py")
        if Path(notebook_path).is_file():
            marimo_app = (
                marimo.create_asgi_app(quiet=True, include_code=False)
                .with_app(path="", root=notebook_path)
                .build()
            )
            app.mount("/notebook", marimo_app)
            _notebook_available = True
            logger.info("Marimo notebook mounted at /notebook")
        else:
            _notebook_error = f"Notebook file not found: {notebook_path}"
    except ImportError:
        _notebook_error = "Marimo not installed. Install with: pip install marimo"
        logger.info("Marimo not installed, /notebook not available")
    except Exception as exc:
        _notebook_error = str(exc)
        logger.warning("Failed to mount Marimo notebook: %s", exc)

    @app.get("/api/notebook/status")
    def notebook_status():
        return {"available": _notebook_available, "error": _notebook_error}

    # Serve built React frontend if dist/ exists
    frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app
