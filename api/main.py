"""FastAPI application factory for MemDiver."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from memdiver.api.config import get_settings
from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.api.dependencies import get_tool_session
from memdiver.api.security import ApiTokenAuthMiddleware, guard_notebook_websocket
from memdiver.api.services.artifact_store import ArtifactStore
from memdiver.api.services.oracle_registry import (
    init_oracle_registry,
    reset_oracle_registry,
)
from memdiver.api.services.progress_bus import ProgressBus
from memdiver.api.services.task_manager import (
    init_task_manager,
    reset_task_manager,
)

logger = logging.getLogger("memdiver.api.main")
_logger = logging.getLogger("memdiver.api")


def _capability_error_handler(request: Request, exc: CapabilityError) -> JSONResponse:
    """Translate a propagating :class:`CapabilityError` into an HTTP response.

    This is the API adapter's single global translation point: any core/app/
    service layer that raises the transport-agnostic ``CapabilityError`` gets a
    structured HTTP response here, so those layers never import ``fastapi``.
    Internal-category errors are logged with a traceback for diagnostics.
    """
    if exc.category is ErrorCategory.INTERNAL:
        _logger.exception("unhandled internal capability error: %s", exc.message)
    return JSONResponse(status_code=exc.status, content=exc.to_dict())


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup / shutdown lifecycle for the FastAPI app."""
    settings = get_settings()
    logger.info("MemDiver API starting on %s:%d", settings.host, settings.port)
    # NOTE: upload_dir is deliberately NOT created here. It is
    # configure-on-first-use (api/config.py) and may legitimately be None;
    # creating it at startup is what used to materialise a world-writable
    # /tmp/memdiver_uploads on every create_app(). The directory is now
    # created 0o700 on demand by api.dependencies.upload_dir_or_409.
    if settings.dataset_root:
        session = get_tool_session()
        # set_dataset now RAISES a CapabilityError for a missing root (it used to
        # return an ignored error dict). Keep startup resilient: a misconfigured
        # root must not abort the whole app — log and continue unset, exactly as
        # the old ignored-error-dict path did.
        try:
            session.set_dataset(settings.dataset_root)
        except CapabilityError as exc:
            logger.warning("Configured dataset_root not usable: %s", exc)

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
    from memdiver.app.reader_cache import shutdown_default_cache

    shutdown_default_cache()


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    # Logging is configured by ENTRYPOINTS, not as an import side-effect of
    # core. setup_logging() is idempotent (it never adds a duplicate handler),
    # so building the app more than once — as the test suite does — is safe.
    from memdiver.core.log import setup_logging

    setup_logging()
    settings = get_settings()

    app = FastAPI(
        title="MemDiver",
        description="Memory dump forensic analysis API",
        version="0.1.0",
        lifespan=_lifespan,
    )

    # Single global translation point for the transport-agnostic
    # CapabilityError: any propagating core/service error becomes a structured
    # HTTP response here, so those layers never raise fastapi.HTTPException.
    app.add_exception_handler(CapabilityError, _capability_error_handler)

    # --- Localhost trust model -------------------------------------------
    # MemDiver is a LOCAL forensic workbench: the API binds to 127.0.0.1 and
    # the operator deliberately points it at arbitrary local dump files. The
    # free-form dump/browse path parameters (inspect, analysis, and the
    # /api/path/browse + /api/path/info filesystem browser) are therefore NOT
    # sandboxed on purpose — restricting a user's freely chosen dump path would
    # break a core feature. The only path hardening applied is on filesystem
    # paths CONSTRUCTED from a client-supplied identifier (session / structure /
    # artifact names), which must stay inside their intended storage directory
    # so an identifier like "../../etc/passwd" cannot escape it.
    #
    # CORS: pairing a wildcard origin ("*") with allow_credentials=True is
    # rejected by browsers and unsafe (it would let any site make credentialed
    # requests), so any literal "*" is stripped from the configured origins and
    # we fall back to the localhost dev origin. allow_methods / allow_headers
    # are narrowed to exactly what the SPA sends (GET/POST/DELETE + the OPTIONS
    # preflight; Content-Type on JSON/upload bodies, Authorization/X-API-Key
    # when an API token is configured) instead of "*".
    cors_origins = [o for o in settings.cors_origins if o != "*"]
    if not cors_origins:
        cors_origins = ["http://localhost:5173"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # API token auth (Phase 2.5): a no-op unless MEMDIVER_API_TOKEN is set.
    # Protects every /api, /ws, and /notebook route; the health check, the
    # OpenAPI/docs endpoints, and the static frontend bundle stay exempt.
    # See api/security.py for the exemption rules and WebSocket handling.
    app.add_middleware(ApiTokenAuthMiddleware, settings=settings)

    @app.get("/health")
    def health() -> dict:
        """Liveness/readiness check. Always reachable, even with a token set."""
        return {"status": "ok"}

    from memdiver.api.routers import (
        algorithms,
        analysis,
        architect,
        consensus,
        dataset,
        docs,
        dumps,
        experiment,
        inspect,
        oracles,
        path,
        pcaps,
        pipeline,
        scan,
        sessions,
        settings as settings_router,
        structures,
        tasks,
    )

    app.include_router(dataset.router, prefix="/api/dataset", tags=["dataset"])
    app.include_router(analysis.router, prefix="/api/analysis", tags=["analysis"])
    app.include_router(algorithms.router, prefix="/api/algorithms", tags=["algorithms"])
    app.include_router(inspect.router, prefix="/api/inspect", tags=["inspect"])
    app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
    app.include_router(tasks.router, prefix="/api/tasks", tags=["tasks"])
    app.include_router(dumps.router, prefix="/api/dumps", tags=["dumps"])
    app.include_router(pcaps.router, prefix="/api/pcaps", tags=["pcaps"])
    app.include_router(path.router, prefix="/api/path", tags=["path"])
    app.include_router(structures.router, prefix="/api/structures", tags=["structures"])
    app.include_router(architect.router, prefix="/api/architect", tags=["architect"])
    app.include_router(consensus.router, prefix="/api/consensus", tags=["consensus"])
    app.include_router(oracles.router, prefix="/api/oracles", tags=["oracles"])
    app.include_router(pipeline.router, prefix="/api/pipeline", tags=["pipeline"])
    app.include_router(experiment.router, prefix="/api/experiment", tags=["experiment"])
    # D1 — running the rules MemDiver emits. A router of its own rather than a
    # route on ``architect`` (which is EXEMPT_ROUTERS'd as having no app-layer
    # producer) or on ``analysis`` (still on the legacy {"detail": ...} error
    # contract); see the note at the top of api/routers/scan.py.
    app.include_router(scan.router, prefix="/api/scan", tags=["scan"])
    app.include_router(
        settings_router.router, prefix="/api/settings", tags=["settings"]
    )
    # In-app documentation. Mounted under /api (NOT at /docs, which is
    # FastAPI's own Swagger UI) and therefore before the "/" StaticFiles
    # catch-all, and token-guarded exactly like its siblings.
    app.include_router(docs.router, prefix="/api/docs", tags=["docs"])

    from memdiver.api.ws.progress import router as ws_router

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
            # The notebook kernel runs live code over a WebSocket. The HTTP
            # auth middleware never sees websocket scope, so guard the WS at the
            # mount: when a token is configured, an unauthenticated notebook WS
            # is refused (see security.guard_notebook_websocket).
            marimo_app = guard_notebook_websocket(marimo_app, settings)
            app.mount("/notebook", marimo_app)

            # Starlette compiles a Mount as ``path + "/{path:path}"``, so the
            # mount above only matches "/notebook/..." -- never the bare
            # "/notebook". Without this route that bare path falls through to
            # the "/" StaticFiles catch-all registered below, which looks for a
            # file named "notebook" in the bundle and 404s. Router-level
            # redirect_slashes cannot save it either: it only runs when NO route
            # matched, and the catch-all always matches.
            #
            # Registered inside this branch on purpose: with no mount to land
            # on, redirecting would only trade one 404 for another.
            @app.get("/notebook", include_in_schema=False)
            def notebook_redirect() -> RedirectResponse:
                return RedirectResponse("/notebook/")

            _notebook_available = True
            logger.info("Marimo notebook mounted at /notebook/")
        else:
            _notebook_error = f"Notebook file not found: {notebook_path}"
    except ImportError:
        # Marimo is the one interface that is still opt-in, so this is the
        # only place a genuine "install the extra" hint is still correct.
        _notebook_error = missing_package_message("Marimo", extra="marimo")
        logger.info("Marimo not installed, /notebook not available")
    except Exception as exc:
        _notebook_error = str(exc)
        logger.warning("Failed to mount Marimo notebook: %s", exc)

    @app.get("/api/notebook/status")
    def notebook_status():
        return {"available": _notebook_available, "error": _notebook_error}

    # Serve the built React frontend if it exists. Resolution (including the
    # MEMDIVER_FRONTEND_DIST override for packaged/relocated deployments) lives
    # in api/frontend_build.py, which also owns the staleness check `memdiver
    # web` prints — the two must never disagree about which directory is being
    # served. Degrades safely via the .is_dir() guard below.
    from memdiver.api.frontend_build import frontend_dist_path

    frontend_dist = frontend_dist_path()

    # The bundle ships favicon.svg but no favicon.ico, and index.html points at
    # the logo. A browser still asks for /favicon.ico on any page that declares
    # no icon of its own (an error page, the Marimo mount), so answer it with
    # the SVG the bundle already has rather than logging a 404 every time.
    # Registered before the "/" catch-all below, which would otherwise take it.
    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> FileResponse:
        icon = frontend_dist / "favicon.svg"
        if not icon.is_file():
            raise HTTPException(status_code=404, detail="favicon not found")
        return FileResponse(icon, media_type="image/svg+xml")

    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app
