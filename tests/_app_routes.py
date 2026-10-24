"""Shared FastAPI route walk for tests that enumerate the app's endpoints.

A plain loop over ``app.routes`` is not enough on FastAPI versions that keep
each ``include_router`` call as a lazy ``_IncludedRouter`` entry: such a walk
stops at the top level and sees only a handful of routes. Every test that
needs the real endpoint list goes through :func:`iter_app_routes` instead.
"""

from __future__ import annotations


def iter_app_routes(app):
    """Yield ``(route, path, methods)`` for every endpoint on *app*, flattened.

    Newer FastAPI keeps each ``include_router`` call as one lazy
    ``_IncludedRouter`` entry in ``app.routes`` (prefix applied on the fly);
    its public ``fastapi.routing.iter_route_contexts`` expands those into one
    context per real endpoint with the prefixed path. Older FastAPI has no
    such helper because ``include_router`` already copied every route,
    prefix and all, straight into ``app.routes``.
    """
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:  # older FastAPI: app.routes is already flat
        for route in app.routes:
            yield route, getattr(route, "path", None), getattr(route, "methods", None)
        return
    for context in iter_route_contexts(app.routes):
        yield context.original_route, context.path, context.methods
