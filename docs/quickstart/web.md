# Web UI quickstart

The default entry point serves the FastAPI backend with the React frontend bundle mounted at `/`.

```bash
memdiver          # equivalent to: memdiver web
memdiver web --port 8080
```

On first launch the session-landing page opens. Click **New session**, point the wizard at a dump directory, choose algorithms, and drop into the workspace.

## What you see

- **Main panel** — hex viewer with color-coded byte classification (key / structural / dynamic).
- **Sidebar** — tabs for bookmarks, dumps, format, structures, sessions, and import.
- **Bottom tabs** — analysis, results, strings, entropy, consensus, live-consensus, architect, experiment, convergence, verify-key, pipeline.
- **Detail panel** — neighborhood overlay, structure overlay, or result summary.

## Dataset layout expected by the wizard

See [](../file_formats/dataset_layout.md).

## API docs

Swagger UI at `/docs`, ReDoc at `/redoc`, OpenAPI JSON at `/openapi.json`. WebSocket task progress at `/ws/tasks/{task_id}`.
