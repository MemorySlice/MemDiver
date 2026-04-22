// Playwright's webServer config in playwright.config.ts owns backend/
// frontend lifecycle. This file is a placeholder for future helpers
// (e.g. custom fixtures that depend on servers being up).
export const BACKEND_PORT = process.env.BACKEND_PORT ?? "8091";
export const FRONTEND_PORT = process.env.FRONTEND_PORT ?? "5191";
export const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;
export const FRONTEND_URL = `http://127.0.0.1:${FRONTEND_PORT}`;
