"""CLI entrypoint."""

from __future__ import annotations

import uvicorn

from pisigma_auth.config import get_settings


def main() -> None:
    settings = get_settings()
    if not settings.host:
        raise RuntimeError("AUTH_HOST is required to start the dev server")
    if settings.port is None:
        raise RuntimeError("AUTH_PORT is required to start the dev server")
    uvicorn.run(
        "pisigma_auth.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
