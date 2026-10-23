"""FastAPI webhook API that receives Shuffle alerts and triggers responses."""

from __future__ import annotations

import secrets
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from soclab import __version__
from soclab.config import Settings, get_settings_optional
from soclab.exceptions import AlertMappingError
from soclab.normalizers.shuffle import map_shuffle_alert
from soclab.services.response import ResponseService, build_response_service

TOKEN_HEADER = "X-SOCLAB-TOKEN"


class HealthResponse(BaseModel):
    status: str
    stage: int
    version: str
    dry_run: bool
    adapter: str


class AlertDecisionResponse(BaseModel):
    """Decision returned to Shuffle. Never includes the webhook token."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    severity: str
    action: str
    requested_action: str
    target_ip: str | None = None
    executed: bool
    dry_run: bool
    duplicate: bool
    protected: bool
    adapter: str
    reason: str


def _check_token(settings: Settings, provided: str | None) -> None:
    expected = settings.webhook_token.get_secret_value()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="webhook token is not configured",
        )
    candidate = provided or ""
    if not secrets.compare_digest(
        candidate.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=401,
            detail=f"invalid or missing {TOKEN_HEADER} header",
        )


def create_app(
    *,
    settings: Settings | None = None,
    response_service: ResponseService | None = None,
) -> FastAPI:
    """Build the API. A caller may inject a service (tests, verification, demo)."""
    resolved = settings or get_settings_optional()
    service = response_service or build_response_service(resolved)

    app = FastAPI(
        title="SOC Lab SOAR API",
        version=__version__,
        description="Stage 3 webhook receiver: Shuffle -> SOC Lab -> firewall adapter.",
    )
    app.state.settings = resolved
    app.state.response_service = service

    def require_token(
        x_soclab_token: Annotated[str | None, Header(alias=TOKEN_HEADER)] = None,
    ) -> None:
        _check_token(resolved, x_soclab_token)

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            stage=3,
            version=__version__,
            dry_run=service.dry_run,
            adapter=service.adapter_name,
        )

    @app.get("/ready")
    def ready() -> JSONResponse:
        problems = service.readiness_problems()
        if not resolved.webhook_token.get_secret_value():
            problems.append("webhook token is not configured")
        if problems:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "problems": problems},
            )
        return JSONResponse(
            content={
                "status": "ready",
                "dry_run": service.dry_run,
                "adapter": service.adapter_name,
            }
        )

    @app.post(
        "/api/v1/alerts",
        response_model=AlertDecisionResponse,
        dependencies=[Depends(require_token)],
    )
    def ingest_alert(payload: Annotated[Any, Body(...)]) -> AlertDecisionResponse:
        try:
            alert = map_shuffle_alert(payload)
        except AlertMappingError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        outcome = service.handle(alert)
        return AlertDecisionResponse(
            alert_id=outcome.alert_id,
            severity=outcome.severity.value,
            action=outcome.action.value,
            requested_action=outcome.requested_action.value,
            target_ip=outcome.target_ip,
            executed=outcome.executed,
            dry_run=outcome.dry_run,
            duplicate=outcome.duplicate,
            protected=outcome.protected,
            adapter=outcome.adapter,
            reason=outcome.reason,
        )

    return app
