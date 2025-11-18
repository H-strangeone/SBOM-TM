from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .models import Threat
from .storage import session_scope


def build_app() -> FastAPI:
    app = FastAPI(title="SBOM-TM API", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/threats", response_model=list[dict])
    def list_threats(project: str | None = None) -> list[dict]:
        with session_scope() as session:
            query = session.query(Threat)
            if project:
                query = query.filter(Threat.project == project)
            return [
                threat.hypothesis | {"threat_id": threat.id, "score": threat.score}
                for threat in query.all()
            ]

    @app.get("/threats/{threat_id}", response_model=dict)
    def get_threat(threat_id: int) -> dict:
        with session_scope() as session:
            threat = session.get(Threat, threat_id)
            if not threat:
                raise HTTPException(status_code=404, detail="Threat not found")
            return threat.hypothesis | {"threat_id": threat.id, "score": threat.score}

    return app
