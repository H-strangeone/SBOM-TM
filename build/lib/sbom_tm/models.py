from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class ProjectScan(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    project: str = Field(index=True)
    sbom_path: str
    created_at: datetime = Field(default_factory=datetime.now, index=True)


class Component(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="projectscan.id", index=True)
    name: str
    version: Optional[str] = None
    purl: Optional[str] = Field(default=None, index=True)
    supplier: Optional[str] = None
    hashes: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    properties: Optional[dict] = Field(default=None, sa_column=Column(JSON))


class Vulnerability(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    component_id: Optional[int] = Field(foreign_key="component.id", index=True)
    cve: Optional[str] = Field(default=None, index=True)
    severity: Optional[str] = None
    cvss: Optional[float] = None
    exploit_maturity: Optional[str] = None
    published: Optional[str] = None
    raw: dict = Field(sa_column=Column(JSON))


class Threat(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    project: str = Field(index=True)
    scan_id: int = Field(foreign_key="projectscan.id", index=True)
    vulnerability_id: int = Field(foreign_key="vulnerability.id")
    rule_id: str
    score: float = Field(index=True)
    status: str = Field(default="open", index=True)
    hypothesis: dict = Field(sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.now, index=True)
