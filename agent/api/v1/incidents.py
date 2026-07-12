from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from agent.persistence.database import get_db
from sqlalchemy.orm import Session
from agent.persistence.repositories import IncidentRepository, AuditEventRepository
from agent.persistence.lifecycle import IncidentLifecycle

router = APIRouter(prefix="/incidents", tags=["incidents"])

class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    incident_type: str
    severity: str
    status: str
    confidence: float

class StatusUpdateRequest(BaseModel):
    status: str
    actor: str = "api_user"
    details: Optional[dict] = None

@router.get("/", response_model=List[IncidentResponse])
def list_incidents(status: Optional[str] = None, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    repo = IncidentRepository(db)
    if status:
        incidents = repo.get_by_status(status)
    else:
        incidents = repo.list(skip=skip, limit=limit)
    
    return [
        IncidentResponse(
            incident_id=i.incident_id,
            title=i.title,
            incident_type=i.incident_type,
            severity=i.severity,
            status=i.status,
            confidence=i.confidence
        ) for i in incidents
    ]

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    repo = IncidentRepository(db)
    incident = repo.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    return IncidentResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        incident_type=incident.incident_type,
        severity=incident.severity,
        status=incident.status,
        confidence=incident.confidence
    )

@router.patch("/{incident_id}/status")
def update_status(incident_id: str, req: StatusUpdateRequest, db: Session = Depends(get_db)):
    repo = IncidentRepository(db)
    incident = repo.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    try:
        IncidentLifecycle.transition(incident, req.status, actor=req.actor, details=req.details)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
        
    return {"status": "success", "new_status": incident.status}

@router.get("/{incident_id}/timeline")
def get_timeline(incident_id: str, db: Session = Depends(get_db)):
    repo = AuditEventRepository(db)
    events = repo.get_by_incident(incident_id)
    
    return [
        {
            "id": e.id,
            "action": e.action,
            "old_status": e.old_status,
            "new_status": e.new_status,
            "actor": e.actor,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "details": e.details
        } for e in events
    ]
