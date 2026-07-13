import pytest
import tempfile
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from server import app
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import Base, IngestionJob, Incident
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

# Create a file-backed DB for all idempotency tests to correctly simulate cross-thread blocking and parallel writes
# We create a new file-backed SQLite database for each test session to avoid WinError 32 issues
@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    def override_get_uow():
        uow = UnitOfWork(session_factory=TestingSessionLocal)
        yield uow
        
    app.dependency_overrides[from_api_deps := __import__('agent.api.deps', fromlist=['get_uow']).get_uow] = override_get_uow
    
    yield path, TestingSessionLocal
    
    app.dependency_overrides.clear()
    engine.dispose()
    os.remove(path)

@pytest.fixture
def api_client(temp_db):
    yield TestClient(app)

def create_temp_log(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path

def test_idempotency_exact_duplicate(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        with open(path, "rb") as f:
            res1 = api_client.post("/analyze/file", files={"file": f})
        assert res1.status_code == 200
        assert res1.json().get("reused") is False

        with open(path, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is True
        
        # Verify db counts
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 1
    finally:
        os.remove(path)

def test_idempotency_file_mutated(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content1 = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    log_content2 = '{"event_id": "2", "timestamp": "2023-10-10T10:00:00Z"}\n'
    
    path1 = create_temp_log(log_content1)
    path2 = create_temp_log(log_content2)
    
    try:
        with open(path1, "rb") as f:
            res1 = api_client.post("/analyze/file", files={"file": f})
        assert res1.status_code == 200
        
        with open(path2, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False
        
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 2
    finally:
        os.remove(path1)
        os.remove(path2)

def test_idempotency_pipeline_version(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        with open(path, "rb") as f:
            res1 = api_client.post("/analyze/file", files={"file": f})
        assert res1.status_code == 200
        
        # Override pipeline version
        with open(path, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f}, headers={"Pipeline-Version": "v2.0"})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False
        
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 2
    finally:
        os.remove(path)

def test_idempotency_cross_mode(api_client, temp_db):
    # Test POST /detect/file and then POST /analyze/file
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        with open(path, "rb") as f:
            res1 = api_client.post("/detect/file", files={"file": f})
        assert res1.status_code == 200
        assert res1.json().get("reused") is False
        
        with open(path, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False  # Because different mode
        
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 2
    finally:
        os.remove(path)

def test_idempotency_parallel_submission(api_client, temp_db):
    # Send 5 parallel requests for the exact same file
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z", "suspicious": true}\n'
    path = create_temp_log(log_content)
    
    barrier = threading.Barrier(5)
    
    def parallel_worker():
        barrier.wait()
        with open(path, "rb") as f:
            return api_client.post("/analyze/file", files={"file": f})
            
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(parallel_worker) for _ in range(5)]
            responses = [f.result() for f in futures]
            
        status_codes = [r.status_code for r in responses]
        reused_flags = [r.json().get("reused") for r in responses if r.status_code == 200]
        duplicate_errors = [r.status_code for r in responses if r.status_code == 409]
        
        # 1 should succeed with reused=False (or 200). Others should be 409 or reused=True if they arrived later.
        # Since they are completely parallel and fast, most will hit 409 Concurrent processing
        assert 200 in status_codes
        
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            # Only one job should be stored
            assert uow.session.query(IngestionJob).count() == 1
    finally:
        os.remove(path)

def test_idempotency_rollback_isolation(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        # Mock persist analysis to throw an exception
        with patch('agent.application.analysis_service.AnalysisService._persist_analysis') as mock_persist:
            mock_persist.side_effect = Exception("DB failure simulation")
            
            with pytest.raises(Exception, match="DB failure simulation"):
                with open(path, "rb") as f:
                    res1 = api_client.post("/analyze/file", files={"file": f})
            
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            # Job should be failed
            job = uow.session.query(IngestionJob).first()
            assert job is not None
            assert job.status == "failed"
            
        # Try again successfully
        with open(path, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
            
        assert res2.status_code == 200
        assert res2.json().get("reused") is False # It failed previously, so we run analysis again
        
        with uow:
            assert uow.session is not None
            # Job should now be completed
            job = uow.session.query(IngestionJob).first()
            assert job is not None
            assert job.status == "completed"
            assert job.reused_count == 1
    finally:
        os.remove(path)
