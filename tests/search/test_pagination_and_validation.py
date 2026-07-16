from datetime import datetime, timedelta, timezone

from agent.persistence.orm_models import Incident
from tests.search.conftest import BASE_TIME


def add_tied_incidents(search_env, count=7):
    with search_env.session_factory() as session:
        session.add_all(
            Incident(
                incident_id=f"tie-{index:02d}",
                title=f"Tied {index}",
                incident_type="test",
                incident_family="test",
                status="new",
                severity="medium",
                confidence=0.5,
                first_seen=BASE_TIME,
                last_seen=BASE_TIME,
                created_at=BASE_TIME,
                primary_entity=f"192.0.2.{index + 1}",
            )
            for index in range(count)
        )
        session.commit()


def test_first_page_is_deterministic_with_stable_id_tie_breaker(search_env):
    add_tied_incidents(search_env)
    first = search_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 3}
    )
    second = search_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 3}
    )
    assert first.status_code == 200
    assert first.json() == second.json()
    assert [item["incident_id"] for item in first.json()["items"]] == [
        "tie-06",
        "tie-05",
        "tie-04",
    ]


def test_cursor_pages_are_non_overlapping_without_skips_or_duplicates(search_env):
    add_tied_incidents(search_env)
    seen = []
    cursor = None
    while True:
        params = {"page_size": 2}
        if cursor is not None:
            params["cursor"] = cursor
        response = search_env.client.get("/api/v1/search/incidents", params=params)
        assert response.status_code == 200, response.text
        document = response.json()
        page_ids = [item["incident_id"] for item in document["items"]]
        assert not set(page_ids) & set(seen)
        seen.extend(page_ids)
        if not document["has_more"]:
            assert document["next_cursor"] is None
            break
        assert document["next_cursor"]
        cursor = document["next_cursor"]
    assert seen == [f"tie-{index:02d}" for index in reversed(range(7))]


def test_tampered_cursor_is_rejected(search_env):
    add_tied_incidents(search_env)
    first = search_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 2}
    ).json()
    cursor = first["next_cursor"]
    tampered = f"{cursor[:-1]}{'A' if cursor[-1] != 'A' else 'B'}"
    response = search_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 2, "cursor": tampered}
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_search_cursor"


def test_overlong_cursor_is_rejected_as_safe_400(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents", params={"cursor": "x" * 2049}
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_search_cursor"


def test_cursor_from_different_resource_is_rejected(seeded_env):
    first = seeded_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 1}
    ).json()
    response = seeded_env.client.get(
        "/api/v1/search/events",
        params={"page_size": 1, "cursor": first["next_cursor"]},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_search_cursor"


def test_page_size_maximum_is_enforced(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 201}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "page_size_invalid"


def test_search_never_returns_more_than_configured_page_size(search_env):
    add_tied_incidents(search_env, count=205)
    response = search_env.client.get(
        "/api/v1/search/incidents", params={"page_size": 200}
    )
    assert response.status_code == 200
    assert len(response.json()["items"]) == 200
    assert response.json()["has_more"] is True


def test_invalid_date_range_is_rejected(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents",
        params={
            "created_at_from": datetime(2026, 2, 2, tzinfo=timezone.utc).isoformat(),
            "created_at_to": datetime(2026, 2, 1, tzinfo=timezone.utc).isoformat(),
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "created_at_range_invalid"


def test_naive_datetime_is_rejected(search_env):
    response = search_env.client.get(
        "/api/v1/search/events", params={"timestamp_from": "2026-01-01T12:00:00"}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "timezone_required"


def test_invalid_ip_is_rejected(search_env):
    response = search_env.client.get(
        "/api/v1/search/events", params={"src_ip": "999.2.3.4"}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_ip"


def test_invalid_severity_and_status_are_rejected(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents", params={"severity": "extreme"}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "severity_invalid"
    response = search_env.client.get(
        "/api/v1/search/jobs", params={"status": "unknown"}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "status_invalid"


def test_excessive_filter_list_is_rejected(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents",
        params=[("status", "new") for _ in range(21)],
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "status_too_many_values"


def test_empty_exact_filter_does_not_become_wildcard(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents", params={"primary_entity": ""}
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "primary_entity_empty"


def test_nullable_alternative_sort_paginates(search_env):
    with search_env.session_factory() as session:
        for index in range(3):
            session.add(
                Incident(
                    incident_id=f"nullable-{index}",
                    title="Nullable",
                    incident_type="test",
                    incident_family="test",
                    status="new",
                    severity="low",
                    confidence=0.2,
                    first_seen=BASE_TIME - timedelta(days=index),
                    last_seen=BASE_TIME,
                    created_at=BASE_TIME,
                    primary_entity=f"198.51.100.{index + 1}",
                )
            )
        session.commit()
    first = search_env.client.get(
        "/api/v1/search/incidents",
        params={"sort": "first_seen", "direction": "asc", "page_size": 2},
    ).json()
    second = search_env.client.get(
        "/api/v1/search/incidents",
        params={
            "sort": "first_seen",
            "direction": "asc",
            "page_size": 2,
            "cursor": first["next_cursor"],
        },
    ).json()
    assert len(first["items"] + second["items"]) == 3
