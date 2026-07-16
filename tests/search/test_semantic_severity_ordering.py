from datetime import timedelta

from agent.persistence.orm_models import DetectionSignal, Incident
from tests.search.conftest import BASE_TIME


RISK_ORDER = ["none", "informational", "low", "medium", "high", "critical"]


def seed_incident_severities(search_env, severities=RISK_ORDER):
    with search_env.session_factory() as session:
        session.add_all(
            Incident(
                incident_id=f"incident-{severity}-{index}",
                title=f"{severity} incident",
                incident_type="severity_test",
                incident_family="test",
                status="new",
                severity=severity,
                confidence=0.5,
                first_seen=BASE_TIME - timedelta(minutes=index),
                last_seen=BASE_TIME,
                created_at=BASE_TIME,
                primary_entity=f"entity-{index}",
            )
            for index, severity in enumerate(severities)
        )
        session.commit()


def seed_signal_severities(search_env, severities=RISK_ORDER):
    with search_env.session_factory() as session:
        session.add_all(
            DetectionSignal(
                signal_id=f"signal-{severity}-{index}",
                rule_id=f"rule-{index}",
                rule_name=f"{severity} rule",
                signal_family="test",
                signal_type="severity_test",
                severity=severity,
                confidence=0.5,
                first_seen=BASE_TIME - timedelta(minutes=index),
                last_seen=BASE_TIME,
                created_at=BASE_TIME,
                suppressed=False,
            )
            for index, severity in enumerate(severities)
        )
        session.commit()


def severities(response):
    assert response.status_code == 200, response.text
    return [item["severity"] for item in response.json()["items"]]


def walk_pages(client, resource, id_field):
    seen = []
    cursor = None
    while True:
        params = {
            "sort": "severity",
            "direction": "asc",
            "page_size": 2,
        }
        if cursor is not None:
            params["cursor"] = cursor
        response = client.get(f"/api/v1/search/{resource}", params=params)
        assert response.status_code == 200, response.text
        document = response.json()
        seen.extend(item[id_field] for item in document["items"])
        if not document["has_more"]:
            return seen
        cursor = document["next_cursor"]


def test_incident_severity_ascending_uses_semantic_order(search_env):
    seed_incident_severities(search_env)
    response = search_env.client.get(
        "/api/v1/search/incidents",
        params={"sort": "severity", "direction": "asc"},
    )
    assert severities(response) == RISK_ORDER


def test_incident_severity_descending_uses_semantic_order(search_env):
    seed_incident_severities(search_env)
    response = search_env.client.get(
        "/api/v1/search/incidents",
        params={"sort": "severity", "direction": "desc"},
    )
    assert severities(response) == list(reversed(RISK_ORDER))


def test_signal_severity_ascending_uses_semantic_order(search_env):
    seed_signal_severities(search_env)
    response = search_env.client.get(
        "/api/v1/search/signals",
        params={"sort": "severity", "direction": "asc"},
    )
    assert severities(response) == RISK_ORDER


def test_signal_severity_descending_uses_semantic_order(search_env):
    seed_signal_severities(search_env)
    response = search_env.client.get(
        "/api/v1/search/signals",
        params={"sort": "severity", "direction": "desc"},
    )
    assert severities(response) == list(reversed(RISK_ORDER))


def test_severity_pagination_across_levels_has_no_missing_records(search_env):
    seed_incident_severities(search_env)
    seen = walk_pages(search_env.client, "incidents", "incident_id")
    assert set(seen) == {
        f"incident-{severity}-{index}"
        for index, severity in enumerate(RISK_ORDER)
    }


def test_severity_pagination_has_no_duplicate_records(search_env):
    seed_signal_severities(search_env)
    seen = walk_pages(search_env.client, "signals", "signal_id")
    assert len(seen) == len(set(seen)) == len(RISK_ORDER)


def test_same_severity_uses_stable_resource_id_ordering(search_env):
    seed_incident_severities(search_env, ["high", "high", "high"])
    seed_signal_severities(search_env, ["medium", "medium", "medium"])
    incidents = search_env.client.get(
        "/api/v1/search/incidents",
        params={"sort": "severity", "direction": "asc"},
    ).json()["items"]
    signals = search_env.client.get(
        "/api/v1/search/signals",
        params={"sort": "severity", "direction": "desc"},
    ).json()["items"]
    assert [item["incident_id"] for item in incidents] == [
        "incident-high-0",
        "incident-high-1",
        "incident-high-2",
    ]
    assert [item["signal_id"] for item in signals] == [
        "signal-medium-2",
        "signal-medium-1",
        "signal-medium-0",
    ]


def test_tampered_severity_cursor_is_rejected(search_env):
    seed_incident_severities(search_env)
    first = search_env.client.get(
        "/api/v1/search/incidents",
        params={"sort": "severity", "direction": "asc", "page_size": 1},
    ).json()
    cursor = first["next_cursor"]
    tampered = f"{cursor[:-1]}{'A' if cursor[-1] != 'A' else 'B'}"
    response = search_env.client.get(
        "/api/v1/search/incidents",
        params={
            "sort": "severity",
            "direction": "asc",
            "page_size": 1,
            "cursor": tampered,
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_search_cursor"
