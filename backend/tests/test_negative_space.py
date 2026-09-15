from types import SimpleNamespace

from app.services.intelligence.supervisory_engine import (
    negative_space_analysis,
)


def make_analyst():
    return SimpleNamespace(
        analyst_id="A001",
    )


def test_critical_asset_silence():
    analyst = make_analyst()

    assets = [
        SimpleNamespace(
            asset_id="ASSET001",
            criticality="CRITICAL",
        )
    ]

    activities = []

    findings = negative_space_analysis(
        analyst,
        [],
        [],
        assets,
        activities,
    )

    categories = {
        finding["category"]
        for finding in findings
    }

    assert "CRITICAL_ASSET_SILENCE" in categories


def test_high_alert_without_investigation():
    analyst = make_analyst()

    alert = SimpleNamespace(
        alert_id="ALERT001",
        analyst_id="A001",
        severity="HIGH",
        status="OPEN",
        escalated=False,
    )

    findings = negative_space_analysis(
        analyst,
        [alert],
        [],
        [],
        [],
    )

    categories = {
        finding["category"]
        for finding in findings
    }

    assert "EXPECTED_INVESTIGATION_MISSING" in categories


def test_critical_closed_without_escalation():
    analyst = make_analyst()

    alert = SimpleNamespace(
        alert_id="ALERT002",
        analyst_id="A001",
        severity="CRITICAL",
        status="CLOSED",
        escalated=False,
    )

    findings = negative_space_analysis(
        analyst,
        [alert],
        [],
        [],
        [],
    )

    categories = {
        finding["category"]
        for finding in findings
    }

    assert "EXPECTED_ESCALATION_MISSING" in categories


def test_high_activity_without_alert():
    analyst = make_analyst()

    asset = SimpleNamespace(
        asset_id="ASSET002",
        criticality="HIGH",
    )

    activity = SimpleNamespace(
        asset_id="ASSET002",
        event_count=5000,
        network_events=1000,
        authentication_events=1000,
        log_sources_active=10,
        timestamp=None,
    )

    findings = negative_space_analysis(
        analyst,
        [],
        [],
        [asset],
        [activity],
    )

    categories = {
        finding["category"]
        for finding in findings
    }

    assert "EXPECTED_ALERT_MISSING" in categories