from app.services.ingestion.schemas import CSV_SCHEMAS
from app.services.ingestion.validate import (
    is_valid_datetime,
    is_valid_id,
    is_valid_number,
)


def test_valid_organization_id():
    assert is_valid_id("ORG00001", "ORG")


def test_invalid_organization_id():
    assert not is_valid_id("ORG123", "ORG")


def test_valid_analyst_id():
    assert is_valid_id("AN00001", "AN")


def test_invalid_asset_id():
    assert not is_valid_id("ASTABC01", "AST")


def test_valid_datetime():
    assert is_valid_datetime("2026-08-20 15:17:00")


def test_valid_date():
    assert is_valid_datetime("2026-08-20")


def test_invalid_datetime():
    assert not is_valid_datetime("20-08-2026")


def test_valid_integer():
    assert is_valid_number("25", "experience_years")


def test_valid_float():
    assert is_valid_number("37.1227", "metric_value")


def test_invalid_integer():
    assert not is_valid_number("abc", "experience_years")


def test_all_csv_schemas_defined():
    assert len(CSV_SCHEMAS) == 8


def test_expected_csv_files():
    expected = {
        "organizations",
        "analysts",
        "assets",
        "alerts",
        "incidents",
        "investigations",
        "asset_activity",
        "peer_benchmarks",
    }

    assert set(CSV_SCHEMAS.keys()) == expected