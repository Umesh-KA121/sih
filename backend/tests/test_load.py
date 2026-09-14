from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String

from app.services.ingestion.load import (
    parse_boolean,
    parse_value,
)


def test_parse_boolean():
    assert parse_boolean("Yes") is True
    assert parse_boolean("No") is False
    assert parse_boolean("true") is True
    assert parse_boolean("false") is False
    assert parse_boolean("") is None


def test_parse_integer():
    assert parse_value("42", Integer()) == 42


def test_parse_float():
    assert parse_value("37.1227", Float()) == 37.1227


def test_parse_date():
    result = parse_value(
        "2026-08-20",
        Date(),
    )

    assert result == date(2026, 8, 20)


def test_parse_datetime():
    result = parse_value(
        "2026-08-20 15:17:00",
        DateTime(),
    )

    assert result == datetime(
        2026,
        8,
        20,
        15,
        17,
        0,
    )


def test_parse_string():
    assert parse_value(
        "Critical",
        String(),
    ) == "Critical"


def test_parse_blank_string():
    assert parse_value(
        "",
        String(),
    ) is None