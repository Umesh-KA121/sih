from __future__ import annotations

import argparse
import csv
from datetime import date, datetime
from pathlib import Path

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String, Text, delete
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import (
    Alert,
    Analyst,
    Asset,
    AssetActivity,
    Incident,
    Investigation,
    Organization,
    PeerBenchmark,
)


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DATA_DIR = PROJECT_ROOT / "data"

BATCH_SIZE = 2000


# -------------------------------------------------------------------
# CSV → SQLAlchemy model mapping
# -------------------------------------------------------------------

LOAD_ORDER = [
    ("organizations.csv", Organization),
    ("analysts.csv", Analyst),
    ("assets.csv", Asset),
    ("incidents.csv", Incident),
    ("alerts.csv", Alert),
    ("investigations.csv", Investigation),
    ("asset_activity.csv", AssetActivity),
    ("peer_benchmarks.csv", PeerBenchmark),
]


# -------------------------------------------------------------------
# Value conversion
# -------------------------------------------------------------------

def parse_boolean(value: str | None) -> bool | None:
    if value is None or value.strip() == "":
        return None

    normalized = value.strip().lower()

    if normalized in {"yes", "true", "1"}:
        return True

    if normalized in {"no", "false", "0"}:
        return False

    raise ValueError(f"Invalid boolean value: {value}")


def parse_value(value: str | None, column_type):
    if value is None:
        return None

    value = value.strip()

    if value == "":
        return None

    if isinstance(column_type, Boolean):
        return parse_boolean(value)

    if isinstance(column_type, Integer):
        return int(value)

    if isinstance(column_type, Float):
        return float(value)

    if isinstance(column_type, DateTime):
        return datetime.fromisoformat(value)

    if isinstance(column_type, Date):
        return date.fromisoformat(value)

    if isinstance(column_type, (String, Text)):
        return value

    return value


# -------------------------------------------------------------------
# Row conversion
# -------------------------------------------------------------------

def convert_row(row: dict, model) -> dict:
    result = {}

    for column in model.__table__.columns:
        column_name = column.name

        if column_name not in row:
            continue

        result[column_name] = parse_value(
            row[column_name],
            column.type,
        )

    return result


# -------------------------------------------------------------------
# CSV loading
# -------------------------------------------------------------------

def load_file(
    session: Session,
    filename: str,
    model,
) -> int:
    filepath = DATA_DIR / filename

    if not filepath.exists():
        raise FileNotFoundError(f"CSV file not found: {filepath}")

    inserted = 0
    batch = []

    print(f"\nLoading {filename}...")

    with filepath.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        for row_number, row in enumerate(reader, start=2):
            try:
                converted = convert_row(row, model)
                batch.append(converted)

            except Exception as exc:
                raise ValueError(
                    f"{filename}, row {row_number}: {exc}"
                ) from exc

            if len(batch) >= BATCH_SIZE:
                session.execute(
                    model.__table__.insert(),
                    batch,
                )

                inserted += len(batch)
                batch.clear()

                print(
                    f"  inserted: {inserted:,}",
                    end="\r",
                )

        if batch:
            session.execute(
                model.__table__.insert(),
                batch,
            )

            inserted += len(batch)

    print(f"  inserted: {inserted:,}")

    return inserted


# -------------------------------------------------------------------
# Database reset
# -------------------------------------------------------------------

def reset_database(session: Session) -> None:
    print("\nResetting SAT-SA database...")

    # Delete children first because of foreign keys.
    delete_order = [
        Investigation,
        Alert,
        AssetActivity,
        PeerBenchmark,
        Incident,
        Asset,
        Analyst,
        Organization,
    ]

    for model in delete_order:
        result = session.execute(delete(model))
        print(
            f"  cleared {model.__tablename__}: "
            f"{result.rowcount:,} rows"
        )

    session.commit()

    print("Database reset complete.")


# -------------------------------------------------------------------
# Full ingestion
# -------------------------------------------------------------------

def load_all(reset: bool = False) -> None:
    session = SessionLocal()

    try:
        if reset:
            reset_database(session)

        print("\n" + "=" * 70)
        print("SAT-SA CSV DATA INGESTION")
        print("=" * 70)

        total_rows = 0

        for filename, model in LOAD_ORDER:
            count = load_file(
                session=session,
                filename=filename,
                model=model,
            )

            total_rows += count

            # Commit after each file.
            session.commit()

            print(
                f"✓ {filename:<25} "
                f"{count:>8,} rows committed"
            )

        print("\n" + "=" * 70)
        print("INGESTION COMPLETE")
        print("=" * 70)
        print(f"Total rows inserted: {total_rows:,}")
        print("=" * 70)

    except Exception:
        session.rollback()
        print("\n✗ INGESTION FAILED")
        print("Transaction rolled back for the current file.")
        raise

    finally:
        session.close()


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Load SAT-SA CSV datasets into PostgreSQL."
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear existing SAT-SA data before ingestion.",
    )

    args = parser.parse_args()

    load_all(reset=args.reset)


if __name__ == "__main__":
    main()