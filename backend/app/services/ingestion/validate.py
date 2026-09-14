import csv
import re
from datetime import datetime
from pathlib import Path

from app.services.ingestion.schemas import CSV_SCHEMAS


BASE_DIR = Path(__file__).resolve().parents[4]
DATA_DIR = BASE_DIR / "data"


BOOLEAN_VALUES = {"yes", "no", "true", "false", "1", "0"}

INTEGER_COLUMNS = {
    "experience_years",
    "duration_minutes",
    "queries_executed",
    "event_count",
    "log_sources_active",
    "network_events",
    "authentication_events",
}

FLOAT_COLUMNS = {
    "closure_time_minutes",
    "metric_value",
    "peer_mean",
    "peer_stddev",
}

DATETIME_COLUMNS = {
    "created_at",
    "closed_at",
    "started_at",
    "completed_at",
    "resolved_at",
    "timestamp",
    "calculated_at",
}

DATE_COLUMNS = {
    "joined_at",
}


class ValidationResult:
    def __init__(self, filename: str):
        self.filename = filename
        self.rows = 0
        self.errors: list[str] = []
        self.warnings: list[str] = []

    @property
    def passed(self) -> bool:
        return not self.errors


def is_valid_id(value: str, prefix: str) -> bool:
    pattern = rf"^{re.escape(prefix)}\d{{5}}$"
    return bool(re.fullmatch(pattern, value))


def is_valid_datetime(value: str) -> bool:
    if not value:
        return True

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
    )

    for fmt in formats:
        try:
            datetime.strptime(value, fmt)
            return True
        except ValueError:
            continue

    return False


def is_valid_number(value: str, column: str) -> bool:
    if not value:
        return True

    try:
        if column in INTEGER_COLUMNS:
            int(value)
        else:
            float(value)

        return True
    except ValueError:
        return False


def validate_file(
    schema,
    data_dir: Path,
) -> tuple[ValidationResult, set[str]]:

    result = ValidationResult(schema.filename)

    file_path = data_dir / schema.filename

    if not file_path.exists():
        result.errors.append(
            f"File not found: {file_path}"
        )
        return result, set()

    seen_ids: set[str] = set()

    try:
        with file_path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:

            reader = csv.DictReader(file)

            if reader.fieldnames is None:
                result.errors.append(
                    "CSV has no header row."
                )
                return result, seen_ids

            actual_columns = set(reader.fieldnames)
            required_columns = set(schema.required_columns)

            missing_columns = required_columns - actual_columns

            if missing_columns:
                result.errors.append(
                    "Missing columns: "
                    + ", ".join(sorted(missing_columns))
                )

            for row_number, row in enumerate(reader, start=2):

                result.rows += 1

                record_id = row.get(schema.id_column, "").strip()

                # --------------------------------
                # ID validation
                # --------------------------------

                if not record_id:
                    result.errors.append(
                        f"Row {row_number}: missing {schema.id_column}"
                    )
                else:

                    if record_id in seen_ids:
                        result.errors.append(
                            f"Row {row_number}: duplicate "
                            f"{schema.id_column}={record_id}"
                        )

                    seen_ids.add(record_id)

                    if not is_valid_id(
                        record_id,
                        schema.id_prefix,
                    ):
                        result.errors.append(
                            f"Row {row_number}: invalid "
                            f"{schema.id_column}={record_id}"
                        )

                # --------------------------------
                # Required fields
                # --------------------------------

                for column in schema.required_non_empty:

                    value = row.get(column, "").strip()

                    if not value:
                        result.errors.append(
                            f"Row {row_number}: "
                            f"{column} cannot be empty"
                        )

                # --------------------------------
                # Boolean validation
                # --------------------------------

                for column in (
                    "evidence_reviewed",
                    "escalated",
                    "false_positive",
                    "escalation_decision",
                ):

                    if column in row:
                        value = row[column].strip().lower()

                        if value and value not in BOOLEAN_VALUES:
                            result.errors.append(
                                f"Row {row_number}: invalid boolean "
                                f"{column}={row[column]}"
                            )

                # --------------------------------
                # Numeric validation
                # --------------------------------

                for column in (
                    INTEGER_COLUMNS | FLOAT_COLUMNS
                ):

                    if column in row:

                        value = row[column].strip()

                        if not is_valid_number(
                            value,
                            column,
                        ):
                            result.errors.append(
                                f"Row {row_number}: invalid numeric "
                                f"{column}={value}"
                            )

                # --------------------------------
                # Date/time validation
                # --------------------------------

                for column in DATETIME_COLUMNS:

                    if column in row:

                        value = row[column].strip()

                        if value and not is_valid_datetime(value):
                            result.errors.append(
                                f"Row {row_number}: invalid datetime "
                                f"{column}={value}"
                            )

                for column in DATE_COLUMNS:

                    if column in row:

                        value = row[column].strip()

                        if value and not is_valid_datetime(value):
                            result.errors.append(
                                f"Row {row_number}: invalid date "
                                f"{column}={value}"
                            )

    except UnicodeDecodeError as exc:
        result.errors.append(
            f"Encoding error: {exc}"
        )

    except csv.Error as exc:
        result.errors.append(
            f"CSV parsing error: {exc}"
        )

    return result, seen_ids


def validate_relationships(
    datasets: dict[str, set[str]],
    results: dict[str, ValidationResult],
) -> None:

    relationship_rules = [
        (
            "analysts",
            "organization_id",
            "organizations",
        ),
        (
            "assets",
            "organization_id",
            "organizations",
        ),
        (
            "alerts",
            "organization_id",
            "organizations",
        ),
        (
            "alerts",
            "asset_id",
            "assets",
        ),
        (
            "alerts",
            "analyst_id",
            "analysts",
        ),
        (
            "alerts",
            "incident_id",
            "incidents",
        ),
        (
            "incidents",
            "organization_id",
            "organizations",
        ),
        (
            "investigations",
            "alert_id",
            "alerts",
        ),
        (
            "investigations",
            "analyst_id",
            "analysts",
        ),
        (
            "asset_activity",
            "asset_id",
            "assets",
        ),
        (
            "peer_benchmarks",
            "organization_id",
            "organizations",
        ),
    ]

    for source, column, target in relationship_rules:

        source_file = DATA_DIR / CSV_SCHEMAS[source].filename

        if not source_file.exists():
            continue

        target_ids = datasets.get(target, set())

        if not target_ids:
            continue

        with source_file.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:

            reader = csv.DictReader(file)

            for row_number, row in enumerate(reader, start=2):

                value = row.get(column, "").strip()

                # Nullable foreign keys are allowed.
                if not value:
                    continue

                if value not in target_ids:

                    results[source].errors.append(
                        f"Row {row_number}: "
                        f"{column}={value} does not exist in "
                        f"{target}"
                    )


def main() -> int:

    print()
    print("=" * 70)
    print("SAT-SA CSV DATA VALIDATION")
    print("=" * 70)
    print()

    results: dict[str, ValidationResult] = {}
    datasets: dict[str, set[str]] = {}

    # --------------------------------
    # Individual file validation
    # --------------------------------

    for name, schema in CSV_SCHEMAS.items():

        result, ids = validate_file(
            schema,
            DATA_DIR,
        )

        results[name] = result
        datasets[name] = ids

        if result.passed:
            print(
                f"✓ {schema.filename:<28}"
                f"{result.rows:>8,} rows"
            )
        else:
            print(
                f"✗ {schema.filename:<28}"
                f"{result.rows:>8,} rows"
                f"  ({len(result.errors)} errors)"
            )

    print()

    # --------------------------------
    # Cross-file validation
    # --------------------------------

    print("Cross-file relationship validation")
    print("-" * 70)

    validate_relationships(
        datasets,
        results,
    )

    relationship_errors = sum(
        len(result.errors)
        for result in results.values()
    )

    if relationship_errors == 0:
        print("✓ All foreign-key references are valid")
    else:
        print(
            f"✗ Found {relationship_errors:,} "
            f"relationship/data errors"
        )

    print()

    # --------------------------------
    # Detailed errors
    # --------------------------------

    total_errors = 0

    for result in results.values():

        if result.errors:

            print(f"\n{result.filename}")
            print("-" * 70)

            # Don't flood terminal with thousands of errors.
            display_errors = result.errors[:20]

            for error in display_errors:
                print(f"  ✗ {error}")

            if len(result.errors) > 20:
                print(
                    f"  ... and "
                    f"{len(result.errors) - 20:,} more errors"
                )

            total_errors += len(result.errors)

    print()
    print("=" * 70)

    if total_errors == 0:

        print("RESULT: PASS")
        print("All CSV files passed validation.")

        return 0

    print(
        f"RESULT: FAIL — "
        f"{total_errors:,} validation errors found."
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())