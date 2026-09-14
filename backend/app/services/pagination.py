from typing import Any


def paginate(
    query: Any,
    page: int = 1,
    limit: int = 25,
):
    page = max(page, 1)
    limit = min(max(limit, 1), 100)

    total = query.count()

    items = (
        query
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "data": items,
    }