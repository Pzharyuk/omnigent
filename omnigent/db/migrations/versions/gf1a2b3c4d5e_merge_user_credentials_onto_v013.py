"""Merge user_credentials onto the v0.13.0 alembic head.

Revision ID: gf1a2b3c4d5e
Revises: e8a4416a05a1, ge1b2c3d4e5f
Create Date: 2026-09-12 00:00:00.000000

The fork's ``user_credentials`` revision branched off ``f7a8b9c0d1e2``.
v0.13.0 continued that same parent through ``ge1b2c3d4e5f``. A live
database already stamped with ``e8a4416a05a1`` must still be able to
``upgrade head`` through the upstream revisions; this empty merge joins
the two heads so that happens without rewriting the already-applied
``user_credentials`` revision.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "gf1a2b3c4d5e"
down_revision: tuple[str, str] = ("e8a4416a05a1", "ge1b2c3d4e5f")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No schema change — join the two heads."""


def downgrade() -> None:
    """No schema change — split the two heads."""
