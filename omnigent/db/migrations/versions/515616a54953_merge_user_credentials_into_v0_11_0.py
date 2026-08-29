"""merge the user_credentials branch into the v0.11.0 head

Revision ID: 515616a54953
Revises: e8a4416a05a1, e5d9bc8ac650
Create Date: 2026-08-29 00:00:00.000000

Schema-neutral merge point. ``user_credentials`` (``e8a4416a05a1``) branched
off ``f7a8b9c0d1e2``, and upstream added four revisions on that same parent,
leaving two heads — which ``alembic upgrade head`` refuses to resolve.

Merging rather than re-parenting ``e8a4416a05a1`` is deliberate: a deployed
database is already stamped ``e8a4416a05a1``, so re-parenting would leave the
stamp sitting on the head and silently skip the four upstream revisions.
Against this merge Alembic still sees them as unapplied and runs them.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "515616a54953"
down_revision: tuple[str, str] = ("e8a4416a05a1", "e5d9bc8ac650")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No schema change: this revision only rejoins the two branches."""


def downgrade() -> None:
    """No schema change to undo."""
