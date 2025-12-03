"""Database migrations for mundane.

Each migration is a separate file that defines schema changes.
Migrations are applied automatically when the database is initialized.
"""

import sqlite3
from abc import ABC, abstractmethod
from typing import List


class Migration(ABC):
    """Base class for database migrations."""

    @property
    @abstractmethod
    def version(self) -> int:
        """Migration version number."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of this migration."""
        pass

    @abstractmethod
    def upgrade(self, conn: sqlite3.Connection) -> None:
        """Apply this migration.

        Args:
            conn: Database connection to apply migration to
        """
        pass

    def downgrade(self, conn: sqlite3.Connection) -> None:
        """Rollback this migration (optional).

        Args:
            conn: Database connection to rollback migration from

        Raises:
            NotImplementedError: If migration doesn't support rollback
        """
        raise NotImplementedError(
            f"Migration {self.version} does not support downgrade"
        )


def get_all_migrations() -> List[Migration]:
    """Get all migrations in version order.

    Returns:
        List of Migration instances sorted by version
    """
    from . import migration_001_plugin_output
    from . import migration_002_remove_filesystem_columns

    migrations = [
        migration_001_plugin_output.Migration001(),
        migration_002_remove_filesystem_columns.Migration002(),
    ]

    # Sort by version to ensure correct order
    return sorted(migrations, key=lambda m: m.version)
