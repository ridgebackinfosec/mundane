"""Database migrations for mundane.

Each migration is a separate file that defines schema changes.
Migrations are applied automatically when the database is initialized.

## Migration System Architecture

The migration system uses an abstract base class pattern:

1. **Migration base class**: Defines the interface that all migrations must implement
   - `version` property: Returns migration version number (int)
   - `description` property: Returns human-readable description (str)
   - `upgrade()` method: Applies the migration changes
   - `downgrade()` method: Optional rollback (not implemented by default)

2. **Migration registry**: `get_all_migrations()` returns all migration instances
   - Imports all migration modules
   - Creates instances of each migration class
   - Returns sorted list (by version number)

3. **Automatic execution**: Migrations run in `initialize_database()`
   - Checks current schema version from `schema_version` table
   - Filters to pending migrations (version > current_version)
   - Executes migrations in order
   - Records each migration in `schema_version` table

## Creating New Migrations

See docs/DATABASE.md "Schema Migrations" section for complete guide.

Quick steps:
1. Create `migration_XXX_description.py` with Migration class
2. Add import and instance to `get_all_migrations()`
3. Update SCHEMA_VERSION in database.py
4. Update schema.sql documentation

## Design Decisions

- **One-way migrations**: No downgrade support (simplifies implementation)
- **Idempotent**: Migrations check if changes exist before applying
- **Version tracking**: Simple integer versioning (no timestamps)
- **Automatic execution**: Runs on every startup (fast with version check)
- **Sequential numbering**: Enforces linear migration history
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
    from . import migration_003_foundation_tables
    from . import migration_004_host_normalization

    migrations = [
        migration_001_plugin_output.Migration001(),
        migration_002_remove_filesystem_columns.Migration002(),
        migration_003_foundation_tables.Migration003(),
        migration_004_host_normalization.Migration004(),
    ]

    # Sort by version to ensure correct order
    return sorted(migrations, key=lambda m: m.version)
