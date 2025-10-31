"""Workflow mapping system for plugin-specific verification workflows."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import yaml

from .logging_setup import log_error


@dataclass
class WorkflowStep:
    """
    Represents a single step in a verification workflow.

    Attributes:
        title: Step title/description
        commands: List of commands to execute
        notes: Additional notes or guidance
    """

    title: str
    commands: list[str]
    notes: str


@dataclass
class Workflow:
    """
    Represents a complete verification workflow for plugin(s).

    Attributes:
        plugin_id: Original plugin_id string from YAML (may be comma-separated)
        workflow_name: Human-readable workflow name
        description: Brief description
        steps: List of workflow steps
        references: List of reference URLs
    """

    plugin_id: str
    workflow_name: str
    description: str
    steps: list[WorkflowStep]
    references: list[str]


class WorkflowMapper:
    """
    Manages workflow mappings from YAML configuration.
    """

    def __init__(self, yaml_path: Optional[Path] = None):
        """
        Initialize workflow mapper.

        Args:
            yaml_path: Path to workflow mappings YAML file.
                       If None, uses default workflow_mappings.yaml in nessus directory.
        """
        if yaml_path is None:
            # Default to workflow_mappings.yaml in nessus directory
            nessus_dir = Path(__file__).parent.parent
            yaml_path = nessus_dir / "workflow_mappings.yaml"

        self.yaml_path = yaml_path
        self.workflows: dict[str, Workflow] = {}
        self._load_workflows()

    def _load_workflows(self) -> None:
        """Load workflows from YAML file."""
        if not self.yaml_path.exists():
            # No workflow file - mapper will be empty
            return

        try:
            with open(self.yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "workflows" not in data:
                return

            for workflow_data in data["workflows"]:
                plugin_id = str(workflow_data.get("plugin_id", ""))
                if not plugin_id:
                    continue

                steps = []
                for step_data in workflow_data.get("steps", []):
                    step = WorkflowStep(
                        title=step_data.get("title", ""),
                        commands=step_data.get("commands", []),
                        notes=step_data.get("notes", ""),
                    )
                    steps.append(step)

                workflow = Workflow(
                    plugin_id=plugin_id,
                    workflow_name=workflow_data.get("workflow_name", ""),
                    description=workflow_data.get("description", ""),
                    steps=steps,
                    references=workflow_data.get("references", []),
                )

                # Split by comma and register workflow for each ID
                plugin_ids = [id.strip() for id in plugin_id.split(",")]
                for pid in plugin_ids:
                    if pid:  # Skip empty strings
                        self.workflows[pid] = workflow

        except Exception as e:
            # Failed to load workflows - mapper will be empty
            log_error(f"Failed to load workflows from {self.yaml_path}: {e}")

    def get_workflow(self, plugin_id: str) -> Optional[Workflow]:
        """
        Get workflow for a plugin ID.

        Args:
            plugin_id: Nessus plugin ID

        Returns:
            Workflow object if found, None otherwise
        """
        return self.workflows.get(plugin_id)

    def has_workflow(self, plugin_id: str) -> bool:
        """
        Check if workflow exists for plugin ID.

        Args:
            plugin_id: Nessus plugin ID

        Returns:
            True if workflow exists, False otherwise
        """
        return plugin_id in self.workflows

    def get_all_plugin_ids(self) -> list[str]:
        """
        Get list of all plugin IDs with workflows.

        Returns:
            List of plugin ID strings
        """
        return list(self.workflows.keys())

    def count(self) -> int:
        """
        Get count of loaded workflows.

        Returns:
            Number of workflows
        """
        return len(self.workflows)

    def load_additional_workflows(self, yaml_path: Path) -> int:
        """
        Load workflows from an additional YAML file and merge with existing.

        If a plugin_id already exists, the new workflow overrides it.

        Args:
            yaml_path: Path to additional workflow YAML file

        Returns:
            Number of workflow definitions loaded from the additional file
        """
        if not yaml_path.exists():
            return 0

        workflows_loaded = 0

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "workflows" not in data:
                return 0

            for workflow_data in data["workflows"]:
                plugin_id = str(workflow_data.get("plugin_id", ""))
                if not plugin_id:
                    continue

                steps = []
                for step_data in workflow_data.get("steps", []):
                    step = WorkflowStep(
                        title=step_data.get("title", ""),
                        commands=step_data.get("commands", []),
                        notes=step_data.get("notes", ""),
                    )
                    steps.append(step)

                workflow = Workflow(
                    plugin_id=plugin_id,
                    workflow_name=workflow_data.get("workflow_name", ""),
                    description=workflow_data.get("description", ""),
                    steps=steps,
                    references=workflow_data.get("references", []),
                )

                # Split by comma and register workflow for each ID (overrides existing)
                plugin_ids = [id.strip() for id in plugin_id.split(",")]
                for pid in plugin_ids:
                    if pid:
                        self.workflows[pid] = workflow

                # Count this workflow definition as loaded
                workflows_loaded += 1

        except Exception as e:
            log_error(f"Failed to load additional workflows from {yaml_path}: {e}")

        return workflows_loaded
