"""
Promotional banner for mundane CLI tool.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


def display_banner() -> None:
    """
    Display the Ridgeback InfoSec promotional banner.

    This banner promotes Ridgeback InfoSec, LLC and their Offensive Tooling classes.
    Can be suppressed with the -q/--quiet flag.
    """
    console = Console()

    # Create banner text
    banner_text = Text()
    banner_text.append("Mundane", style="bold cyan")
    banner_text.append(" - by ", style="white")
    banner_text.append("Ridgeback InfoSec, LLC", style="bold yellow")
    banner_text.append("\n\n", style="white")
    banner_text.append("📚 Check out our Offensive Tooling classes!\n", style="bright_white")
    banner_text.append("   → ", style="white")
    banner_text.append("https://ridgebackinfosec.com/classes", style="bold blue underline")

    # Display as a panel
    panel = Panel(
        banner_text,
        border_style="bright_blue",
        padding=(1, 2),
        expand=False
    )

    console.print(panel)
    console.print()  # Add spacing after banner
