"""
Promotional banner for mundane CLI tool.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from mundane_pkg._version import __version__


def display_banner() -> None:
    """
    Display the Ridgeback InfoSec promotional banner.

    This banner promotes Ridgeback InfoSec, LLC and their Offensive Tooling classes.
    Can be suppressed with the -q/--quiet flag.
    """
    console = Console()

    # Create banner text with colors that work on both light and dark backgrounds
    banner_text = Text()
    banner_text.append(f"Mundane v{__version__}", style="bold cyan")
    banner_text.append(" - by ")
    banner_text.append("Ridgeback InfoSec, LLC", style="bold magenta")
    banner_text.append("\n\n")
    banner_text.append("Check out our Offensive Tooling training!\n", style="bold")
    banner_text.append("   -> ")
    banner_text.append("https://ridgebackinfosec.com/training", style="bold blue underline")

    # Display as a panel
    panel = Panel(
        banner_text,
        border_style="blue",
        padding=(1, 2),
        expand=False
    )

    console.print(panel)
    console.print()  # Add spacing after banner
