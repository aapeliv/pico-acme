from pathlib import Path

parent_folder = Path(__file__).parent

version = (parent_folder / "version").read_text().strip()
