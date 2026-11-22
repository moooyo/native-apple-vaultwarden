"""Export the named mobile board screenshots from simulator test result bundles."""

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def export_boards(results, output):
    root = Path(__file__).resolve().parents[2]
    canvas = json.loads((root / "Design/openvault-ui-handoff/design/canvas.json").read_text())
    boards = {name.removesuffix(".dc.html") for name in canvas["boards"]
              if name.startswith(("Main.", "iPhone-", "iPad-"))}
    names = boards | {"iPad-Vault-Sidebar", "iPad-Send-Sidebar", "iPhone-Codes-AX5-Dark", "iPhone-Login-Verification", "iPhone-Login-Verification-AX5", "iPhone-Send-Detail",
                      "iPhone-ImportExport-Export"}
    found = set()
    output.mkdir(parents=True, exist_ok=True)
    for bundle in results:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["xcrun", "xcresulttool", "export", "attachments", "--path", str(bundle),
                            "--output-path", directory, "--filter", "*.png"], check=True)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            for test in manifest:
                for attachment in test["attachments"]:
                    name = re.split(r"_[0-9]", Path(attachment["suggestedHumanReadableName"]).stem, maxsplit=1)[0]
                    if name not in names:
                        continue
                    shutil.copyfile(Path(directory) / attachment["exportedFileName"], output / f"{name}.png")
                    found.add(name)
    if missing := boards - found:
        raise SystemExit("Missing board screenshots: " + ", ".join(sorted(missing)))
    print(f"Exported {len(boards)} boards and {len(found - boards)} additional states to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("results", nargs="+", type=Path)
    options = parser.parse_args()
    export_boards(options.results, options.output)
