from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_SCRIPT = ROOT / "frontend" / "assets" / "app.js"


def javascript_function(source: str, name: str) -> str:
    marker = f"function {name}("
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated JavaScript function: {name}")


class FrontendSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_SCRIPT.read_text(encoding="utf-8")

    def test_plugin_colors_cross_a_strict_browser_boundary(self) -> None:
        validator = javascript_function(
            self.script,
            "safePresentationColor",
        )
        layer_config = javascript_function(self.script, "layerConfig")
        source_type = javascript_function(
            self.script,
            "sourceTypeDescriptor",
        )
        discovery = javascript_function(
            self.script,
            "discoverPresentation",
        )

        self.assertIn("/^#[0-9A-Fa-f]{6}$/", validator)
        self.assertIn("stableColor(identity)", validator)
        self.assertIn("safePresentationColor(configured.color, key)", layer_config)
        self.assertIn("safePresentationColor(descriptor.color, key)", source_type)
        self.assertIn("safePresentationColor(item.color, key)", discovery)
        self.assertNotIn("item.color || stableColor", discovery)

    def test_style_bearing_inner_html_uses_validated_color_accessors(self) -> None:
        self.assertIn("--association-color:${layerColor(", self.script)
        self.assertIn("--segment-color:${escapeHtml(layerColor(", self.script)
        self.assertIn("--node-color:${layerColor(", self.script)
        self.assertIn("--chain-color:${layerColor(", self.script)
        self.assertIn("sourceTypeDescriptor(lane.sourceTypes[0]).color", self.script)


if __name__ == "__main__":
    unittest.main()
