"""Central redaction and Markdown-safe presentation helpers."""

import re
from typing import Any

from finsec.utils.redaction import redact_data, redact_text

ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+.!<>])")


class WorkspaceAnalysisRedactor:
    """Apply recursive secret redaction before any value reaches Markdown."""

    def data(self, value: Any) -> Any:
        """Return a recursively redacted structure."""

        return redact_data(value)

    def text(self, value: object | None) -> str:
        """Return sanitized plain text with terminal control sequences removed."""

        if value is None:
            return ""
        return redact_text(ANSI_ESCAPE.sub("", str(value)))

    def markdown(self, value: object | None) -> str:
        """Escape Markdown punctuation after secret redaction."""

        return MARKDOWN_SPECIAL.sub(r"\\\1", self.text(value))

    def table(self, value: object | None) -> str:
        """Return a safe single-line Markdown table value."""

        return self.text(value).replace("|", r"\|").replace("\r", " ").replace("\n", "<br>")

    def diagnostic(self, value: object | None) -> str:
        """Sanitize command/service diagnostics without interpreting presentation output."""

        return self.text(value).replace("```", "` ` `")
