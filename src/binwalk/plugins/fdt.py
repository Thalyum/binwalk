import binwalk.core.common
import binwalk.core.plugin
from binwalk.core.compat import str2bytes


class FDTPlugin(binwalk.core.plugin.Plugin):
    """Provides an extraction method for Flattened Device Tree."""

    MODULES = ["Signature"]

    FDT_SZ_OFFSET = 4
    FDT_SZ_SIZE = 4

    def init(self):
        """Add default rule for FDT extraction."""
        if self.module.extractor.enabled:
            self.module.extractor.add_rule(
                regex="^flattened device tree",
                extension="dtb",
                recurse=False,
            )

    def scan(self, result):
        """Update the result size for proper extraction."""
        if result.description.lower().startswith("flattened device tree"):
            fd = self.module.config.open_file(
                result.file.path, offset=result.offset + self.FDT_SZ_OFFSET
            )
            data = fd.read(self.FDT_SZ_SIZE)
            size = int.from_bytes(str2bytes(data), "big")
            fd.close()

            result.size = size
