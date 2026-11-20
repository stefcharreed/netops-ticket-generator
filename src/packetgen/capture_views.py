"""Per-method capture view rules: what each capture method can see, and how its frames are wrapped.

Pure data and stdlib helpers; no dpkt, so validate() can use the same rules the renderer does.
"""
from __future__ import annotations

METHODS = ("span", "erspan")  # phase 3 adds epc and asa_capture
ENCAPS = ("native", "replicate")
