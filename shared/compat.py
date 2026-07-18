"""
Pydantic v1/v2 compatibility shim.

The codebase targets Pydantic v2 (field_validator). Some environments —
notably distro-packaged Python where PyPI is unreachable — ship Pydantic v1,
which only has the older `validator`. This shim exposes a single
`field_validator` that works on both, so services run unchanged regardless
of which Pydantic major version is installed.

Usage in services:
    from shared.compat import BaseModel, field_validator
"""

import pydantic
from pydantic import BaseModel, Field  # noqa: F401  (Field exists in v1 and v2)

_PYDANTIC_V2 = pydantic.VERSION.startswith("2")

if _PYDANTIC_V2:
    from pydantic import field_validator  # noqa: F401
else:
    # Pydantic v1: wrap the old `validator` to accept the v2 signature.
    # v2 calls @field_validator("field") and the method takes (cls, v).
    # v1 uses @validator("field"); allow_reuse avoids duplicate-name errors.
    from pydantic import validator as _v1_validator

    def field_validator(*fields, **kwargs):  # type: ignore
        # Strip v2-only kwargs that v1 doesn't accept (e.g. mode=)
        kwargs.pop("mode", None)
        kwargs.setdefault("allow_reuse", True)
        return _v1_validator(*fields, **kwargs)
