"""Public configuration and core-owned native CTF decoder.

The private transport remains a separately source-bound core implementation.
Deployment attestation uses the existing public/core boundary, including the
complete core package and native bridge in the executable pin.
"""

from ._babeltrace_process import (
    BabeltraceDecoderConfiguration,
    BabeltraceProcessDecoder,
    TraceDecodeError,
)


class BabeltraceTraceDecoder(BabeltraceProcessDecoder):
    """Configurable Babeltrace 2 decoder implementing the public TraceDecoder."""


__all__ = [
    "BabeltraceDecoderConfiguration",
    "BabeltraceTraceDecoder",
    "TraceDecodeError",
]
