from typing import Any, Final

__all__ = ['CONFORMANCE_CORPUS_FORMAT_VERSION', 'CONFORMANCE_CORPUS_ROOT', 'CONFORMANCE_CORPUS_NAME', 'STATUS_MEMBER', 'LOG_MEMBER', 'CTF_MEMBER', 'MALFORMED_STATUS_MEMBER', 'MALFORMED_CTF_MEMBER', 'UNSUPPORTED_MEMBER', 'EXPECTATIONS_MEMBER', 'MANIFEST_MEMBER', 'ingestion_temporal_semantic_vector', 'render_ingestion_temporal_semantic_vector', 'ingestion_conformance_members', 'build_ingestion_conformance_corpus']

CONFORMANCE_CORPUS_FORMAT_VERSION: int
CONFORMANCE_CORPUS_ROOT: str
CONFORMANCE_CORPUS_NAME: str
STATUS_MEMBER: Final[str]
LOG_MEMBER: Final[str]
CTF_MEMBER: Final[str]
MALFORMED_STATUS_MEMBER: Final[str]
MALFORMED_CTF_MEMBER: Final[str]
UNSUPPORTED_MEMBER: Final[str]
EXPECTATIONS_MEMBER: Final[str]
MANIFEST_MEMBER: Final[str]

def ingestion_temporal_semantic_vector() -> dict[str, Any]: ...
def render_ingestion_temporal_semantic_vector() -> bytes: ...
def ingestion_conformance_members() -> dict[str, bytes]: ...
def build_ingestion_conformance_corpus() -> bytes: ...
