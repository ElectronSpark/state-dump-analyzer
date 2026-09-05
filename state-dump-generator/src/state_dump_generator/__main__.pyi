import argparse
from .archive import ArchiveProjectionError as ArchiveProjectionError, write_assembly as write_assembly
from .path_safety import resolve_output_file as resolve_output_file
from .server import DEFAULT_HOST as DEFAULT_HOST, DEFAULT_PORT as DEFAULT_PORT, create_server as create_server, load_document as load_document, new_document as new_document, validate_document as validate_document

class _ConsoleArgumentParser(argparse.ArgumentParser): ...

def main(argv: list[str] | None = None) -> int: ...
