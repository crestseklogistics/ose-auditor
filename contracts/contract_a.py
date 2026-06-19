"""
Contract A - Project Source Index

This module defines the schema, validation logic, and constants for Contract A,
which is produced by parser.py and consumed by the FSA (analyzer.py).

Contract A contains the normalized source code index of a target project,
including file paths, stripped content, hashes, and metadata. It is the
data contract exchanged between the OSE Auditor orchestrator (client) and
the analysis server, and is validated identically on both sides to
guarantee data consistency.

Validation rules implemented (see Data Contract Specification):
    A-001: `files` array MUST contain at least one file.
    A-002: `files` array MUST NOT exceed 10,000 items.
    A-003: Each `stripped_content` MUST NOT exceed 1 MB.
    A-004: `path_relative` MUST NOT be an absolute path.
    A-005: `language` MUST be one of the supported language identifiers.
    A-006: `project_identifier` MUST be a valid SHA-256 hex digest.
    A-007: If `truncated` is true, callers are warned about the cap.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class ValidationError(Exception):
    """Raised when a payload fails Contract A validation.

    All validation problems found in a single pass are collected and
    exposed both as ``self.errors`` (a list of individual messages) and
    folded into the exception's string representation, so callers can
    either inspect the structured list or simply log/print the
    exception directly.
    """

    def __init__(self, errors: Any) -> None:
        if isinstance(errors, str):
            errors = [errors]
        self.errors: List[str] = list(errors)
        message = "Contract A validation failed with {} error(s):\n{}".format(
            len(self.errors),
            "\n".join(f"  - {e}" for e in self.errors),
        )
        super().__init__(message)


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

VERSION = "1.0.0"
VALID_LANGUAGES = ["js", "ts", "jsx", "tsx", "sol", "py", "mq4", "mq5"]
MIN_FILES = 1
MAX_FILES = 10000
MAX_CONTENT_SIZE = 1048576  # 1 MB

PROJECT_ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
# Matches POSIX absolute paths ("/..."), Windows drive-letter paths
# ("C:\..." or "C:/..."), UNC paths ("\\server\share"), and home-relative
# paths ("~/...") -- all of which are disallowed for `path_relative`.
ABSOLUTE_PATH_PATTERN = re.compile(r"^([a-zA-Z]:[\\/]|[\\/]|~)")

REQUIRED_FILE_FIELDS = (
    "path_relative",
    "language",
    "hash",
    "stripped_content",
    "original_size",
    "stripped_size",
)

logger = logging.getLogger("ose.contract_a")


# --------------------------------------------------------------------------
# Dataclasses (optional typed views over the raw dict payload)
# --------------------------------------------------------------------------

@dataclass
class ContractAFile:
    """A single normalized source file entry within Contract A."""

    path_relative: str
    language: str
    hash: str
    stripped_content: str
    original_size: int
    stripped_size: int
    is_test_file: bool = False
    is_third_party: bool = False


@dataclass
class ContractA:
    """The full Contract A payload: the Project Source Index."""

    project_identifier: str
    files: List[ContractAFile] = field(default_factory=list)
    truncated: bool = False
    version: str = VERSION


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

def _is_relative_path(path: str) -> bool:
    """Return True if `path` looks like a relative filesystem path."""
    if not isinstance(path, str) or not path:
        return False
    return ABSOLUTE_PATH_PATTERN.match(path) is None


def _validate_file_entry(
    file_entry: Any, index: int, errors: List[str]
) -> Optional[Dict[str, Any]]:
    """Validate a single `files[index]` entry, appending problems to `errors`.

    Returns a shallow-copied, cleaned dict for the entry, or None if the
    entry was not a dict at all (and therefore cannot be cleaned).
    """
    if not isinstance(file_entry, dict):
        errors.append(
            f"files[{index}]: expected an object, got {type(file_entry).__name__}"
        )
        return None

    cleaned = dict(file_entry)

    # path_relative (A-004)
    path = file_entry.get("path_relative")
    if not isinstance(path, str) or not path:
        errors.append(
            f"files[{index}].path_relative: required non-empty string field "
            "is missing or invalid"
        )
    elif not _is_relative_path(path):
        errors.append(
            f"files[{index}].path_relative: must be a relative path, got "
            f"absolute-looking path '{path}' (rule A-004)"
        )

    # language (A-005)
    language = file_entry.get("language")
    if language not in VALID_LANGUAGES:
        errors.append(
            f"files[{index}].language: '{language}' is not one of the "
            f"supported languages {VALID_LANGUAGES} (rule A-005)"
        )

    # stripped_content (A-003)
    content = file_entry.get("stripped_content")
    if not isinstance(content, str):
        errors.append(
            f"files[{index}].stripped_content: required string field is "
            "missing or invalid"
        )
    elif len(content) > MAX_CONTENT_SIZE:
        errors.append(
            f"files[{index}].stripped_content: size {len(content)} bytes "
            f"exceeds the {MAX_CONTENT_SIZE} byte (1 MB) limit (rule A-003)"
        )

    # hash
    file_hash = file_entry.get("hash")
    if not isinstance(file_hash, str) or not file_hash:
        errors.append(
            f"files[{index}].hash: required non-empty string field is "
            "missing or invalid"
        )

    # original_size / stripped_size
    for size_field in ("original_size", "stripped_size"):
        value = file_entry.get(size_field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(
                f"files[{index}].{size_field}: required non-negative integer "
                "field is missing or invalid"
            )

    # optional booleans
    for bool_field in ("is_test_file", "is_third_party"):
        if bool_field in file_entry and not isinstance(file_entry[bool_field], bool):
            errors.append(
                f"files[{index}].{bool_field}: must be a boolean if present"
            )

    return cleaned


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def validate_contract_a(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate that `data` conforms to the Contract A schema (Project Source Index).

    All applicable validation rules (A-001 through A-007) are checked in a
    single pass; every problem found is collected rather than raising on
    the first failure, so callers see the complete set of issues at once.

    Args:
        data: The parsed payload (e.g. from parser.py's JSON output).

    Returns:
        A cleaned/normalized copy of `data` with `files` shallow-copied
        and `truncated` coerced to a bool.

    Raises:
        ValidationError: If `data` does not conform to the Contract A
            schema. The exception's `errors` attribute holds the full
            list of individual problems found.
    """
    errors: List[str] = []

    if not isinstance(data, dict):
        raise ValidationError(
            f"Contract A payload must be an object, got {type(data).__name__}"
        )

    # project_identifier (A-006)
    project_id = data.get("project_identifier")
    if not isinstance(project_id, str) or not PROJECT_ID_PATTERN.match(project_id):
        errors.append(
            "project_identifier: must be a 64-character lowercase SHA-256 "
            f"hex digest (rule A-006), got {project_id!r}"
        )

    # files presence/type
    files = data.get("files")
    if not isinstance(files, list):
        errors.append("files: required field must be a list of file objects")
        files = []

    # A-001 / A-002
    if len(files) < MIN_FILES:
        errors.append(
            f"files: must contain at least {MIN_FILES} file (rule A-001), "
            f"got {len(files)}"
        )
    if len(files) > MAX_FILES:
        errors.append(
            f"files: must not exceed {MAX_FILES} items (rule A-002), "
            f"got {len(files)}"
        )

    cleaned_files: List[Dict[str, Any]] = []
    for i, entry in enumerate(files):
        cleaned_entry = _validate_file_entry(entry, i, errors)
        if cleaned_entry is not None:
            cleaned_files.append(cleaned_entry)

    # truncated flag (A-007) -- non-critical, logged rather than failed
    truncated = data.get("truncated", False)
    if not isinstance(truncated, bool):
        errors.append("truncated: must be a boolean if present")
    elif truncated and len(files) > MAX_FILES:
        logger.warning(
            "Contract A 'truncated' flag is set but files array contains "
            "%d entries, exceeding the expected cap of %d (rule A-007)",
            len(files),
            MAX_FILES,
        )
    elif truncated:
        logger.warning(
            "Contract A 'truncated' flag is set; consumers should be aware "
            "the source index may not represent the full project (rule A-007)"
        )

    if errors:
        raise ValidationError(errors)

    cleaned_data = dict(data)
    cleaned_data["files"] = cleaned_files
    cleaned_data["project_identifier"] = project_id
    cleaned_data["truncated"] = bool(truncated)
    return cleaned_data


def is_valid_contract_a(data: Dict[str, Any]) -> bool:
    """Return True if `data` is a valid Contract A payload, False otherwise."""
    try:
        validate_contract_a(data)
        return True
    except ValidationError:
        return False


def get_contract_a_schema() -> Dict[str, Any]:
    """Return the JSON Schema (draft-07) representation of Contract A."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "ContractA_ProjectSourceIndex",
        "description": (
            "Project Source Index produced by parser.py and consumed by "
            "the FSA (analyzer.py)."
        ),
        "type": "object",
        "required": ["project_identifier", "files"],
        "properties": {
            "project_identifier": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$",
                "description": (
                    "SHA-256 hex digest identifying the target project "
                    "(rule A-006)."
                ),
            },
            "files": {
                "type": "array",
                "minItems": MIN_FILES,
                "maxItems": MAX_FILES,
                "items": {
                    "type": "object",
                    "required": list(REQUIRED_FILE_FIELDS),
                    "properties": {
                        "path_relative": {
                            "type": "string",
                            "description": (
                                "Relative path of the file within the "
                                "project (rule A-004)."
                            ),
                        },
                        "language": {
                            "type": "string",
                            "enum": VALID_LANGUAGES,
                            "description": "Detected source language (rule A-005).",
                        },
                        "hash": {"type": "string"},
                        "stripped_content": {
                            "type": "string",
                            "maxLength": MAX_CONTENT_SIZE,
                            "description": (
                                "Normalized file content, capped at 1 MB "
                                "(rule A-003)."
                            ),
                        },
                        "original_size": {"type": "integer", "minimum": 0},
                        "stripped_size": {"type": "integer", "minimum": 0},
                        "is_test_file": {"type": "boolean", "default": False},
                        "is_third_party": {"type": "boolean", "default": False},
                    },
                },
            },
            "truncated": {
                "type": "boolean",
                "default": False,
                "description": "Indicates the files array was capped (rule A-007).",
            },
            "version": {"type": "string", "default": VERSION},
        },
    }
