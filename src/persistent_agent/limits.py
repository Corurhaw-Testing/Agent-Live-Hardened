"""Fixed import budgets, including extension fields, before expensive work."""
import math

from .errors import IdentityValidationError

MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 10_000
MAX_STRING = 65_536
MAX_NODES = 100_000


def check_json_nesting(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise IdentityValidationError("JSON nesting limit exceeded")
        elif char in "]}":
            depth -= 1


def check_structure(data: object) -> None:
    # Iterative traversal also catches cycles before deepcopy/jsonschema.
    pending = [(data, 0, False)]
    ancestors = set()
    nodes = 0
    size_floor = 0
    while pending:
        value, depth, leaving = pending.pop()
        if leaving:
            ancestors.remove(id(value))
            continue
        nodes += 1
        size_floor += 1
        if nodes > MAX_NODES:
            raise IdentityValidationError("JSON node limit exceeded")
        if type(value) in (dict, list):
            if id(value) in ancestors:
                raise IdentityValidationError("cyclic JSON data")
            if depth >= MAX_DEPTH:
                raise IdentityValidationError("JSON nesting limit exceeded")
            if len(value) > MAX_ITEMS:
                raise IdentityValidationError("JSON collection limit exceeded")
            ancestors.add(id(value))
            pending.append((value, depth, True))
            if isinstance(value, dict):
                for key, child in value.items():
                    if type(key) is not str or len(key) > MAX_STRING:
                        raise IdentityValidationError("invalid or oversized JSON key")
                    try:
                        size_floor += len(key.encode("utf-8"))
                    except UnicodeError as exc:
                        raise IdentityValidationError("invalid UTF-8 JSON key") from exc
                    pending.append((child, depth + 1, False))
            else:
                pending.extend((child, depth + 1, False) for child in value)
        elif type(value) is str:
            if len(value) > MAX_STRING:
                raise IdentityValidationError("JSON string limit exceeded")
            try:
                size_floor += len(value.encode("utf-8"))
            except UnicodeError as exc:
                raise IdentityValidationError("invalid UTF-8 JSON string") from exc
        elif type(value) is float:
            if not math.isfinite(value):
                raise IdentityValidationError("record must contain finite JSON values")
        elif type(value) is int:
            if value.bit_length() > 4096:
                raise IdentityValidationError("JSON integer limit exceeded")
        elif value is not None and type(value) is not bool:
            raise IdentityValidationError("record must contain JSON values only")
        if size_floor > MAX_BYTES:
            raise IdentityValidationError("JSON byte limit exceeded")
