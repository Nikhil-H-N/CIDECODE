"""
In-memory database that mimics the Motor/MongoDB async API.
Drop-in replacement so the project runs without MongoDB.
"""

import copy
import re
import uuid
from collections import defaultdict
from datetime import datetime
from functools import cmp_to_key
from typing import Any, Dict, List, Optional, Tuple


class ObjectId(str):
    """Generate or validate an ObjectId-like hex string."""
    def __new__(cls, id_str: str = None):
        return str.__new__(cls, str(id_str) if id_str is not None else uuid.uuid4().hex[:24])


def _get_nested(doc: dict, field_path: str) -> Any:
    """Access nested fields using dot notation (e.g., 'threat_score.overall_score')."""
    parts = field_path.split(".")
    current = doc
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if current is None:
            return None
    return current


def _get_nested_with_presence(doc: dict, field_path: str) -> Tuple[bool, Any]:
    """Access nested fields and report whether the full path exists."""
    parts = field_path.split(".")
    current = doc
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return False, None
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return False, None
        else:
            return False, None
    return True, current


def _regex_matches(value: Any, pattern: Any, flags: int = 0) -> bool:
    """Match regex against scalars or any element of a list."""
    if value is None:
        candidates = [""]
    elif isinstance(value, list):
        candidates = [str(item) for item in value]
    else:
        candidates = [str(value)]
    return any(re.search(str(pattern), candidate, flags) for candidate in candidates)


def _compare_values(left: Any, right: Any) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return -1
    if right is None:
        return 1
    try:
        return (left > right) - (left < right)
    except TypeError:
        left_s = str(left)
        right_s = str(right)
        return (left_s > right_s) - (left_s < right_s)


def _sort_documents(docs: List[dict], sort_keys: List[Tuple[str, int]]) -> None:
    def compare(left: dict, right: dict) -> int:
        for field, direction in sort_keys:
            result = _compare_values(_get_nested(left, field), _get_nested(right, field))
            if result:
                return -result if direction == -1 else result
        return 0

    docs.sort(key=cmp_to_key(compare))


def _set_nested(doc: dict, field_path: str, value: Any):
    """Set a nested field using dot notation."""
    parts = field_path.split(".")
    current = doc
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def _match_value(doc_value: Any, condition: Any, field_exists: bool = True) -> bool:
    """Match a single field value against a query condition."""
    if isinstance(condition, dict):
        for op, operand in condition.items():
            if op == "$gt":
                if not (doc_value is not None and doc_value > operand):
                    return False
            elif op == "$gte":
                if not (doc_value is not None and doc_value >= operand):
                    return False
            elif op == "$lt":
                if not (doc_value is not None and doc_value < operand):
                    return False
            elif op == "$lte":
                if not (doc_value is not None and doc_value <= operand):
                    return False
            elif op == "$ne":
                if doc_value == operand:
                    return False
            elif op == "$exists":
                if field_exists != bool(operand):
                    return False
            elif op == "$regex":
                flags = 0
                regex_cond = condition
                if regex_cond.get("$options", "") and "i" in regex_cond["$options"]:
                    flags |= re.IGNORECASE
                try:
                    if not _regex_matches(doc_value, operand, flags):
                        return False
                except re.error:
                    return False
            elif op == "$in":
                if isinstance(doc_value, list):
                    if not any(item in operand for item in doc_value):
                        return False
                elif doc_value not in operand:
                    return False
            elif op == "$nin":
                if isinstance(doc_value, list):
                    if any(item in operand for item in doc_value):
                        return False
                elif doc_value in operand:
                    return False
        return True
    else:
        return doc_value == condition


def _match_query(doc: dict, query: dict) -> bool:
    """Check if a document matches a MongoDB-style query."""
    if not query:
        return True

    for field, condition in query.items():
        if field == "$or":
            if not any(_match_query(doc, sub_query) for sub_query in condition):
                return False
            continue

        field_exists, doc_value = _get_nested_with_presence(doc, field)

        if isinstance(condition, dict) and "$regex" in condition:
            regex_pattern = condition["$regex"]
            options = condition.get("$options", "")
            flags = re.IGNORECASE if "i" in options else 0
            try:
                if not _regex_matches(doc_value, regex_pattern, flags):
                    return False
            except re.error:
                return False
            continue

        if not _match_value(doc_value, condition, field_exists):
            return False

    return True


def _apply_update(doc: dict, update: dict) -> dict:
    """Apply a MongoDB-style update to a document."""
    result = copy.deepcopy(doc)

    if "$set" in update:
        for field, value in update["$set"].items():
            _set_nested(result, field, value)

    if "$setOnInsert" in update:
        for field, value in update["$setOnInsert"].items():
            existing = _get_nested(result, field)
            if existing is None:
                _set_nested(result, field, value)

    if "$unset" in update:
        for field in update["$unset"]:
            parts = field.split(".")
            current = result
            for part in parts[:-1]:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    current = None
                    break
            if isinstance(current, dict) and parts[-1] in current:
                del current[parts[-1]]

    if "$inc" in update:
        for field, value in update["$inc"].items():
            current = _get_nested(result, field)
            _set_nested(result, field, (current or 0) + value)

    return result


def _convert_dates(obj: Any) -> Any:
    """Convert datetime objects to ISO strings for storage."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _convert_dates(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_convert_dates(item) for item in obj]
    return obj


class InsertResult:
    def __init__(self, inserted_id: str):
        self.inserted_id = inserted_id


class UpdateResult:
    def __init__(self, matched_count: int, modified_count: int):
        self.matched_count = matched_count
        self.modified_count = modified_count


class DeleteResult:
    def __init__(self, deleted_count: int):
        self.deleted_count = deleted_count


class AsyncCursor:
    """Async cursor for find() and aggregate() results."""

    def __init__(self, documents: List[dict]):
        self._documents = documents
        self._sort_keys: List[Tuple[str, int]] = []
        self._skip_n = 0
        self._limit_n = None

    def sort(self, sort_spec) -> "AsyncCursor":
        if isinstance(sort_spec, list):
            for item in sort_spec:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    self._sort_keys.append((item[0], item[1]))
                elif isinstance(item, dict):
                    for k, v in item.items():
                        self._sort_keys.append((k, v))
        elif isinstance(sort_spec, dict):
            for k, v in sort_spec.items():
                self._sort_keys.append((k, v))
        return self

    def skip(self, n: int) -> "AsyncCursor":
        self._skip_n = n
        return self

    def limit(self, n: int) -> "AsyncCursor":
        self._limit_n = n
        return self

    def _resolve(self) -> List[dict]:
        docs = list(self._documents)

        if self._sort_keys:
            try:
                _sort_documents(docs, self._sort_keys)
            except Exception:
                pass

        if self._skip_n:
            docs = docs[self._skip_n:]

        if self._limit_n is not None:
            docs = docs[:self._limit_n]

        return docs

    def __aiter__(self):
        self._resolved = self._resolve()
        self._index = 0
        return self

    async def __anext__(self):
        if self._index >= len(self._resolved):
            raise StopAsyncIteration
        doc = self._resolved[self._index]
        self._index += 1
        return doc

    async def to_list(self, length=None) -> List[dict]:
        docs = self._resolve()
        if length is not None:
            docs = docs[:length]
        return docs


class InMemoryCollection:
    """In-memory collection mimicking Motor's AsyncIOMotorCollection."""

    def __init__(self, name: str):
        self.name = name
        self._documents: Dict[str, dict] = {}

    def _generate_id(self) -> str:
        return ObjectId()

    async def find_one(self, query: dict = None) -> Optional[dict]:
        query = query or {}
        for doc in self._documents.values():
            if _match_query(doc, query):
                return copy.deepcopy(doc)
        return None

    def find(self, query: dict = None, projection: dict = None) -> AsyncCursor:
        query = query or {}
        matching = [copy.deepcopy(doc) for doc in self._documents.values() if _match_query(doc, query)]

        if projection:
            projected = []
            include_mode = any(v == 1 for v in projection.values())
            for doc in matching:
                if include_mode:
                    new_doc = {"_id": doc.get("_id")}
                    for field, flag in projection.items():
                        if field == "_id":
                            continue
                        if flag == 1:
                            val = _get_nested(doc, field)
                            if val is not None:
                                _set_nested(new_doc, field, val)
                    projected.append(new_doc)
                else:
                    new_doc = copy.deepcopy(doc)
                    for field, flag in projection.items():
                        if flag == 0 and field in new_doc:
                            del new_doc[field]
                    projected.append(new_doc)
            matching = projected

        return AsyncCursor(matching)

    async def insert_one(self, doc: dict) -> InsertResult:
        doc = _convert_dates(doc)
        doc_id = doc.get("_id")
        if not doc_id:
            doc_id = self._generate_id()
            doc["_id"] = doc_id
        else:
            doc_id = str(doc_id)
            doc["_id"] = doc_id

        self._documents[doc_id] = copy.deepcopy(doc)
        return InsertResult(doc_id)

    async def update_one(self, query: dict, update: dict, upsert: bool = False) -> UpdateResult:
        matched = 0
        modified = 0

        for doc_id, doc in list(self._documents.items()):
            if _match_query(doc, query):
                matched = 1
                updated = _apply_update(doc, update)
                if updated != doc:
                    modified = 1
                    updated["_id"] = doc_id
                    self._documents[doc_id] = copy.deepcopy(updated)
                break

        if matched == 0 and upsert:
            new_doc = {}
            for field, value in query.items():
                if not field.startswith("$"):
                    _set_nested(new_doc, field, value)
            new_doc = _apply_update(new_doc, update)
            if "_id" not in new_doc:
                new_doc["_id"] = self._generate_id()
            new_doc = _convert_dates(new_doc)
            self._documents[new_doc["_id"]] = copy.deepcopy(new_doc)
            return UpdateResult(0, 1)

        return UpdateResult(matched, modified)

    async def replace_one(self, query: dict, replacement: dict, upsert: bool = False) -> UpdateResult:
        replacement = _convert_dates(replacement)
        matched = 0
        modified = 0

        for doc_id, doc in list(self._documents.items()):
            if _match_query(doc, query):
                matched = 1
                replacement["_id"] = doc_id
                if replacement != doc:
                    modified = 1
                    self._documents[doc_id] = copy.deepcopy(replacement)
                break

        if matched == 0 and upsert:
            if "_id" not in replacement:
                replacement["_id"] = self._generate_id()
            self._documents[replacement["_id"]] = copy.deepcopy(replacement)
            return UpdateResult(0, 1)

        return UpdateResult(matched, modified)

    async def delete_one(self, query: dict) -> DeleteResult:
        for doc_id, doc in list(self._documents.items()):
            if _match_query(doc, query):
                del self._documents[doc_id]
                return DeleteResult(1)
        return DeleteResult(0)

    async def delete_many(self, query: dict) -> DeleteResult:
        to_delete = [doc_id for doc_id, doc in self._documents.items() if _match_query(doc, query)]
        for doc_id in to_delete:
            del self._documents[doc_id]
        return DeleteResult(len(to_delete))

    async def count_documents(self, query: dict = None) -> int:
        query = query or {}
        return sum(1 for doc in self._documents.values() if _match_query(doc, query))

    def aggregate(self, pipeline: List[dict]) -> AsyncCursor:
        """Execute an aggregation pipeline and return results as an AsyncCursor."""
        docs = [copy.deepcopy(doc) for doc in self._documents.values()]

        for stage in pipeline:
            if len(stage) != 1:
                continue

            op, spec = next(iter(stage.items()))

            if op == "$match":
                docs = [doc for doc in docs if _match_query(doc, spec)]

            elif op == "$group":
                group_id = spec.get("_id")
                groups: Dict[str, List[dict]] = defaultdict(list)

                for doc in docs:
                    if group_id is None:
                        key = "null"
                    elif isinstance(group_id, str) and group_id.startswith("$"):
                        key = str(_get_nested(doc, group_id[1:]))
                    elif isinstance(group_id, dict):
                        key_parts = {}
                        for k, v in group_id.items():
                            if isinstance(v, str) and v.startswith("$"):
                                key_parts[k] = _get_nested(doc, v[1:])
                            else:
                                key_parts[k] = v
                        key = str(key_parts)
                    else:
                        key = str(group_id)
                    groups[key].append(doc)

                result_docs = []
                for key, group_docs in groups.items():
                    result_doc = {"_id": key if key != "null" else None}

                    for field_name, accumulator in spec.items():
                        if field_name == "_id":
                            continue

                        if not isinstance(accumulator, dict):
                            continue

                        for op_name, op_spec in accumulator.items():
                            if op_name == "$sum":
                                if isinstance(op_spec, (int, float)):
                                    result_doc[field_name] = op_spec * len(group_docs)
                                elif isinstance(op_spec, str) and op_spec.startswith("$"):
                                    total = 0
                                    for d in group_docs:
                                        val = _get_nested(d, op_spec[1:])
                                        if isinstance(val, (int, float)):
                                            total += val
                                    result_doc[field_name] = total
                                elif isinstance(op_spec, dict):
                                    total = 0
                                    for d in group_docs:
                                        if _evaluate_cond_expr(op_spec, d):
                                            total += 1
                                    result_doc[field_name] = total
                            elif op_name == "$first":
                                if group_docs:
                                    if isinstance(op_spec, str) and op_spec.startswith("$"):
                                        result_doc[field_name] = _get_nested(group_docs[0], op_spec[1:])
                                    else:
                                        result_doc[field_name] = op_spec
                            elif op_name == "$last":
                                if group_docs:
                                    if isinstance(op_spec, str) and op_spec.startswith("$"):
                                        result_doc[field_name] = _get_nested(group_docs[-1], op_spec[1:])
                                    else:
                                        result_doc[field_name] = op_spec
                            elif op_name == "$max":
                                values = []
                                for d in group_docs:
                                    if isinstance(op_spec, str) and op_spec.startswith("$"):
                                        v = _get_nested(d, op_spec[1:])
                                        if isinstance(v, (int, float)):
                                            values.append(v)
                                result_doc[field_name] = max(values) if values else None
                            elif op_name == "$min":
                                values = []
                                for d in group_docs:
                                    if isinstance(op_spec, str) and op_spec.startswith("$"):
                                        v = _get_nested(d, op_spec[1:])
                                        if isinstance(v, (int, float)):
                                            values.append(v)
                                result_doc[field_name] = min(values) if values else None

                    result_docs.append(result_doc)
                docs = result_docs

            elif op == "$sort":
                if isinstance(spec, dict):
                    fields = list(spec.items())
                    try:
                        _sort_documents(docs, fields)
                    except Exception:
                        pass

            elif op == "$limit":
                docs = docs[:spec]

            elif op == "$skip":
                docs = docs[spec:]

            elif op == "$project":
                projected = []
                for doc in docs:
                    new_doc = {}
                    for field, flag in spec.items():
                        if flag == 1:
                            val = _get_nested(doc, field)
                            if val is not None:
                                _set_nested(new_doc, field, val)
                        elif isinstance(flag, dict):
                            val = _evaluate_project_expr(flag, doc)
                            _set_nested(new_doc, field, val)
                    if "_id" not in spec or spec.get("_id") == 1:
                        new_doc["_id"] = doc.get("_id")
                    projected.append(new_doc)
                docs = projected

            elif op == "$addFields":
                for doc in docs:
                    for field, expr in spec.items():
                        val = _evaluate_project_expr(expr, doc)
                        _set_nested(doc, field, val)

            elif op == "$unwind":
                path = spec if isinstance(spec, str) else spec.get("path", "")
                if path.startswith("$"):
                    path = path[1:]
                unwound = []
                for doc in docs:
                    arr = _get_nested(doc, path)
                    if isinstance(arr, list):
                        for item in arr:
                            new_doc = copy.deepcopy(doc)
                            _set_nested(new_doc, path, item)
                            unwound.append(new_doc)
                    else:
                        unwound.append(doc)
                docs = unwound

        return AsyncCursor(docs)


def _evaluate_cond_expr(expr: Any, doc: dict) -> Any:
    """Evaluate a conditional expression ($cond, $eq, etc.) against a document."""
    if isinstance(expr, dict):
        if "$cond" in expr:
            cond = expr["$cond"]
            if isinstance(cond, list) and len(cond) >= 3:
                if_val = _evaluate_cond_expr(cond[0], doc)
                return _evaluate_cond_expr(cond[1], doc) if if_val else _evaluate_cond_expr(cond[2], doc)
            elif isinstance(cond, dict):
                if_val = _evaluate_cond_expr(cond.get("if", False), doc)
                return _evaluate_cond_expr(cond.get("then", None), doc) if if_val else _evaluate_cond_expr(cond.get("else", None), doc)

        if "$eq" in expr:
            vals = expr["$eq"]
            if isinstance(vals, list) and len(vals) == 2:
                a = _get_nested(doc, vals[0][1:]) if isinstance(vals[0], str) and vals[0].startswith("$") else vals[0]
                b = _get_nested(doc, vals[1][1:]) if isinstance(vals[1], str) and vals[1].startswith("$") else vals[1]
                return a == b

        if "$and" in expr:
            return all(_evaluate_cond_expr(sub, doc) for sub in expr["$and"])

        if "$or" in expr:
            return any(_evaluate_cond_expr(sub, doc) for sub in expr["$or"])

        if "$gt" in expr:
            vals = expr["$gt"]
            a = _get_nested(doc, vals[0][1:]) if isinstance(vals[0], str) and vals[0].startswith("$") else vals[0]
            b = _get_nested(doc, vals[1][1:]) if isinstance(vals[1], str) and vals[1].startswith("$") else vals[1]
            return (a or 0) > (b or 0)

        if "$gte" in expr:
            vals = expr["$gte"]
            a = _get_nested(doc, vals[0][1:]) if isinstance(vals[0], str) and vals[0].startswith("$") else vals[0]
            b = _get_nested(doc, vals[1][1:]) if isinstance(vals[1], str) and vals[1].startswith("$") else vals[1]
            return (a or 0) >= (b or 0)

    if isinstance(expr, str) and expr.startswith("$"):
        return _get_nested(doc, expr[1:])

    return expr


def _evaluate_project_expr(expr: Any, doc: dict) -> Any:
    """Evaluate a project-stage expression against a document."""
    if isinstance(expr, dict):
        if "$dateToString" in expr:
            dts = expr["$dateToString"]
            date_field = dts.get("date", "")
            fmt = dts.get("format", "%Y-%m-%d")
            if isinstance(date_field, str) and date_field.startswith("$"):
                val = _get_nested(doc, date_field[1:])
            else:
                val = date_field
            if isinstance(val, datetime):
                return val.strftime(fmt.replace("%Y", "%Y").replace("%m", "%m").replace("%d", "%d"))
            elif isinstance(val, str):
                try:
                    dt = datetime.fromisoformat(val)
                    return dt.strftime(fmt)
                except Exception:
                    return val
            return str(val) if val else ""

        if "$substr" in expr:
            parts = expr["$substr"]
            if isinstance(parts, list) and len(parts) >= 1:
                field = parts[0]
                if isinstance(field, str) and field.startswith("$"):
                    val = _get_nested(doc, field[1:])
                    start = parts[1] if len(parts) > 1 else 0
                    length = parts[2] if len(parts) > 2 else len(str(val or ""))
                    return str(val or "")[start:start + length]

        if "$toInt" in expr or "$toLong" in expr or "$toDouble" in expr:
            inner = expr.get("$toInt") or expr.get("$toLong") or expr.get("$toDouble")
            val = _evaluate_project_expr(inner, doc)
            try:
                return int(val)
            except (ValueError, TypeError):
                return 0

        if "$toString" in expr:
            inner = expr["$toString"]
            if isinstance(inner, str) and inner.startswith("$"):
                return str(_get_nested(doc, inner[1:]) or "")
            return str(inner)

        for op in ("$add", "$subtract", "$multiply", "$divide"):
            if op in expr:
                vals = expr[op]
                resolved = []
                for v in vals:
                    if isinstance(v, str) and v.startswith("$"):
                        resolved.append(_get_nested(doc, v[1:]) or 0)
                    else:
                        resolved.append(v)
                if op == "$add":
                    return sum(resolved)
                elif op == "$subtract":
                    return resolved[0] - resolved[1] if len(resolved) >= 2 else resolved[0]
                elif op == "$multiply":
                    result = 1
                    for r in resolved:
                        result *= r
                    return result
                elif op == "$divide":
                    return resolved[0] / resolved[1] if len(resolved) >= 2 and resolved[1] != 0 else 0

    if isinstance(expr, str) and expr.startswith("$"):
        return _get_nested(doc, expr[1:])

    return expr


class InMemoryDatabase:
    """In-memory database mimicking Motor's AsyncIOMotorDatabase."""

    def __init__(self):
        self._collections: Dict[str, InMemoryCollection] = {}

    def __getattr__(self, name: str) -> InMemoryCollection:
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._collections:
            self._collections[name] = InMemoryCollection(name)
        return self._collections[name]

    def __getitem__(self, name: str) -> InMemoryCollection:
        if name not in self._collections:
            self._collections[name] = InMemoryCollection(name)
        return self._collections[name]
