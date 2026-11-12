"""Преобразование pydantic-моделей в упрощённую схему для генерации форм и документации."""
from __future__ import annotations

import typing
from typing import Any, Dict, List, Tuple

from pydantic import BaseModel

from .models import MODELS, TABS


def _unwrap(ann) -> Tuple[Any, bool]:
    origin = typing.get_origin(ann)
    if origin is typing.Union:
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return ann, False


def _classify(ann) -> Dict[str, Any]:
    ann, nullable = _unwrap(ann)
    origin = typing.get_origin(ann)
    out: Dict[str, Any] = {"nullable": nullable}
    if origin is typing.Literal:
        out.update(type="select", options=list(typing.get_args(ann)))
    elif origin in (list, List):
        (item,) = typing.get_args(ann) or (str,)
        item, _ = _unwrap(item)
        if isinstance(item, type) and issubclass(item, BaseModel):
            out.update(type="array", fields=describe(item), item_model=item.__name__)
        elif typing.get_origin(item) is typing.Literal:
            out.update(type="multiselect", options=list(typing.get_args(item)))
        elif item is int:
            out.update(type="intlist")
        else:
            out.update(type="list")
    elif isinstance(ann, type) and issubclass(ann, BaseModel):
        out.update(type="object", fields=describe(ann))
    elif ann is bool:
        out["type"] = "bool"
    elif ann is int:
        out["type"] = "int"
    elif ann is float:
        out["type"] = "float"
    else:
        out["type"] = "str"
    return out


def _jsonable(v: Any) -> Any:
    if isinstance(v, BaseModel):
        return v.model_dump()
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v


def describe(model: type) -> List[Dict[str, Any]]:
    fields: List[Dict[str, Any]] = []
    for name, f in model.model_fields.items():
        info = _classify(f.annotation)
        info["key"] = name
        extra = dict(f.json_schema_extra or {})
        info.update(extra)
        try:
            info["default"] = _jsonable(f.get_default(call_default_factory=True))
        except Exception:  # pragma: no cover
            info["default"] = None
        for m in f.metadata:
            for attr in ("ge", "le", "gt", "lt"):
                if hasattr(m, attr):
                    info["min" if attr in ("ge", "gt") else "max"] = getattr(m, attr)
        if info["type"] in ("select", "multiselect") and "labels" in info:
            info["labels"] = {str(k): v for k, v in info["labels"].items()}
        fields.append(info)
    return fields


# Где в документации описаны параметры каждой модели (справочники генерирует tools/gen_reference.py)
DOC_PAGES = {
    "site": "05-sites.md", "location": "05-sites.md", "backend": "05-sites.md", "stream": "06-streams.md",
    "certificate": "07-certificates.md", "global": "08-global-settings.md", "alert_rule": "11-alerts.md",
    "alert_channel": "11-alerts.md", "panel": "13-panel-settings.md",
}
# Элементы списков, у которых в справочнике свой раздел (остальные описаны таблицей внутри поля-списка)
ITEM_KINDS = {"Location": "location", "Backend": "backend"}


def anchor(kind: str, path: str) -> str:
    """Якорь параметра в справочнике: f-<модель>-<путь через дефис>. Совпадает с tools/gen_reference.py."""
    return f"f-{kind}-{path.replace('.', '-')}"


def _add_anchors(fields: List[Dict[str, Any]], kind: str, prefix: str = "", fixed: str = "") -> None:
    for f in fields:
        path = prefix + f["key"]
        f["doc_page"] = DOC_PAGES.get(kind, "")
        f["anchor"] = fixed or anchor(kind, path)
        if f["type"] == "object":
            _add_anchors(f["fields"], kind, path + ".", fixed)
        elif f["type"] == "array" and f.get("fields"):
            item_kind = ITEM_KINDS.get(f.get("item_model", ""))
            if item_kind and not fixed:
                _add_anchors(f["fields"], item_kind)
            else:
                _add_anchors(f["fields"], kind, "", f["anchor"])


def full_schema() -> Dict[str, Any]:
    models = {k: describe(m) for k, m in MODELS.items()}
    for k, fields in models.items():
        _add_anchors(fields, k)
    return {
        "models": models,
        "tabs": {k: [{"id": i, "label": lbl} for i, lbl in v] for k, v in TABS.items()},
    }
