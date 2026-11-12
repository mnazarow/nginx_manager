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
            out.update(type="array", fields=describe(item))
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


def full_schema() -> Dict[str, Any]:
    return {
        "models": {k: describe(m) for k, m in MODELS.items()},
        "tabs": {k: [{"id": i, "label": lbl} for i, lbl in v] for k, v in TABS.items()},
    }
