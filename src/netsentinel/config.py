from pathlib import Path
from types import SimpleNamespace

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "default.yaml"


def _to_namespace(value):
    if isinstance(value, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in value.items()})
    return value


def load_config(path=None):
    """Read the yaml config. Access values like cfg.paths.raw_dir."""
    path = Path(path) if path else DEFAULT_CONFIG
    with open(path, encoding="utf-8") as f:
        cfg = _to_namespace(yaml.safe_load(f))

    # paths in the yaml are relative to the project folder
    for name in ("raw_dir", "artifacts_dir", "reports_dir"):
        p = Path(getattr(cfg.paths, name))
        setattr(cfg.paths, name, p if p.is_absolute() else PROJECT_ROOT / p)
    return cfg
