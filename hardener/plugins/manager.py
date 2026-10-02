import importlib.util
from pathlib import Path


def load_plugins(directory: str = "plugins") -> dict[str, object]:
    loaded = {}
    path = Path(directory)
    if not path.exists():
        return loaded
    for file in path.glob("*.py"):
        if file.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(file.stem, file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, "register"):
                for name, func in module.register().items():
                    loaded[name] = func
    return loaded
