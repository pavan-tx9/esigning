"""SPEC section 7: "Nothing in the codebase deletes a blob. There is no delete method."

A rule nobody can check is a rule that erodes. This checks it: every public name in the storage
package, and the source of every module in it, is inspected for a way to remove stored evidence.
"""

from __future__ import annotations

import ast
import inspect
import pkgutil
from pathlib import Path

import pytest

import esign.storage

#: Verbs that would mean losing a blob.
DESTRUCTIVE = ("delete", "remove", "unlink", "purge", "destroy", "truncate", "rmtree", "expire")

#: Calls that would destroy stored content whatever they are called.
FORBIDDEN_CALLS = (
    "delete_object",
    "delete_objects",
    "delete_bucket",
    "rmtree",
    "rmdir",
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
    "os.rename",
    "os.replace",
    "os.truncate",
)


def _modules() -> list[Path]:
    package_dir = Path(esign.storage.__file__).parent
    submodules = sorted(
        Path(module.module_finder.path) / f"{module.name}.py"  # type: ignore[union-attr]
        for module in pkgutil.iter_modules([str(package_dir)])
    )
    return [*submodules, package_dir / "__init__.py"]


def test_the_package_has_modules_to_inspect() -> None:
    paths = _modules()
    assert len(paths) >= 4
    assert all(path.is_file() for path in paths)


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_no_public_function_or_method_in_the_package_removes_anything(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and not node.name.startswith("_")
        and any(word in node.name.lower() for word in DESTRUCTIVE)
    ]
    assert offenders == [], f"{path.name} defines {offenders}"


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_no_module_calls_anything_that_destroys_stored_content(path: Path) -> None:
    """The one unlink in the package is on a *temporary* file that was never a blob, so this
    looks at what is called on what: ``tmp.unlink()`` is allowed, ``path.unlink()`` is not."""
    source = path.read_text(encoding="utf-8")
    for call in FORBIDDEN_CALLS:
        assert f"{call}(" not in source, f"{path.name} calls {call}"

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "unlink":
            continue
        target = node.func.value
        name = target.id if isinstance(target, ast.Name) else ast.dump(target)
        assert name == "tmp", f"{path.name} unlinks {name}, which is not the temporary file"


def test_the_public_api_offers_only_put_get_and_exists() -> None:
    from esign.contracts import BlobService

    protocol_methods = {name for name in dir(BlobService) if not name.startswith("_")}
    assert protocol_methods == {"put", "get", "exists"}


def test_the_built_service_exposes_nothing_destructive(fs_blobs: object) -> None:
    for name, _ in inspect.getmembers(fs_blobs):
        if name.startswith("_"):
            continue
        assert not any(word in name.lower() for word in DESTRUCTIVE), name


def test_the_module_never_added_a_migration_that_allows_deletion() -> None:
    """The evidence module owns migrations 01xx. It should not have needed one; if it ever adds
    one, it must not hand anybody DELETE on an append-only table."""
    migrations = Path(esign.storage.__file__).parents[3] / "migrations"
    for path in sorted(migrations.glob("01*.sql")):
        sql = path.read_text(encoding="utf-8").upper()
        assert "GRANT DELETE" not in sql, path.name
        assert "DROP TRIGGER" not in sql, path.name
