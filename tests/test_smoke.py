import app


def test_package_imports() -> None:
    assert isinstance(app.__version__, str)
