from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("legitifier")
except PackageNotFoundError:
    __version__ = "dev"
