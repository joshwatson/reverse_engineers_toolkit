from binaryninja.interaction import get_open_filename_input
from binaryninja.typelibrary import TypeLibrary

from .typelib_browser import TypeLibraryBrowser


def browse_type_library(view):
    lib_path: bytes = get_open_filename_input("typelibrary filename:", "*.bntl")

    if lib_path is None:
        return

    lib_path = lib_path.decode("utf-8")

    lib = TypeLibrary.load_from_file(lib_path)

    browser = TypeLibraryBrowser(view, lib)
    browser.exec_()
