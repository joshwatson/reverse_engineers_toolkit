from binaryninja import BinaryView, Type, TypeLibrary, log, Symbol, SymbolType
from binaryninja import core
from binaryninjaui import UIActionContext

import os


def add_types_to_library(lib: TypeLibrary, view: BinaryView):
    for name, type_ in view.types.items():
        if view.is_type_auto_defined(name):
            continue

        lib.add_named_type(name, type_)


def add_objects_to_library(lib: TypeLibrary, view: BinaryView):
    for address, var in view.data_vars.items():
        symbol = view.get_symbol_at(address)

        if symbol is None:
            continue

        symbol_type = Symbol.type

        if symbol_type != SymbolType.DataSymbol:
            continue

        lib.add_named_object(symbol.raw_name, var.type)


def add_functions_to_library(lib: TypeLibrary, view: BinaryView):
    for function in view.functions:
        if function.symbol.auto:
            continue

        lib.add_named_object(function.symbol.raw_name, function.function_type)


def generate_type_library_path(view: BinaryView) -> str:
    path: str = core.BNGetUserDirectory()

    filename: str = (
        os.path.basename(view.file.original_filename).split(".")[0] + ".bntl"
    )

    return os.path.join(path, "typelib", view.arch.name, filename)


def export_type_library(ctx: UIActionContext):
    if (view := ctx.binaryView) is None:
        return

    lib = TypeLibrary.new(view.arch, view.file.original_filename)

    lib.add_platform(view.platform)

    add_types_to_library(lib, view)

    add_objects_to_library(lib, view)

    add_functions_to_library(lib, view)

    path = generate_type_library_path(view)

    lib.finalize()

    log.log_info(f"Writing type library to {path}")

    lib.write_to_file(path)
