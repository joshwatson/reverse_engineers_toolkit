from binaryninja import PluginCommand

from .types.export import export_type_library
from .types.make_struct import make_struct_here

PluginCommand.register(
    "Reverse Engineer's Toolkit\\types\\Export Type Library",
    "Export a type library of the current binary",
    export_type_library,
)

PluginCommand.register_for_range(
    "Reverse Engineer's Toolkit\\types\\Make Structure Here",
    "Make a structure from this range of data variables",
    make_struct_here,
)
