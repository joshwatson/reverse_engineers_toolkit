from .types.libimport import browse_type_library
from binaryninja import PluginCommand
from binaryninjaui import UIAction, UIActionHandler, Menu, ViewType

from .types.export import export_type_library
from .types.make_struct import make_struct_here
from .functions.callgraph import CallGraphViewType

UIAction.registerAction("Reverse Engineer's Toolkit\\Types\\Export Type Library")
UIActionHandler.globalActions().bindAction(
    "Reverse Engineer's Toolkit\\Types\\Export Type Library",
    UIAction(export_type_library, lambda ctx: ctx.binaryView is not None),
)
Menu.mainMenu("Tools").addAction(
    "Reverse Engineer's Toolkit\\Types\\Export Type Library", "Export Type Library"
)

UIAction.registerAction("Reverse Engineer's Toolkit\\Types\\Import Type Library")
UIActionHandler.globalActions().bindAction(
    "Reverse Engineer's Toolkit\\Types\\Import Type Library",
    UIAction(browse_type_library, lambda ctx: ctx.binaryView is not None),
)
Menu.mainMenu("Tools").addAction(
    "Reverse Engineer's Toolkit\\Types\\Import Type Library", "Import Type Library"
)

PluginCommand.register_for_range(
    "Make Structure Here",
    "Make a structure from this range of data variables",
    make_struct_here,
)

ViewType.registerViewType(CallGraphViewType())