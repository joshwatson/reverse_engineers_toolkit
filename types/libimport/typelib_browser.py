from typing import List

from binaryninja.binaryview import BinaryView
from binaryninja.enums import SymbolType
from binaryninja import log
from binaryninja.types import Type
from .typelib_table import TypeTableWidget
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)
from PySide6 import QtCore
from binaryninja.typelibrary import TypeLibrary


class TypeLibraryBrowser(QDialog):
    def __init__(
        self, view: BinaryView, typelibrary: TypeLibrary, parent: QWidget = None
    ):
        QDialog.__init__(self, parent, QtCore.Qt.Dialog | QtCore.Qt.WindowFlags())
        self.lib = typelibrary
        self.view = view
        self.setWindowTitle(self.lib.name)

        self.layout = QVBoxLayout()
        self.button_layout = QWidget()
        self.button_layout.setLayout(QHBoxLayout())

        import_selected_button = QPushButton("Import Selected")
        QtCore.QObject.connect(
            import_selected_button, QtCore.SIGNAL("clicked()"), self.import_selected
        )

        import_all_button = QPushButton("Import All")
        QtCore.QObject.connect(
            import_all_button, QtCore.SIGNAL("clicked()"), self.import_all
        )

        self.button_layout.layout().addWidget(import_selected_button)
        self.button_layout.layout().addWidget(import_all_button)
        self.layout.addWidget(self.button_layout)

        self.layout.addWidget(QLabel("Types"))
        self.types_table = TypeTableWidget(typelibrary.named_types, self)
        self.layout.addWidget(self.types_table)

        self.layout.addWidget(QLabel("Objects"))
        self.objects_table = TypeTableWidget(typelibrary.named_objects, self)
        self.layout.addWidget(self.objects_table)

        self.setLayout(self.layout)

    def import_selected(self):
        selected_type_indexes: List[
            QtCore.QModelIndex
        ] = self.types_table.selectedIndexes()

        selected = set(i.row() for i in selected_type_indexes)

        for row in selected:
            name, type_ = self.types_table.model().types[row]
            self.view.define_user_type(name, type_)

        selected_object_indexes: List[
            QtCore.QModelIndex
        ] = self.objects_table.selectedIndexes()

        selected = set(i.row() for i in selected_object_indexes)

        for row in selected:
            name, type_ = self.objects_table.model().types[row]

            symbol = next(
                (
                    s
                    for s in self.view.get_symbols_by_name(str(name))
                    if s.type
                    in (SymbolType.ImportAddressSymbol, SymbolType.ImportedDataSymbol)
                ),
                None,
            )

            if symbol is None:
                log.log_warn(f"Could not find symbol `{name}` in the binary!")
                continue

            ptr_type = Type.pointer(self.view.arch, type_)
            self.view.define_user_data_var(symbol.address, ptr_type)

        self.view.update_analysis()

    def import_all(self):
        self.view.add_type_library(self.lib)

        for name, type_ in self.lib.named_types.items():
            self.view.define_user_type(name, type_)

        for name, type_ in self.lib.named_objects.items():
            symbol = next(
                (
                    s
                    for s in self.view.get_symbols_by_name(str(name))
                    if s.type
                    in (SymbolType.ImportAddressSymbol, SymbolType.ImportedDataSymbol)
                ),
                None,
            )

            if symbol is None:
                continue

            ptr_type = Type.pointer(self.view.arch, type_)
            self.view.define_user_data_var(symbol.address, ptr_type)

        self.view.update_analysis()
