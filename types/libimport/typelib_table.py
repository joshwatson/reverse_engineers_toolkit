from typing import Dict
from binaryninja.types import Type
from PySide6.QtWidgets import QTableView, QWidget
from PySide6.QtCore import QAbstractTableModel, Qt


class TypeTableWidget(QTableView):
    def __init__(self, types: Dict[str, Type], parent: QWidget = None):
        self.types = types
        QTableView.__init__(self, parent)

        self.setModel(TypeTableModel(self, types))
        self.resizeColumnsToContents()
        self.setSelectionBehavior(QTableView.SelectRows)


class TypeTableModel(QAbstractTableModel):
    def __init__(self, parent: QWidget = None, types: Dict[str, Type] = None):
        if types is None:
            types = {}

        self.types = list(types.items())

        QAbstractTableModel.__init__(self, parent)

    def rowCount(self, parent):
        return len(self.types)

    def columnCount(self, parent):
        return 3

    def data(self, index, role):
        if not index.isValid():
            return None

        elif role != Qt.DisplayRole:
            return None

        if index.column() == 0:
            return str(self.types[index.row()][0])
        elif index.column() == 1:
            return str(self.types[index.row()][1])
        elif index.column() == 2:
            return self.types[index.row()][1].width

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return ["Name", "TypeClass", "Width"][col]
        return None
