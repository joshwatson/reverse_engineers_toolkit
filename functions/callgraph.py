from binaryninja import FlowGraph, BinaryDataNotification
from binaryninja.binaryview import BinaryView
from binaryninja.enums import BranchType, InstructionTextTokenType, SymbolType
from binaryninja.flowgraph import FlowGraphNode
from binaryninja.function import DisassemblyTextLine, Function, InstructionTextToken
from binaryninjaui import FlowGraphWidget, ViewType


class CallGraph(FlowGraph):
    def __init__(self, function: Function):
        FlowGraph.__init__(self)
        self.function = function
        self.view = function.view

    def populate_nodes(self):
        func = self.function
        view = self.view

        nodes = {f: FlowGraphNode(self) for f in view.functions}

        for function, node in nodes.items():
            if function.symbol.type == SymbolType.ImportedFunctionSymbol:
                token_type = InstructionTextTokenType.ImportToken
            else:
                token_type = InstructionTextTokenType.CodeSymbolToken

            node.lines = [
                DisassemblyTextLine(
                    [InstructionTextToken(token_type, function.name, function.start)],
                    function.start,
                )
            ]

            self.append(node)

        for function in view.functions:
            node = nodes[function]
            for callee in set(function.callees):
                callee_node = nodes[callee]
                node.add_outgoing_edge(BranchType.IndirectBranch, callee_node)

    def update(self):
        return CallGraph(self.function)


class CallGraphWidget(FlowGraphWidget, BinaryDataNotification):
    def __init__(self, parent, view: BinaryView):
        self.view = view

        if view.entry_function:
            self.graph = CallGraph(view.entry_function)
        elif view.functions:
            self.graph = CallGraph(view.functions[0])
        else:
            self.graph = None

        FlowGraphWidget.__init__(self, parent, view, self.graph)

        BinaryDataNotification.__init__(self)
        view.register_notification(self)

    def navigate(self, address):
        self.showAddress(address, True)
        return True

    def navigateToFunction(self, function, address):
        self.showAddress(address, True)
        return True

    def function_added(self, view, func):
        self.graph = self.graph.update()
        self.setGraph(self.graph)

    def function_removed(self, view, func):
        self.graph = self.graph.update()
        self.setGraph(self.graph)

    def function_updated(self, view, func):
        self.graph = self.graph.update()
        self.setGraph(self.graph)


class CallGraphViewType(ViewType):
    def __init__(self):
        ViewType.__init__(self, "Call Graph", "Call Graph View")

    def getPriority(self, data, filename):
        if data.functions:
            return 1
        return 0

    def create(self, data, view_frame):
        return CallGraphWidget(view_frame, data)
