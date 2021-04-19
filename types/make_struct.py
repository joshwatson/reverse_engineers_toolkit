from binaryninja import BinaryView
from binaryninja.binaryview import BinaryReader
from binaryninja.demangle import (
    simplify_name_to_qualified_name,
    simplify_name_to_string,
)
from binaryninja.enums import SymbolType, TypeClass
from binaryninja.function import Function
from binaryninja.types import QualifiedName, Type, Structure


def add_members(view: BinaryView, structure: Structure, start: int, length: int):
    offset = 0
    br = BinaryReader(view)

    if (dv := view.get_data_var_at(start)) is None:
        dv = view.get_next_data_var_after(start)
        offset = dv.address - start

    while offset < length:
        field_name = f"field_{offset}"

        type_ = dv.type

        # if this field is a pointer, let's see what it's pointing at. We can make
        # more informed decisions about the type and name of this field that way.
        if (
            type_.type_class == TypeClass.PointerTypeClass
            and type_.target.type_class == TypeClass.VoidTypeClass
        ):
            br.seek(dv.address)
            ptr = (
                br.read64()
                if view.address_size == 8
                else br.read32()
                if view.address_size == 4
                else br.read16()
                if view.address_size == 2
                else br.read8()
            )

            # If this field is pointing at a symbol, let's rename the field to be that symbol
            if ptr_symbol := view.get_symbol_at(ptr):
                field_name = simplify_name_to_string(ptr_symbol.short_name).split("::")[
                    -1
                ]

            # If this field points to a function, we should make a function pointer for that
            # function. This is very useful for C++ vtables and other function tables.
            if function := view.get_function_at(ptr):
                type_ = Type.pointer(function.arch, function.function_type)

            # If this field points to a data variable, we should make a pointer to that type.
            elif ptr_dv := view.get_data_var_at(ptr):
                type_ = Type.pointer(view.arch, ptr_dv.type)

        # Determine if this structure should be packed based on the alignment of the field.
        if offset % type_.width != 0:
            structure.packed = True

        structure.insert(offset, type_, field_name)

        if (dv := view.get_next_data_var_after(dv.address)) is None:
            break

        offset = dv.address - start


def make_struct_here(view: BinaryView, address: int, length: int):
    structure_name = f"struct_{address:x}"

    structure = Structure()
    structure.width = length

    add_members(view, structure, address, length)

    structure_type = Type.structure_type(structure)

    view.begin_undo_actions()

    view.define_user_type(structure_name, structure_type)

    named_type = Type.named_type_from_type(structure_name, structure_type)

    view.define_user_data_var(address, named_type)

    view.commit_undo_actions()
