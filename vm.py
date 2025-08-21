import ast
import random
import struct
import io

def rdint():
    return random.randint(100000, 99999999999999)

class OpCodes():
    LOAD_CONST = rdint()
    LOAD_NAME = rdint()
    CALL = rdint()
    RESUME = rdint()
    POP_TOP = rdint()
    STORE_NAME = rdint()
    COMPARE_OP = rdint()
    POP_JUMP_IF_FALSE = rdint()
    JUMP_FORWARD = rdint()
    JUMP_IF_TRUE_OR_POP = rdint()
    JUMP_IF_FALSE_OR_POP = rdint()
    UNARY_NEGATIVE = rdint()
    BINARY_OP = rdint()
    DUP_TOP = rdint()
MAGIC_NUMBER = b'BO MAY LA TRINH DEP TRAI NGHE CHUA CON CHO'
VERSION = b'\x02010'
TYPE_NONE = 0
TYPE_BOOL = 1
TYPE_INT = 2
TYPE_STRING = 3

def pack_constants(constants):
    stream = io.BytesIO()
    for const in constants:
        if const is None:
            stream.write(struct.pack('>B', TYPE_NONE))
        elif isinstance(const, bool):
            stream.write(struct.pack('>B?', TYPE_BOOL, const))
        elif isinstance(const, int):
            stream.write(struct.pack('>Bq', TYPE_INT, const))
        elif isinstance(const, str):
            encoded = const.encode('utf-8')
            stream.write(struct.pack('>BI', TYPE_STRING, len(encoded)))
            stream.write(encoded)
        else:
            raise TypeError(f'Unsupported constant type: {type(const)}')
    return stream.getvalue()

def pack_string_list(string_list):
    stream = io.BytesIO()
    for s in string_list:
        encoded = s.encode('utf-8')
        stream.write(struct.pack('>I', len(encoded)))
        stream.write(encoded)
    return stream.getvalue()

def pack_bytecode(bytecode_list):
    stream = io.BytesIO()
    for number in bytecode_list:
        stream.write(struct.pack('>Q', number))
    return stream.getvalue()

def b_bytes(bytecode, constants, names, cmp_op_names, bin_op_names):
    constants_bytes = pack_constants(constants)
    names_bytes = pack_string_list(names)
    cmp_op_names_bytes = pack_string_list(cmp_op_names)
    bin_op_names_bytes = pack_string_list(bin_op_names)
    bytecode_bytes = pack_bytecode(bytecode)
    package = io.BytesIO()
    package.write(MAGIC_NUMBER)
    package.write(VERSION)
    for data_block in [constants_bytes, names_bytes, cmp_op_names_bytes, bin_op_names_bytes, bytecode_bytes]:
        package.write(struct.pack('>I', len(data_block)))
        package.write(data_block)
    return package.getvalue()

class Compiler(ast.NodeVisitor):
    def __init__(self):
        self.bytecode = []
        self.constants = []
        self.names = []
        self.cmp_op_names = ['Eq', 'NotEq', 'Lt', 'LtE', 'Gt', 'GtE', 'Is', 'IsNot', 'In', 'NotIn']
        self._cmp_op_map = {ast.Eq: 'Eq', ast.NotEq: 'NotEq', ast.Lt: 'Lt', ast.LtE: 'LtE', ast.Gt: 'Gt', ast.GtE: 'GtE', ast.Is: 'Is', ast.IsNot: 'IsNot', ast.In: 'In', ast.NotIn: 'NotIn'}
        self.bin_op_names = ['Add', 'Sub', 'Mult', 'Div', 'FloorDiv', 'Mod', 'Pow']
        self._bin_op_map = {ast.Add: 'Add', ast.Sub: 'Sub', ast.Mult: 'Mult', ast.Div: 'Div', ast.FloorDiv: 'FloorDiv', ast.Mod: 'Mod', ast.Pow: 'Pow'}
    def _add_name(self, name):
        if name not in self.names:
            self.names.append(name)
        return self.names.index(name)
    def _add_constant(self, value):
        if callable(value): return -1
        if value not in self.constants: self.constants.append(value)
        return self.constants.index(value)
    def _emit_instruction(self, opcode, arg=0):
        self.bytecode.extend([opcode.value, arg >> 8, arg & 255])
        return len(self.bytecode) - 3
    def _patch_jump(self, pos, target):
        self.bytecode[pos + 1] = target >> 8
        self.bytecode[pos + 2] = target & 255
    def compile(self, source_code):
        self.bytecode, self.constants, self.names = ([], [], [])
        tree = ast.parse(source_code)
        self.visit(tree)
        return (self.bytecode, self.constants, self.names, self.cmp_op_names, self.bin_op_names)
    def visit_Module(self, node):
        for stmt in node.body: self.visit(stmt)
    def visit_Expr(self, node):
        self.visit(node.value)
        self._emit_instruction(OpCodes.POP_TOP)
    def visit_Constant(self, node):
        self._emit_instruction(OpCodes.LOAD_CONST, self._add_constant(node.value))
    def visit_Name(self, node):
        name_index = self._add_name(node.id)
        if isinstance(node.ctx, ast.Load): self._emit_instruction(OpCodes.LOAD_NAME, name_index)
        elif isinstance(node.ctx, ast.Store): self._emit_instruction(OpCodes.STORE_NAME, name_index)
    def visit_UnaryOp(self, node):
        self.visit(node.operand)
        if isinstance(node.op, ast.USub): self._emit_instruction(OpCodes.UNARY_NEGATIVE)
        else: raise NotImplementedError(f'Unary operator {node.op} not supported')
    def visit_BinOp(self, node):
        self.visit(node.left)
        self.visit(node.right)
        op_index = self.bin_op_names.index(self._bin_op_map[type(node.op)])
        self._emit_instruction(OpCodes.BINARY_OP, op_index)
    def visit_Call(self, node):
        for arg in node.args: self.visit(arg)
        self.visit(node.func)
        self._emit_instruction(OpCodes.CALL, len(node.args))
    def visit_Assign(self, node):
        self.visit(node.value)
        for i, target in enumerate(node.targets):
            if i < len(node.targets) - 1: self._emit_instruction(OpCodes.DUP_TOP)
            self.visit(target)
    def visit_Compare(self, node):
        self.visit(node.left)
        self.visit(node.comparators[0])
        op_index = self.cmp_op_names.index(self._cmp_op_map[type(node.ops[0])])
        self._emit_instruction(OpCodes.COMPARE_OP, op_index)
        if len(node.ops) > 1:
            end_jump_patches = []
            for i in range(1, len(node.ops)):
                jump_pos = self._emit_instruction(OpCodes.JUMP_IF_FALSE_OR_POP, 9999)
                end_jump_patches.append(jump_pos)
                self.visit(node.comparators[i - 1])
                self.visit(node.comparators[i])
                op_index = self.cmp_op_names.index(self._cmp_op_map[type(node.ops[i])])
                self._emit_instruction(OpCodes.COMPARE_OP, op_index)
            end_target = len(self.bytecode)
            for pos in end_jump_patches: self._patch_jump(pos, end_target)
    def visit_BoolOp(self, node):
        is_and = isinstance(node.op, ast.And)
        jump_op = OpCodes.JUMP_IF_FALSE_OR_POP if is_and else OpCodes.JUMP_IF_TRUE_OR_POP
        end_jump_patches = []
        for i, value in enumerate(node.values):
            self.visit(value)
            if i < len(node.values) - 1:
                jump_pos = self._emit_instruction(jump_op, 9999)
                end_jump_patches.append(jump_pos)
        end_target = len(self.bytecode)
        for pos in end_jump_patches: self._patch_jump(pos, end_target)
    def visit_If(self, node):
        self.visit(node.test)
        jump_if_false_pos = self._emit_instruction(OpCodes.POP_JUMP_IF_FALSE, 9999)
        for stmt in node.body: self.visit(stmt)
        if node.orelse:
            jump_over_else_pos = self._emit_instruction(OpCodes.JUMP_FORWARD, 9999)
            else_start_target = len(self.bytecode)
            self._patch_jump(jump_if_false_pos, else_start_target)
            for stmt in node.orelse: self.visit(stmt)
            end_target = len(self.bytecode)
            self._patch_jump(jump_over_else_pos, end_target)
        else:
            end_target = len(self.bytecode)
            self._patch_jump(jump_if_false_pos, end_target)

source_code = '''
a = int(input('> '))
if a > 1230 and a < 123123 or a > 1:
    print('dit me may')
elif a == 0 and a < 1 or a <12321312:
    print('vcl ')
'''
print('-- Source code running --')
exec(source_code)

compiler = Compiler()
bytecode, constants, names, cmp_op_names, bin_op_names = compiler.compile(source_code)
executable_package_bytes = b_bytes(bytecode, constants, names, cmp_op_names, bin_op_names)

_used_names = set()
def generate_obfuscated_name(length=11):
    while True:
        name = ''.join(random.choices([chr(i) for i in range(44032, 55204) if chr(i).isprintable() and chr(i).isidentifier()], k=length))
        if name not in _used_names:
            _used_names.add(name)
            return name

name_map = {
    "class_name": generate_obfuscated_name(),
    "run_method": generate_obfuscated_name(),
    "unpack_const_method": generate_obfuscated_name(),
    "unpack_str_list_method": generate_obfuscated_name(),
    "unpack_bytecode_method": generate_obfuscated_name(),
    "stack": generate_obfuscated_name(),
    "variables": generate_obfuscated_name(),
    "ip": generate_obfuscated_name(),
    "bytecode": generate_obfuscated_name(),
    "constants": generate_obfuscated_name(),
    "names": generate_obfuscated_name(),
    "cmp_ops": generate_obfuscated_name(),
    "bin_ops": generate_obfuscated_name(),
    "package_bytes": generate_obfuscated_name(),
    "stream": generate_obfuscated_name(),
    "magic": generate_obfuscated_name(),
    "version": generate_obfuscated_name(),
    "const_size": generate_obfuscated_name(),
    "names_size": generate_obfuscated_name(),
    "cmp_op_names_size": generate_obfuscated_name(),
    "local_cmp_op_names": generate_obfuscated_name(),
    "bin_op_names_size": generate_obfuscated_name(),
    "local_bin_op_names": generate_obfuscated_name(),
    "bytecode_size": generate_obfuscated_name(),
    "local_cmp_op_map": generate_obfuscated_name(),
    "local_bin_op_map": generate_obfuscated_name(),
    "opcode": generate_obfuscated_name(),
    "arg_high": generate_obfuscated_name(),
    "arg_low": generate_obfuscated_name(),
    "arg": generate_obfuscated_name(),
    "func": generate_obfuscated_name(),
    "args_list": generate_obfuscated_name(),
    "res": generate_obfuscated_name(),
    "right_val": generate_obfuscated_name(),
    "left_val": generate_obfuscated_name(),
    "helper_stream": generate_obfuscated_name(),
    "const_list": generate_obfuscated_name(),
    "type_tag": generate_obfuscated_name(),
    "size": generate_obfuscated_name(),
    "str_list": generate_obfuscated_name(),
    "bcode_list": generate_obfuscated_name(),
    "val": generate_obfuscated_name(),
}

vm_template = '''
import struct
import io
import operator

class {class_name}:
    def __init__(self):
        self.{stack}, self.{variables}, self.{ip} = [], {{}}, 0
        self.{bytecode}, self.{constants}, self.{names} = None, None, None
        self.{cmp_ops}, self.{bin_ops} = [], []
    
    def {unpack_const_method}(self, {helper_stream}):
        {const_list} = []
        while {helper_stream}.tell() < len({helper_stream}.getvalue()):
            {type_tag}, = struct.unpack('>B', {helper_stream}.read(1))
            if {type_tag} == {TYPE_NONE}: {const_list}.append(None)
            elif {type_tag} == {TYPE_BOOL}: {const_list}.append(struct.unpack('>?', {helper_stream}.read(1))[0])
            elif {type_tag} == {TYPE_INT}: {const_list}.append(struct.unpack('>q', {helper_stream}.read(8))[0])
            elif {type_tag} == {TYPE_STRING}:
                {size}, = struct.unpack('>I', {helper_stream}.read(4))
                {const_list}.append({helper_stream}.read({size}).decode('utf-8'))
        return {const_list}
        
    def {unpack_str_list_method}(self, {helper_stream}):
        {str_list} = []
        while {helper_stream}.tell() < len({helper_stream}.getvalue()):
            {size}, = struct.unpack('>I', {helper_stream}.read(4))
            {str_list}.append({helper_stream}.read({size}).decode('utf-8'))
        return {str_list}

    def {unpack_bytecode_method}(self, {helper_stream}):
        {bcode_list} = []
        while {helper_stream}.tell() < len({helper_stream}.getvalue()):
            {val}, = struct.unpack('>Q', {helper_stream}.read(8))
            {bcode_list}.append({val})
        return {bcode_list}

    def {run_method}(self, {package_bytes}):
        {stream} = io.BytesIO({package_bytes})
        {magic}, {version} = {stream}.read(42), {stream}.read(4)
        if {magic} != {MAGIC_NUMBER!r} or {version} != {VERSION!r}:
            raise ValueError("Invalid package format or version")

        {const_size}, = struct.unpack('>I', {stream}.read(4))
        self.{constants} = self.{unpack_const_method}(io.BytesIO({stream}.read({const_size})))
        {names_size}, = struct.unpack('>I', {stream}.read(4))
        self.{names} = self.{unpack_str_list_method}(io.BytesIO({stream}.read({names_size})))
        {cmp_op_names_size}, = struct.unpack('>I', {stream}.read(4))
        {local_cmp_op_names} = self.{unpack_str_list_method}(io.BytesIO({stream}.read({cmp_op_names_size})))
        {bin_op_names_size}, = struct.unpack('>I', {stream}.read(4))
        {local_bin_op_names} = self.{unpack_str_list_method}(io.BytesIO({stream}.read({bin_op_names_size})))
        
        {bytecode_size}, = struct.unpack('>I', {stream}.read(4))
        self.{bytecode} = self.{unpack_bytecode_method}(io.BytesIO({stream}.read({bytecode_size})))

        self.{variables} = __builtins__.__dict__
        {local_cmp_op_map} = {{'Eq': operator.eq, 'NotEq': operator.ne, 'Lt': operator.lt, 'LtE': operator.le, 'Gt': operator.gt, 'GtE': operator.ge, 'Is': operator.is_, 'IsNot': operator.is_not, 'In': lambda a, b: a in b, 'NotIn': lambda a, b: a not in b}}
        self.{cmp_ops} = [{local_cmp_op_map}[name] for name in {local_cmp_op_names}]
        {local_bin_op_map} = {{'Add': operator.add, 'Sub': operator.sub, 'Mult': operator.mul, 'Div': operator.truediv, 'FloorDiv': operator.floordiv, 'Mod': operator.mod, 'Pow': operator.pow}}
        self.{bin_ops} = [{local_bin_op_map}[name] for name in {local_bin_op_names}]

        self.{ip} = 0
        while self.{ip} < len(self.{bytecode}):
            {opcode} = self.{bytecode}[self.{ip}]
            {arg_high} = self.{bytecode}[self.{ip} + 1]
            {arg_low} = self.{bytecode}[self.{ip} + 2]
            {arg} = ({arg_high} << 8) | {arg_low}
            self.{ip} += 3
            
            if {opcode} == {OpCodes_LOAD_CONST}: self.{stack}.append(self.{constants}[{arg}])
            elif {opcode} == {OpCodes_LOAD_NAME}: self.{stack}.append(self.{variables}[self.{names}[{arg}]])
            elif {opcode} == {OpCodes_STORE_NAME}: self.{variables}[self.{names}[{arg}]] = self.{stack}.pop()
            elif {opcode} == {OpCodes_CALL}:
                {func}, {args_list} = self.{stack}.pop(), [self.{stack}.pop() for _ in range({arg})]
                {args_list}.reverse()
                {res} = {func}(*{args_list})
                if {res} is not None: self.{stack}.append({res})
            elif {opcode} == {OpCodes_POP_TOP}:
                if self.{stack}: self.{stack}.pop()
            elif {opcode} == {OpCodes_UNARY_NEGATIVE}: self.{stack}.append(-self.{stack}.pop())
            elif {opcode} == {OpCodes_DUP_TOP}: self.{stack}.append(self.{stack}[-1])
            elif {opcode} == {OpCodes_BINARY_OP}:
                {right_val}, {left_val} = self.{stack}.pop(), self.{stack}.pop()
                self.{stack}.append(self.{bin_ops}[{arg}]({left_val}, {right_val}))
            elif {opcode} == {OpCodes_COMPARE_OP}:
                {right_val}, {left_val} = self.{stack}.pop(), self.{stack}.pop()
                self.{stack}.append(self.{cmp_ops}[{arg}]({left_val}, {right_val}))
            elif {opcode} == {OpCodes_POP_JUMP_IF_FALSE}:
                if not self.{stack}.pop(): self.{ip} = {arg}
            elif {opcode} == {OpCodes_JUMP_FORWARD}: self.{ip} = {arg}
            elif {opcode} == {OpCodes_JUMP_IF_TRUE_OR_POP}:
                if self.{stack}[-1]: self.{ip} = {arg}
                else: self.{stack}.pop()
            elif {opcode} == {OpCodes_JUMP_IF_FALSE_OR_POP}:
                if not self.{stack}[-1]: self.{ip} = {arg}
                else: self.{stack}.pop()
            elif {opcode} == {OpCodes_RESUME}: pass

{class_name}().{run_method}({executable_package_bytes!r})
'''

format_dict = {
    **name_map,
    'TYPE_NONE': TYPE_NONE, 'TYPE_BOOL': TYPE_BOOL, 'TYPE_INT': TYPE_INT, 'TYPE_STRING': TYPE_STRING,
    'MAGIC_NUMBER': MAGIC_NUMBER, 'VERSION': VERSION,
    'OpCodes_LOAD_CONST': OpCodes.LOAD_CONST.value, 'OpCodes_LOAD_NAME': OpCodes.LOAD_NAME.value,
    'OpCodes_CALL': OpCodes.CALL.value, 'OpCodes_RESUME': OpCodes.RESUME.value,
    'OpCodes_POP_TOP': OpCodes.POP_TOP.value, 'OpCodes_STORE_NAME': OpCodes.STORE_NAME.value,
    'OpCodes_COMPARE_OP': OpCodes.COMPARE_OP.value, 'OpCodes_POP_JUMP_IF_FALSE': OpCodes.POP_JUMP_IF_FALSE.value,
    'OpCodes_JUMP_FORWARD': OpCodes.JUMP_FORWARD.value, 'OpCodes_JUMP_IF_TRUE_OR_POP': OpCodes.JUMP_IF_TRUE_OR_POP.value,
    'OpCodes_JUMP_IF_FALSE_OR_POP': OpCodes.JUMP_IF_FALSE_OR_POP.value, 'OpCodes_UNARY_NEGATIVE': OpCodes.UNARY_NEGATIVE.value,
    'OpCodes_BINARY_OP': OpCodes.BINARY_OP.value, 'OpCodes_DUP_TOP': OpCodes.DUP_TOP.value,
    'executable_package_bytes': executable_package_bytes
}

final_vm_code = vm_template.format_map(format_dict)

print('\n-- Final VM running --\n')
open('hehe.py','wb').write(final_vm_code.encode())
exec(final_vm_code)
