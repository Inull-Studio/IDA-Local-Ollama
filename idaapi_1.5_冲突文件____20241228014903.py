# -*- coding: utf-8 -*-
import sys
# 添加Python包路径（根据实际情况调整，请先用对应版本的python -m pip install ollama）
sys.path.append('/Users/lovensar/.pyenv/versions/3.9.6/lib/python3.9/site-packages')
sys.path.append('D:/Program Files (x86)/python39/Lib/site-packages')
sys.path.append('E:/python38/Lib/site-packages')
import idaapi
import idc
import idautils
import ida_hexrays
import os
import re
import time
from ollama import Client, ResponseError

# 初始化大模型客户端
client_1 = Client(host='http://127.0.0.1:11434')  # 第一个智能体
client_2 = Client(host='http://127.0.0.1:11434')  # 第二个智能体

# 定义模型
model_name_1 = 'qwen2.5-coder:1.5b-instruct-q8_0'  # 第一个智能体使用的模型
model_name_2 = 'qwen2.5-coder:1.5b-instruct-q8_0'  # 第二个智能体使用的模型

def refresh_pseudocode(ea):
    try:
        # 获取当前函数的伪代码对象
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            # 打开伪代码视图并刷新
            view = ida_hexrays.open_pseudocode(ea, 0)  # 传递地址而不是伪代码对象
            if view:
                view.refresh_view(True)  # True 表示强制刷新
                print(f"### Refreshed pseudocode for function at address: {hex(ea)}")
            else:
                print(f"### Failed to open pseudocode view for function at address: {hex(ea)}")
        else:
            print(f"### Failed to decompile function at address: {hex(ea)}")
    except ida_hexrays.DecompilationFailure as e:
        print(f"### Decompilation failed for function at address: {hex(ea)} - {e}")

def refresh_all_pseudocode():
    """
    刷新所有函数的伪代码视图。
    """
    for func_ea in idautils.Functions():
        refresh_pseudocode(func_ea)

# 获取伪代码并提取未命名的变量
def get_pseudo_code(func_ea):
    try:
        # 确保Hex-Rays decompiler可用
        if not idaapi.init_hexrays_plugin():
            return "Hex-Rays decompiler is not available."
        
        # 获取函数
        func = idaapi.get_func(func_ea)
        if not func:
            return "Invalid function address."

        # 获取伪代码
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return "Failed to decompile the function."

        # 获取伪代码文本
        pseudo_code = str(cfunc)

        # 提取未命名的函数、全局变量、形参和局部变量
        unnamed_functions = re.findall(r'sub_[0-9A-Fa-f]+', pseudo_code)
        unnamed_globals = re.findall(r'dword_[0-9A-Fa-f]+', pseudo_code)
        unnamed_globals += re.findall(r'qword_[0-9A-Fa-f]+', pseudo_code)
        unnamed_globals += re.findall(r'byte_[0-9A-Fa-f]+', pseudo_code)
        unnamed_globals += re.findall(r'word_[0-9A-Fa-f]+', pseudo_code)
        
        unnamed_params = re.findall(r'a123[0-9]+', pseudo_code)
        unnamed_locals = re.findall(r'v123[0-9]+', pseudo_code)

        return {
            'pseudo_code': pseudo_code,
            'unnamed_functions': list(set(unnamed_functions)),
            'unnamed_globals': list(set(unnamed_globals)),
            'unnamed_params': list(set(unnamed_params)),
            'unnamed_locals': list(set(unnamed_locals))
        }
    except Exception as e:
        return f"Error: {str(e)}"

def save_pseudo_code_to_file(file_path, content):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def get_next_step(file_dir, func_name):
    step = 1
    while True:
        file_name = f"{func_name}_{step}.txt"
        file_path = os.path.join(file_dir, file_name)
        if not os.path.exists(file_path):
            return step
        step += 1

def valid_symbol_name(symbol_name):
    """
    确保符号名称是有效的，并且不会与现有名称冲突。
    """
    # 移除空格并确保没有保留前缀
    symbol_name = symbol_name.replace(" ", "_")  # 替换空格为下划线
    reserved_prefixes = ['sub_', 'byte_', 'word_', 'dword_', 'qword_']
    
    for prefix in reserved_prefixes:
        if symbol_name.startswith(prefix):
            # 避免保留前缀
            symbol_name = symbol_name[len(prefix):]  # 移除前缀
    
    # 过滤掉非法字符，包括反引号（`）和其他非字母数字字符
    symbol_name = re.sub(r'[^a-zA-Z0-9_]', '', symbol_name)
    
    # 如果符号名为空，则为其添加默认后缀
    if not symbol_name:
        symbol_name = 'invalid_symbol'
    
    # 确保符号名称不以数字开头
    if symbol_name and symbol_name[0].isdigit():
        symbol_name = f"func_{symbol_name}"  # 添加前缀以避免数字开头
    
    # 检查名称是否已存在
    if idc.get_name_ea(idaapi.BADADDR, symbol_name) != idaapi.BADADDR:
        # 如果名称已存在，添加后缀
        counter = 1
        original_name = symbol_name
        while idc.get_name_ea(idaapi.BADADDR, symbol_name) != idaapi.BADADDR:
            symbol_name = f"{original_name}_{counter}"
            counter += 1
    
    return symbol_name

def get_function_address(old_name):
    """
    尝试根据旧名称获取函数的地址。
    """
    # print(f"[DEBUG]get_name_ea={old_name}")
    addr = idc.get_name_ea(idaapi.BADADDR, old_name)
    if addr == idaapi.BADADDR:
        print(f"### Could not find function address for: {old_name}")
    return addr

def update_ida_symbols(rename_results):
    """
    更新IDA中的符号名称。
    :param rename_results: 包含重命名信息的字典
    :param func_ea: 可选参数，单个函数的地址（用于特定情况）
    :param func_ea_dict: 可选参数，包含旧名称到地址的映射字典
    """
    print(f"[DEBUG]rename_results={rename_results}")
    for category, renames in rename_results.items():
        if category == 'Unnamed Globals' or category == 'Unnamed Functions':
            for old_name, new_name in renames.items():
                # 处理名称中的非法字符和保留前缀
                new_name = valid_symbol_name(new_name)
                addr = get_function_address(old_name)
                print(f"[DEBUG]addr={hex(addr)}, new_name={new_name}")
                if idc.set_name(addr, new_name, idc.SN_NOCHECK):
                    print(f"### Updated {category} name@{hex(addr)}: {old_name} -> {new_name}")
                    rename_results[category].pop(old_name)
                    return new_name
                else:
                    print(f"### Failed to update {category} name: {old_name}")
                    rename_results[category].pop(old_name)
                    return False

        # elif category == 'Unnamed Globals':
        #     for old_name, new_name in renames.items():
        #         # 处理名称中的非法字符和保留前缀
        #         new_name = valid_symbol_name(new_name)
        #         # 尝试使用提供的地址进行重命名
        #         if old_name in func_ea_dict:
        #             addr = func_ea_dict[old_name]
        #         else:
        #             addr = get_function_address(old_name)
        #         if addr != idaapi.BADADDR:
        #             if idc.set_name(addr, new_name, idc.SN_NOWARN):
        #                 print(f"### Updated Globals name: {old_name} -> {new_name}")
        #             else:
        #                 print(f"### Failed to update Globals name: {old_name}")
        #         else:
        #             print(f"### Could not update Globals name: {old_name} (Address not found)")

    #     elif category == 'Unnamed Params' or category == 'Unnamed Locals':
    #         # 对于参数和局部变量，使用 Hex-Rays API 修改名称
    #         for old_name, new_name in renames.items():
    #             if category == 'Unnamed Params':
    #                 modify_param_name(func_ea, old_name, new_name)
    #             elif category == 'Unnamed Locals':
    #                 modify_local_var(func_ea, old_name, new_name)

def modify_param_name(func_ea, param_name, new_name):
    return True
    """
    修改函数参数的名称。
    """
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print("Failed to decompile the function!")
        return False

    # 获取参数列表
    for lvar in cfunc.lvars:
        if (lvar.is_arg) and (lvar.name == param_name):  # 正确地检查 is_arg 属性
            # 修改参数名称
            if ida_hexrays.rename_lvar(lvar, new_name, ida_hexrays.RN_USER | ida_hexrays.RN_Decompiled):
                print(f"Parameter '{param_name}' renamed to '{new_name}'")
                return True
            else:
                print("Failed to rename parameter!")
                return False

    print(f"Parameter '{param_name}' not found!")
    return False



def modify_local_var(func_ea, var_name, new_name):
    """
    修改局部变量的名称。
    """
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print("Failed to decompile the function!")
        return False

    # 获取局部变量管理器
    lvars = cfunc.lvars

    # 查找指定名称的局部变量
    for lvar in lvars:
        if not (lvar.is_arg) and lvar.name == var_name:
            # 修改局部变量的名称
            if ida_hexrays.rename_lvar(lvar, new_name, ida_hexrays.RN_USER | ida_hexrays.RN_Decompiled):
                print(f"Local variable '{var_name}' renamed to '{new_name}'")
                return True
            else:
                print("Failed to rename local variable!")
                return False

    print(f"Local variable '{var_name}' not found!")
    return False

def process_function(func_ea, output_dir):
    func_name = idc.get_func_name(func_ea)
    print(f"Processing function: {func_name}")

    # 获取伪代码和未命名变量信息
    pseudo_code_info = get_pseudo_code(func_ea)
    if isinstance(pseudo_code_info, str):  # 如果是错误信息
        print(pseudo_code_info)
        return

    prompt = f'''
\n\n\n\n
您好，您是最好的代码命名优化师！全球顶尖的代码命名优化专家！
==========================
已知：
{pseudo_code_info['pseudo_code']}
请对以上伪代码的函数进行重命名及其内部变量进行重命名：
Unnamed Functions: {pseudo_code_info['unnamed_functions']}
Unnamed Globals: {pseudo_code_info['unnamed_globals']}
Unnamed Params: {pseudo_code_info['unnamed_params']}
Unnamed Locals: {pseudo_code_info['unnamed_locals']}
不要生成优化代码，只需重命名变量即可。
请说明白这个符号的功能，不要使用无意义的命名，比如globalVar，或者func_1ACD这种没有意义的命名。
同时，不要忘了对原函数名进行重命名。
请对代码使用驼峰法进行功能性描述的重命名，格式为：
旧命名 -> 新命名
例如：（依次输出一个格式，一行）
sub_123456 -> readData
==========================
'''

    # 构建用户消息
    user_message = {
        'role': 'user',
        'content': prompt
    }
    # print(f"### User message:\n### {prompt}")

    # 将伪代码和未命名变量信息发送给第一个智能体，并以流式方式获取响应
    try:
        response_stream = client_1.chat(model=model_name_1, messages=[user_message], stream=True, options={'max_turns': 1,'temperature': 0,'top_p': 0.7,"max_tokens": 30000})
        buffer = ""
        optimized_code_lines = []

        for chunk in response_stream:
            text = chunk.get('message', {}).get('content', '')
            if text:
                buffer += text
                # 检查是否有完整的行
                lines = buffer.splitlines(True)  # 保留换行符
                if "<|" in lines:
                    break
                for i, line in enumerate(lines[:-1]):
                    if line.endswith('\n'):
                        print(f":: {line.rstrip()}")
                        optimized_code_lines.append(line.rstrip())
                buffer = lines[-1] if lines else ""
                if len(buffer) > 4096:
                    print(f"### 缓冲区长度超过限制：{len(buffer)}")
                    break

        # 处理剩余的缓冲区内容
        if buffer:
            print(f":: {buffer}")
            optimized_code_lines.append(buffer.rstrip())

        # 调用第二个智能体进行重命名查询
        rename_results = {}
        print(f'''
('Unnamed Functions', {pseudo_code_info['unnamed_functions']}),
('Unnamed Globals', {pseudo_code_info['unnamed_globals']}),
('Unnamed Params', {pseudo_code_info['unnamed_params']}),
('Unnamed Locals', {pseudo_code_info['unnamed_locals']})
''')
        for category, items in [
            ('Unnamed Functions', pseudo_code_info['unnamed_functions']),
            ('Unnamed Globals', pseudo_code_info['unnamed_globals']),
            ('Unnamed Params', pseudo_code_info['unnamed_params']),
            ('Unnamed Locals', pseudo_code_info['unnamed_locals'])
        ]:
            for item in items:
                query = f"请问在{pseudo_code_info['pseudo_code']}的重命名变换如下：\n---\n{optimized_code_lines}\n---\n的回答中，{item} 被重命名为什么？这个命名如果没有表达有用信息则认为是无效命名（不能是类似于globalVar这种没意义的命名，应该是WriteBuff这类有具体功能的命名），请直接输出{item}，如果是有意义的，请直接输出答案并不要解释和分析答案，请直接输出答案。"
                try:
                    # print(f"[DEBUG] {query}")
                    response = client_2.chat(model=model_name_2, messages=[{'role': 'user', 'content': query}], stream=False, options={'max_turns': 1,'temperature': 0.2,"max_tokens": 100000})
                    renamed_item = response['message']['content'].strip()
                    print(f"*** {renamed_item}")
                    # 进一步验证重命名后的名称是否合法
                    renamed_item = valid_symbol_name(renamed_item)
                    rename_results.setdefault(category, {})[item] = renamed_item
                    new_name = update_ida_symbols(rename_results)
                    if new_name:
                        print(f"=>=>=>>> {category}: {item} -> {new_name}")
                    else:
                        print("### 无法更新符号名称")
                except ResponseError as e:
                    print(f"### 请求模型时发生错误：{e.error}（状态码：{e.status_code})")
                    continue
        

        def parse_renamed_items(response_text):
            """
            解析模型返回的文本，提取旧命名 -> 新命名的替换对。
            
            :param response_text: 模型返回的文本
            :return: 包含替换对的字典
            """
            print(f"[DEBUG]response_text={response_text}")
            renamed_items = []
            for line in response_text:
                # 使用正则表达式匹配 "旧命名 -> 新命名" 的格式
                # init_proc -> initializeProcess
                # pattern = r'\s*(?P<old_name>[^\s]+)*\s->\s(?P<new_name>[^\s]+)'
                pattern= r'^\b(?P<old_name>[0-9A-Za-z_.]+)*\s->\s*(?P<new_name>[0-9A-Za-z_.]+)'
                matches = re.finditer(pattern, line)

                for match in matches:
                    # print(f"[DEBUG]match={match}")
                    old_name, new_name = match.group('old_name'), match.group('new_name')
                    renamed_items.append((old_name, new_name))
                    # print(f"[DEBUG]old_name={old_name}, new_name={new_name}")
            print(f"[DEBUG]renamed_items={renamed_items}")
            return renamed_items

        def process_renamed_items(renamed_items, rename_results, func_ea):
            """
            处理解析后的替换对，验证新名称并更新符号名称。
            
            :param renamed_items: 包含替换对的字典
            :param rename_results: 存储重命名结果的字典
            :param func_ea: 函数的起始地址
            """         
                
        if not any(pseudo_code_info[key] for key in ['unnamed_functions', 'unnamed_globals', 'unnamed_params', 'unnamed_locals']):
            renamed_items = parse_renamed_items(optimized_code_lines)
            for old_name, new_name in renamed_items:
                if old_name in ['start', 'main', '_start'] or re.fullmatch(r'(v|a)\d+', old_name):
                    continue
                query = f"请问在{pseudo_code_info['pseudo_code']}的优化版本：\n---\n{optimized_code_lines}\n---\n的回答中，{old_name}被替换成了谁？请按照以下格式输出，请不要做分析，请直接输出答案：\n{old_name} -> 新命名"
                try:    
                    # print(f"[DEBUG]-2 {query}")
                    # response = client_2.chat(model=model_name_2, messages=[{'role': 'user', 'content': query}], stream=False)
                    # response_text = response['message']['content'].strip()
                    # print(f"*** {response_text}")
                    # 解析响应中的替换对
                    new_name = valid_symbol_name(new_name)
                    addr = get_function_address(old_name)
                    print(f"[DEBUG]addr={hex(addr)}, new_name={new_name}")
                    if idc.set_name(addr, new_name, idc.SN_NOCHECK | idc.SN_NOWARN):
                        print(f"=>=>=>>> Updated @{hex(addr)} {old_name} -> {new_name}")
                    else:
                        print(f"!!! Failed to update {old_name} -> {new_name}")
                except Exception as e:
                    print(f"### Error：{e}")
                    continue

    except Exception as e:
        print(f"### Error: {e}")
        return

def save_idb(output_path=None):
    """
    保存当前的IDA数据库。
    
    :param output_path: 保存文件的路径。如果为None，则保存到当前文件位置。
    """
    try:
        # 使用 idc.save_database 保存数据库
        if idc.save_database(output_path, 0):  # 0 表示普通保存
            print("### 数据库已成功保存")
        else:
            print("### 保存数据库失败")
    except Exception as e:
        print(f"### 保存数据库时发生错误: {e}")

def main():
    # 获取当前IDA打开的文件名（不包括扩展名）
    if True:
        import ida_kernwin

        def jump_to_output_window():
            """
            将焦点自动跳转到 IDA 的输出窗口（Messages 窗口）。
            """
            # 查找输出窗口的句柄
            output_window = ida_kernwin.find_widget("Output") or ida_kernwin.find_widget("Messages")
            if output_window:
                ida_kernwin.activate_widget(output_window, True)

        
        input_file_path = idc.get_input_file_path()
        if not input_file_path:
            print("### 无法获取输入文件路径，请确保文件已正确加载到IDA Pro中。")
            return

        file_name = os.path.splitext(os.path.basename(input_file_path))[0]
        # 创建输出目录
        output_dir = os.path.join(os.path.dirname(input_file_path), f"{file_name}_pseudo_code")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        print("### Function list with pseudo-code:")
        print("### {:<20}{}".format("Address", "Name"))
        print("### " + "-" * 40)

        # 遍历所有函数
        for i in range(2):
            for func_ea in idautils.Functions():
                jump_to_output_window()
                # 获取函数名称
                func_name = idc.get_func_name(func_ea)
                # 打印函数起始地址和名称
                print("### {:<#020x} {}".format(func_ea, func_name))
                # 处理函数
                process_function(func_ea, output_dir)
            

        print("### 函数处理完毕，正在自动分析。。。")
        print("\n### 所有函数处理完毕，结果已保存到文件中。")
        idc.auto_wait()
        refresh_all_pseudocode()
    

# 程序入口
if __name__ == '__main__':
    main()