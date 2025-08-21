# -*- coding: utf-8 -*-
import logging
import os
import re
import sys
import time

import ida_hexrays
import ida_kernwin
import idaapi
import idautils
import idc


# ----------------------------
# Configuration
# ----------------------------
OLLAMA_HOST = 'http://localhost:11434'
MODEL_NAME = 'qwen2.5-coder:7b'
TIMEOUT_SECONDS = 60
MAX_RESPONSE_LENGTH = 4096
RENAME_RETRIES = 10
CHUNK_SIZE = 10000
TEMPERATURE = 0.2
TOP_P = 0.8

PYTHON_PACKAGE_PATHS = [
    r'D:\Codes\Python\IDA-Local-Ollama\.venv\Lib\site-packages'
]

# Initialize Python paths
def setup_python_paths(paths):
    """
    Appends existing paths to the system path for Python package imports.
    """
    for path in paths:
        if os.path.exists(path):
            sys.path.append(path)

setup_python_paths(PYTHON_PACKAGE_PATHS)
from ollama import Client


# Setup logging
logging.basicConfig(
    filename=f'ida_ai_integration_{time.time()}.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ----------------------------
# AI Client
# ----------------------------
class AIClient:
    def __init__(self, host, model_name):
        self.client = Client(host=host)
        self.model_name = model_name

    def chat(self, messages, stream=True, options=None):
        return self.client.chat(
            model=self.model_name,
            messages=messages,
            stream=stream,
            options=options or {}
        )

# Initialize AI Client
ai_client = AIClient(host=OLLAMA_HOST, model_name=MODEL_NAME)

# ----------------------------
# IDA Helper Functions
# ----------------------------
def refresh_pseudocode(ea):
    try:
        view = ida_hexrays.open_pseudocode(ea, 0)
        if view:
            view.refresh_view(True)
    except Exception as e:
        logging.error(f"Failed to refresh pseudocode: {e}")

def get_function_address(name):
    return idc.get_name_ea_simple(name)

def valid_symbol_name(symbol_name):
    # Replace spaces with underscores
    symbol_name = symbol_name.replace(" ", "_")
    # Remove illegal characters
    symbol_name = re.sub(r'[^a-zA-Z0-9_]', '', symbol_name)
    # Default name if empty
    if not symbol_name:
        symbol_name = 'var'
    # Prefix if name starts with a digit
    if symbol_name and symbol_name[0].isdigit():
        symbol_name = f"var_{symbol_name}"
    # Ensure uniqueness
    original_name = symbol_name
    counter = 1
    while idc.get_name_ea_simple(symbol_name) != idaapi.BADADDR:
        symbol_name = f"{original_name}_{counter}"
        counter += 1
        if counter > RENAME_RETRIES:
            symbol_name = f"{original_name}_{int(time.time())}"
            break
    return symbol_name

# ----------------------------
# Pseudocode Processing
# ----------------------------
def extract_unnamed_symbols(pseudo_code):
    patterns = {
        'unnamed_functions': r'\bsub_[0-9A-Fa-f]+\b',
        'unnamed_globals': r'\b(?:dword|qword|byte|word|off)_[0-9A-Fa-f]+\b',
        'unnamed_params': r'\ba[0-9]+\b',
        'unnamed_locals': r'\bv[0-9]+\b'
    }

    results = {key: [] for key in patterns.keys()}

    lines = pseudo_code.split('\n')
    for line in lines:
        if '//' in line:
            line = line[:line.index('//')]

        for key, pattern in patterns.items():
            matches = re.finditer(pattern, line)
            for match in matches:
                symbol = match.group()
                if symbol not in results[key]:
                    results[key].append(symbol)

    return results

def get_pseudo_code(func_ea):
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return None
        pseudo_code = str(cfunc)
        symbols = extract_unnamed_symbols(pseudo_code)
        symbols['pseudo_code'] = pseudo_code
        return symbols
    except Exception as e:
        logging.error(f"Error in get_pseudo_code: {e}")
        return None

# ----------------------------
# Symbol Renaming
# ----------------------------
def set_symbol_name(addr, new_name, old_name=None, symbol_type='function'):
    try:
        if symbol_type == 'function':
            return idc.set_name(addr, new_name, idc.SN_NOCHECK | idc.SN_NOWARN)
        elif symbol_type == 'local':
            # 修复局部变量重命名问题
            func = idaapi.get_func(addr)
            if not func:
                return False

            # 获取函数起始地址
            func_start = func.start_ea

            # 获取cfunc对象
            cfunc = ida_hexrays.decompile(func_start)
            if not cfunc:
                return False

            # 查找局部变量
            for lvar in cfunc.lvars:
                if lvar.name == old_name:
                    # 使用正确的方法重命名局部变量
                    success = ida_hexrays.rename_lvar(func_start, old_name, new_name)
                    if success:
                        # 刷新伪代码视图
                        refresh_pseudocode(func_start)
                        return True
            return False
        elif symbol_type == 'global':
            return idc.set_name(addr, new_name, idc.SN_NOCHECK | idc.SN_NOWARN)
    except Exception as e:
        logging.error(f"Error renaming symbol: {e}")
        return False

def update_ida_symbols(rename_results, current_function_ea=None):
    for category, renames in rename_results.items():
        for old_name, new_name in renames.items():
            valid_name = valid_symbol_name(new_name)
            symbol_type = 'function'

            if category == 'Unnamed Locals':
                symbol_type = 'local'
            elif category == 'Unnamed Globals':
                symbol_type = 'global'

            addr = None
            if symbol_type == 'local':
                addr = current_function_ea
            elif symbol_type == 'global':
                addr = idc.get_name_ea_simple(old_name)
            else:
                addr = get_function_address(old_name)

            if addr != idaapi.BADADDR and addr is not None:
                if set_symbol_name(addr, valid_name, old_name, symbol_type):
                    logging.info(f"{category}: {old_name} -> {valid_name}")
                else:
                    logging.warning(f"Failed to rename {old_name} to {valid_name}")

# ----------------------------
# Prompt Template
# ----------------------------
PROMPT_TEMPLATE = '''
请重命名以下伪代码中的函数和变量：
{pseudo_code}

需要重命名的符号：
函数: {unnamed_functions}
局部变量: {unnamed_locals}

请使用驼峰命名法，确保名称反映功能。
格式：旧名 -> 新名
示例：sub_123456 -> readData
仅输出重命名结果，不要包含其他内容。
'''

def generate_prompt(pseudo_code, unnamed_functions, unnamed_locals):
    return PROMPT_TEMPLATE.format(
        pseudo_code=pseudo_code[:2000] + '...' if len(pseudo_code) > 2000 else pseudo_code,
        unnamed_functions=', '.join(unnamed_functions),
        unnamed_locals=', '.join(unnamed_locals)
    )

# ----------------------------
# Function Processing
# ----------------------------
class FunctionProcessor:
    def __init__(self, ai_client, timeout=TIMEOUT_SECONDS):
        self.ai_client = ai_client
        self.timeout = timeout

    def get_rename_suggestions(self, pseudo_code_info):
        prompt = generate_prompt(
            pseudo_code_info['pseudo_code'],
            pseudo_code_info['unnamed_functions'],
            pseudo_code_info['unnamed_locals']
        )

        try:
            response = self.ai_client.chat(
                messages=[{'role': 'user', 'content': prompt}],
                stream=False,
                options={'temperature': TEMPERATURE, 'top_p': TOP_P}
            )
            return response['message']['content'].strip()
        except Exception as e:
            logging.error(f"AI request failed: {e}")
            return ""

    def parse_rename_suggestions(self, response_text):
        rename_results = {}

        for line in response_text.splitlines():
            match = re.match(r'^(?P<old_name>[a-zA-Z0-9_]+)\s*->\s*(?P<new_name>[a-zA-Z0-9_]+)', line)
            if match:
                old_name = match.group('old_name')
                new_name = match.group('new_name')

                # Determine category
                if old_name.startswith('sub_'):
                    category = 'Unnamed Functions'
                elif old_name.startswith('v'):
                    category = 'Unnamed Locals'
                elif any(old_name.startswith(prefix) for prefix in ['dword_', 'qword_', 'byte_', 'word_', 'off_']):
                    category = 'Unnamed Globals'
                else:
                    category = 'Unnamed Functions'  # Default

                rename_results.setdefault(category, {})[old_name] = new_name

        return rename_results

    def process_function(self, func_ea):
        try:
            func_name = idc.get_func_name(func_ea)
            logging.info(f"Processing function: {func_name}")

            pseudo_code_info = get_pseudo_code(func_ea)
            if not pseudo_code_info:
                return

            # Check if there are any symbols to rename
            has_symbols = any(
                pseudo_code_info[key]
                for key in ['unnamed_functions', 'unnamed_locals', 'unnamed_globals']
            )

            if not has_symbols:
                logging.info(f"No unnamed symbols in function: {func_name}")
                return

            # Get rename suggestions from AI
            response = self.get_rename_suggestions(pseudo_code_info)
            if not response:
                return

            # Parse the response
            rename_results = self.parse_rename_suggestions(response)
            if not rename_results:
                return

            # Update symbols in IDA
            update_ida_symbols(rename_results, func_ea)

        except Exception as e:
            logging.error(f"Error processing function {func_name}: {e}")

# ----------------------------
# Main Execution
# ----------------------------
def main():
    processor = FunctionProcessor(ai_client)

    # Process all functions
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if re.match(r'^(sub_|loc_|unk_|func_)', func_name):
            processor.process_function(func_ea)

    logging.info("Function processing complete")
    print("Function processing complete")

if __name__ == '__main__':
    main()