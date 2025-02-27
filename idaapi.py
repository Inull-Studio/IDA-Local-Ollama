# -*- coding: utf-8 -*-
import sys
import os

# ----------------------------
# Setup Python Paths
# ----------------------------
def setup_python_paths(paths):
    """
    Appends existing paths to the system path for Python package imports.
    """
    for path in paths:
        if os.path.exists(path):
            sys.path.append(path)

# ----------------------------
# Configuration
# ----------------------------
PYTHON_PACKAGE_PATHS = [
    '/Users/lovensar/.pyenv/versions/3.9.6/lib/python3.9/site-packages',
    'D:/Program Files (x86)/python39/Lib/site-packages',
    'E:/python38/Lib/site-packages'
]

# Initialize Python paths
setup_python_paths(PYTHON_PACKAGE_PATHS)

import re
import time
import logging as log
from datetime import timedelta
from tqdm import tqdm
from openai import OpenAI
from ollama import Client, ResponseError
import idaapi
import idc
import idautils
import ida_hexrays
import ida_kernwin



# AI Configuration
OLLAMA_HOST = 'http://127.0.0.1:11434'
MODEL_NAME = 'deepseek-chat'
TIMEOUT_SECONDS = 60
MAX_RESPONSE_LENGTH = 8192
RENAME_RETRIES = 10
CHUNK_SIZE = 20000
BATCH_SIZE = 10
MAX_TURNS = 2
TEMPERATURE = 0.2
TOP_P = 0.8
MAX_TOKENS = 50000

# ----------------------------
# log Configuration
# ----------------------------
log.basicConfig(
    filename='ida_ai_integration.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=log.DEBUG  # Set to DEBUG for detailed logs
)

# ----------------------------
# AI Client Management (Modified for OpenAI API)
# ----------------------------
class AIClient:
    """Modified for DeepSeek API through OpenAI SDK"""
    def __init__(self, api_key, base_url):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self.model_name = MODEL_NAME

    def chat_completion(self, messages, stream=True, **kwargs):
        """Adapted for OpenAI API format"""
        try:
            return self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                stream=stream,
                **kwargs
            )
        except Exception as e:
            log.error(f"API call failed: {str(e)}")
            raise

# 初始化客户端
API_KEY = "sk-84af97bffeff494fa930f3e31a0ff0ad"
if not API_KEY:
    raise ValueError("DEEPSEEK_API_KEY environment variable is not set")

ai_client_1 = AIClient(api_key=API_KEY, base_url="https://api.deepseek.com/v1")
ai_client_2 = AIClient(api_key=API_KEY, base_url="https://api.deepseek.com/v1")

# ----------------------------
# IDA Helper Functions
# ----------------------------
def refresh_pseudocode(ea):
    """
    Refreshes the pseudocode view for a given function address.

    :param ea: Effective address of the function.
    """
    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            log.warning(f"Failed to decompile function at {hex(ea)}")
            return
        view = ida_hexrays.open_pseudocode(ea, 0)
        if view:
            view.refresh_view(True)
            log.info(f"Refreshed pseudocode for function at {hex(ea)}")
        else:
            log.warning(f"Failed to open pseudocode view for function at {hex(ea)}")
    except ida_hexrays.DecompilationFailure as e:
        log.error(f"Decompilation failed for function at {hex(ea)} - {e}")

def refresh_all_pseudocode():
    """
    Refreshes pseudocode for all functions in the IDA database.
    """
    for func_ea in idautils.Functions():
        refresh_pseudocode(func_ea)

def get_function_address(name):
    """
    Retrieves the address of a function by its name.

    :param name: Name of the function.
    :return: Address of the function or BADADDR if not found.
    """
    addr = idc.get_name_ea_simple(name)
    if addr == idaapi.BADADDR:
        log.warning(f"Could not find function address for: {name}")
    return addr

def save_idb(output_path=None):
    """
    Saves the current IDA database.

    :param output_path: Path to save the database. If None, saves to the current location.
    """
    try:
        if idc.save_database(output_path, 0):
            log.info("Database successfully saved")
        else:
            log.error("Failed to save database")
    except Exception as e:
        log.error(f"Error saving database: {e}")

def jump_to_output_window():
    """
    Activates the Output or Messages window in IDA.
    """
    output_window = ida_kernwin.find_widget("Output") or ida_kernwin.find_widget("Messages")
    if output_window:
        ida_kernwin.activate_widget(output_window, True)

# ----------------------------
# Symbol Validation
# ----------------------------
def valid_symbol_name(symbol_name):
    """
    Validates and sanitizes a symbol name to ensure it's suitable for IDA.

    :param symbol_name: Original symbol name.
    :return: Validated and unique symbol name.
    """
    log.debug(f"Original symbol_name: {symbol_name}")
    # Replace spaces with underscores
    symbol_name = symbol_name.replace(" ", "_")
    # Remove reserved prefixes
    reserved_prefixes = ['sub_', 'byte_', 'word_', 'dword_', 'qword_']
    for prefix in reserved_prefixes:
        if symbol_name.startswith(prefix):
            symbol_name = symbol_name[len(prefix):]
            break
    # Remove illegal characters
    symbol_name = re.sub(r'[^a-zA-Z0-9_]', '', symbol_name)
    # Default name if empty
    if not symbol_name:
        symbol_name = 'invalid_symbol'
    # Prefix if name starts with a digit
    if symbol_name and symbol_name[0].isdigit():
        symbol_name = f"func_{symbol_name}"
    # Ensure uniqueness
    original_name = symbol_name
    counter = 1
    while idc.get_name_ea_simple(symbol_name) != idaapi.BADADDR:
        symbol_name = f"rn_{original_name}_{counter}"
        counter += 1
        if counter > RENAME_RETRIES:
            symbol_name = f"FaRN_{original_name}_{int(time.time())}"
            break
    log.debug(f"Validated symbol_name: {symbol_name}")
    return symbol_name

# ----------------------------
# Timeout Decorator
# ----------------------------
def with_timeout(seconds):
    """
    Decorator to add a timeout to functions using signal (Unix only).

    :param seconds: Timeout in seconds.
    :return: Decorated function.
    """
    import signal
    from functools import wraps

    def decorator(func):
        @wraps(func)
        def handler(signum, frame):
            raise TimeoutError(f"Function {func.__name__} timed out after {seconds} seconds")

        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ----------------------------
# Pseudocode Processing
# ----------------------------
def chunk_text(text, max_length=CHUNK_SIZE):
    """
    Splits text into chunks of specified maximum length.

    :param text: Text to be chunked.
    :param max_length: Maximum length of each chunk.
    :return: List of text chunks.
    """
    return [text[i:i + max_length] for i in range(0, len(text), max_length)]

def summarize_pseudo_code(pseudo_code, max_length=CHUNK_SIZE):
    """
    Summarizes pseudocode if it exceeds the maximum length.

    :param pseudo_code: Original pseudocode.
    :param max_length: Maximum allowed length.
    :return: Summarized pseudocode.
    """
    if len(pseudo_code) <= max_length:
        return pseudo_code
    # Simple truncation; can be replaced with advanced summarization if needed
    return pseudo_code[:max_length] + '...'

def extract_unnamed_symbols(pseudo_code):
    """
    Extracts unnamed functions, globals, parameters, and local variables from pseudocode.

    :param pseudo_code: Decompiled pseudocode.
    :return: Dictionary with lists of unnamed symbols.
    """
    patterns = {
        'unnamed_functions': r'sub_[0-9A-Fa-f]+',
        'unnamed_globals': r'dword_[0-9A-Fa-f]+|qword_[0-9A-Fa-f]+|byte_[0-9A-Fa-f]+|word_[0-9A-Fa-f]+',
        'unnamed_params': r'a123[0-9]+',
        'unnamed_locals': r'v123[0-9]+'
    }
    extracted = {}
    for key, pattern in patterns.items():
        found = re.findall(pattern, pseudo_code)
        extracted[key] = list(set(found))
    return extracted

def get_pseudo_code(func_ea, cache=None):
    """
    Decompiles a function and extracts pseudocode and unnamed symbols.

    :param func_ea: Effective address of the function.
    :param cache: Optional cache to store decompiled results.
    :return: Dictionary with pseudocode and unnamed symbols or an error message.
    """
    try:
        if not idaapi.init_hexrays_plugin():
            log.error("Hex-Rays decompiler is not available.")
            return "Hex-Rays decompiler is not available."
        func = idaapi.get_func(func_ea)
        if not func:
            log.error("Invalid function address.")
            return "Invalid function address."
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            log.error("Failed to decompile the function.")
            return "Failed to decompile the function."
        pseudo_code = str(cfunc)
        symbols = extract_unnamed_symbols(pseudo_code)
        symbols['pseudo_code'] = pseudo_code
        return symbols
    except Exception as e:
        log.error(f"Error in get_pseudo_code: {e}")
        return f"Error: {str(e)}"

# ----------------------------
# Symbol Renaming
# ----------------------------
def set_symbol_name(addr, new_name):
    """
    Renames a symbol at a given address.

    :param addr: Address of the symbol.
    :param new_name: New name for the symbol.
    :return: Boolean indicating success.
    """
    if idc.set_name(addr, new_name, idc.SN_NOCHECK | idc.SN_NOWARN):
        log.info(f"Renamed symbol at {hex(addr)} to {new_name}")
        return True
    else:
        log.warning(f"Failed to rename symbol at {hex(addr)} to {new_name}")
        return False

def update_ida_symbols(rename_results):
    """
    Updates symbol names in IDA based on rename_results.

    :param rename_results: Dictionary containing rename mappings.
    """
    for category, renames in rename_results.items():
        for old_name, new_name in renames.items():
            valid_name = valid_symbol_name(new_name)
            addr = get_function_address(old_name)
            if addr and set_symbol_name(addr, valid_name):
                log.info(f"{category}: {old_name} -> {valid_name}")
            else:
                log.warning(f"Unable to update {category} name for {old_name}")

# ----------------------------
# Prompt Template
# ----------------------------
PROMPT_TEMPLATE = '''
您是顶尖的代码命名优化专家。
==========================
已知：
{pseudo_code}
请重命名以上伪代码中的函数和全局变量：
Unnamed Functions: {unnamed_functions}
Unnamed Globals: {unnamed_globals}
请使用驼峰命名法，确保名称具有描述性和功能性。
格式：
旧名 -> 新名
示例：
sub_123456 -> readData
仅按此格式输出，不要包含其他内容。
==========================
'''

def generate_prompt(pseudo_code, unnamed_functions, unnamed_globals):
    """
    Generates a prompt for the AI model based on pseudocode and unnamed symbols.

    :param pseudo_code: Pseudocode of the function.
    :param unnamed_functions: List of unnamed functions.
    :param unnamed_globals: List of unnamed global variables.
    :return: Formatted prompt string.
    """
    return PROMPT_TEMPLATE.format(
        pseudo_code=pseudo_code,
        unnamed_functions=', '.join(unnamed_functions),
        unnamed_globals=', '.join(unnamed_globals)
    )

# ----------------------------
# Function Processing (关键修改)
# ----------------------------
class FunctionProcessor:
    def __init__(self, ai_client1, ai_client2, timeout=TIMEOUT_SECONDS):
        self.ai_client1 = ai_client1
        self.ai_client2 = ai_client2
        self.timeout = timeout
        self.decompiled_cache = {}

    def _process_stream_response(self, response_stream):
        """处理OpenAI格式的流式响应"""
        optimized_code = []
        seen_lines = set()
        buffer = ""
        
        for chunk in response_stream:
            # 获取流式响应内容
            content = chunk.choices[0].delta.content or ""
            buffer += content
            
            # 检测结束标记
            if "</s>" in buffer:
                buffer = buffer.split("</s>")[0]
                break
                
            # 分割完整行
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                
                if line and line not in seen_lines:
                    optimized_code.append(line)
                    seen_lines.add(line)
                    log.debug(f"Optimized Line: {line}")

        return optimized_code

    @with_timeout(TIMEOUT_SECONDS)
    def get_optimized_code(self, pseudo_code_info):
        """使用OpenAI格式的API调用"""
        pseudo_code_chunks = chunk_text(pseudo_code_info['pseudo_code'], max_length=CHUNK_SIZE)
        optimized_lines = []
        for chunk in pseudo_code_chunks:
            summarized_chunk = summarize_pseudo_code(chunk)
            prompt = generate_prompt(
                pseudo_code=summarized_chunk,
                unnamed_functions=pseudo_code_info['unnamed_functions'],
                unnamed_globals=pseudo_code_info['unnamed_globals']
            )
            system_prompt = {"role": "system", "content": "You are a helpful assistant"}
            user_message = {'role': 'user', 'content': prompt}
            try:
                log.debug("### Requesting AI completion...")
                response = self.ai_client1.chat_completion(
                    messages=[system_prompt, user_message],
                    stream=False,
                    temperature=0.5,
                    max_tokens=1024,
                )
                log.debug("### AI completion received.")
                log.debug(response.choices[0].message.content)
                optimized_lines.extend(response.choices[0].message.content)
            except Exception as e:  # 捕获通用异常
                log.error(f"AIClient1 Error: {str(e)}")
            except TimeoutError as e:
                log.error(f"TimeoutError: {e}")
        return optimized_lines

    @with_timeout(TIMEOUT_SECONDS)
    def get_rename_results(self, pseudo_code_info, optimized_code):
        """批量重命名请求适配"""
        rename_results = {}
        categories = ['Unnamed Functions', 'Unnamed Globals']
        items = [
            (categories[0], pseudo_code_info['unnamed_functions']),
            (categories[1], pseudo_code_info['unnamed_globals'])
        ]
        
        for category, symbols in items:
            for i in range(0, len(symbols), BATCH_SIZE):
                batch = symbols[i:i + BATCH_SIZE]
                optimized_code_str = '\n'.join(optimized_code)
                query = f"""
请问在以下伪代码的重命名变换中：
---
{optimized_code_str}
---
中，以下符号被重命名为什么？这个命名如果没有表达有用信息则认为是无效命名（不能是类似于globalVar这种没意义的命名，应该是WriteBuff这类有具体功能的命名），请直接输出新名称，不要解释。
符号列表: {', '.join(batch)}
请按照以下格式输出，每个符号一行：
旧名 -> 新名
"""
                try:
                    system_prompt = {"role": "system", "content": "You are a helpful assistant"}
                    response = self.ai_client2.chat_completion(
                        messages=[system_prompt, {'role': 'user', 'content': query}],
                        stream=False,
                        temperature=0.5,
                        max_tokens=1024,
                    )
                    response_text = response.choices[0].message.content.strip()
                    for line in response_text.splitlines():
                        match = re.match(r'^(?P<old_name>[a-zA-Z0-9_]+)\s*->\s*(?P<new_name>[a-zA-Z0-9_]+)', line)
                        if match:
                            old_name = match.group('old_name')
                            new_name = match.group('new_name')
                            rename_results.setdefault(category, {})[old_name] = new_name
                            log.debug(f"Rename: {old_name} -> {new_name}")
                except Exception as e:  # 捕获通用异常
                    log.error(f"AIClient2 Error: {str(e)}")
                except TimeoutError as e:
                    log.error(f"TimeoutError: {e}")
        return rename_results

    def process_function(self, func_ea):
        """
        Processes a single function: decompiles, optimizes, renames symbols.

        :param func_ea: Effective address of the function.
        """
        try:
            func_name = idc.get_func_name(func_ea)
            log.info(f"Processing function: {func_name}")
            pseudo_code_info = get_pseudo_code(func_ea, cache=self.decompiled_cache)
            if isinstance(pseudo_code_info, str):
                log.error(pseudo_code_info)
                return
            # Only process if there are unnamed functions or globals
            if not any(pseudo_code_info[key] for key in ['unnamed_functions', 'unnamed_globals']):
                log.info(f"No unnamed symbols in function: {func_name}")
                return
            # Get optimized code from AI
            optimized_code = self.get_optimized_code(pseudo_code_info)
            log.info("### Optimized Code:")
            for line in optimized_code:
                log.info(line)
            # Get rename results from AI
            rename_results = self.get_rename_results(pseudo_code_info, optimized_code)
            if rename_results:
                # Update symbols in IDA
                update_ida_symbols(rename_results)
        except TimeoutError as e:
            log.error(f"Timeout Error: {e}")
        except Exception as e:
            log.error(f"Error processing function {func_name}: {e}")

def main():
    """
    Main function to process all relevant functions in the IDA database.
    """
    input_file_path = idc.get_input_file_path()
    if not input_file_path:
        log.error("Unable to get input file path. Ensure the file is loaded in IDA Pro.")
        print("### Unable to get input file path. Ensure the file is loaded in IDA Pro.")
        return

    file_name = os.path.splitext(os.path.basename(input_file_path))[0]
    output_dir = os.path.join(os.path.dirname(input_file_path), f"{file_name}_pseudo_code")
    os.makedirs(output_dir, exist_ok=True)

    log.info("### Function list with pseudocode:")
    print("### Function list with pseudocode:")
    print("### {:<20}{}".format("Address", "Name"))
    print("### " + "-" * 40)

    processor = FunctionProcessor(ai_client_1, ai_client_2)
    # 获取所有函数的地址列表
    func_addrs = list(idautils.Functions())
    lst_length = len(func_addrs)

    # 使用 tqdm 包装迭代器以显示进度条
    for _ in range(2):  # 根据原始脚本迭代两次
        for func_ea in tqdm(func_addrs, total=lst_length, desc="Processing Functions", position=0, leave=True):
            jump_to_output_window()
            func_name = idc.get_func_name(func_ea)
            log.info(f"### {hex(func_ea):<20} {func_name}")
            print("### {:<#020x} {}".format(func_ea, func_name))
            
            if re.match(r'^(sub_|loc_|unk_|func_)', func_name):
                # Process function sequentially
                processor.process_function(func_ea)

    log.info("### Function processing complete. Saving database and refreshing pseudocode...")
    print("### Function processing complete. Saving database and refreshing pseudocode...")
    save_idb()
    refresh_all_pseudocode()
    log.info("### All functions processed. Results saved.")
    print("### All functions processed. Results saved.")

# ----------------------------
# Program Entry Point
# ----------------------------
if __name__ == '__main__':
    start_time = time.time()
    main()
    end_time = time.time()
    elapsed_time = end_time - start_time

    # 使用 timedelta 将秒数转换为更易读的格式
    elapsed_timedelta = timedelta(seconds=elapsed_time)

    # 分离出小时和分钟
    hours, remainder = divmod(elapsed_timedelta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    # 打印结果
    print(f"程序执行时间: {hours}小时, {minutes}分钟, {seconds}秒")
