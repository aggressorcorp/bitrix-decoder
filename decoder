import streamlit as st
import os
import re
import base64


def decode_base64_safe(s):
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except:
        return s


def escape_php_string(s):
    s = s.replace("\\", "\\\\")
    s = s.replace("'", "\\'")
    return s


def parse_php_concatenation(s):
    matches = re.findall(r"'([^']*)'", s)
    return "".join(matches)


def extract_function_arrays(content):
    functions_map = {}

    pattern = re.compile(
        r'function\s+([a-zA-Z0-9_]+)\s*\(\s*\$[a-zA-Z0-9_]+\s*\)\s*\{'
        r'\s*static\s+\$[a-zA-Z0-9_]+\s*=\s*false\s*;'
        r'\s*if\s*\([^)]+\)\s*\$[a-zA-Z0-9_]+\s*=\s*array\s*\('
        r'(.*?)' 
        r'\)\s*;'
        r'\s*return\s+base64_decode\([^)]+\)\s*;'
        r'\s*\}',
        re.DOTALL | re.IGNORECASE
    )

    for match in pattern.finditer(content):
        func_name = match.group(1)
        array_body = match.group(2)
        full_match = match.group(0)

        decoded_items = []

        concat_pattern = re.compile(r"'[^']*'(?:\s*\.\s*'[^']*')*")

        for concat_match in concat_pattern.finditer(array_body):
            concat_str = concat_match.group(0)
            clean_b64 = parse_php_concatenation(concat_str)
            decoded_val = decode_base64_safe(clean_b64)
            decoded_items.append(decoded_val)

        if decoded_items:
            functions_map[func_name] = {
                'items': decoded_items,
                'full_code': full_match
            }

    return functions_map


def extract_globals_arrays(content):

    globals_map = {}

    pattern = re.compile(
        r'(?:<\?php\s+)?'
        r'\$GLOBALS\s*\[\s*[\'"]([a-zA-Z0-9_]+)[\'"]\s*\]\s*=\s*array\s*\(',
        re.IGNORECASE
    )

    for match in pattern.finditer(content):
        var_name = match.group(1)
        start_pos = match.start()

        open_count = 1
        pos = match.end()

        while pos < len(content) and open_count > 0:
            if content[pos] == '(':
                open_count += 1
            elif content[pos] == ')':
                open_count -= 1
            pos += 1

        if open_count == 0:
            semicolon_pos = content.find(';', pos)
            if semicolon_pos != -1:
                full_code = content[start_pos:semicolon_pos + 1]
                array_body = content[match.end():pos - 1]

                decoded_items = []

                b64_pattern = re.compile(r'base64_decode\s*\(\s*([^)]+)\s*\)')

                for b64_match in b64_pattern.finditer(array_body):
                    arg = b64_match.group(1)
                    clean_b64 = parse_php_concatenation(arg)
                    decoded_val = decode_base64_safe(clean_b64)
                    decoded_items.append(decoded_val)

                if decoded_items:
                    globals_map[var_name] = {
                        'items': decoded_items,
                        'full_code': full_code
                    }

    return globals_map


def replace_function_calls(content, functions_map, log):
    modified_content = content

    for func_name, data in functions_map.items():
        items = data['items']

        call_pattern = re.compile(
            re.escape(func_name) + r'\s*\(\s*(\d+)\s*\)'
        )

        matches = list(call_pattern.finditer(modified_content))

        if matches:
            log.append(f"Найдена функция: **{func_name}** ({len(items)} элементов)")

            def replace_call(match):
                index = int(match.group(1))
                if 0 <= index < len(items):
                    val = items[index]
                    return f"'{escape_php_string(val)}'"
                return match.group(0)

            modified_content = call_pattern.sub(replace_call, modified_content)
            log.append(f"Заменено {len(matches)} вызовов **{func_name}**")

    return modified_content


def replace_globals_calls(content, globals_map, log):
    modified_content = content

    for var_name, data in globals_map.items():
        items = data['items']

        log.append(f"Найден массив: **$GLOBALS['{var_name}']** ({len(items)} элементов)")

        usage_pattern = re.compile(
            r'\$GLOBALS\s*\[\s*[\'"]' + re.escape(var_name) + r'[\'"]\s*\]\s*\[\s*[\'"]?(\d+)[\'"]?\s*\]'
        )

        matches = list(usage_pattern.finditer(modified_content))

        if matches:
            def replace_usage(match):
                index = int(match.group(1))
                if 0 <= index < len(items):
                    val = items[index]
                    return f"'{escape_php_string(val)}'"
                return match.group(0)

            modified_content = usage_pattern.sub(replace_usage, modified_content)
            log.append(f"Заменено {len(matches)} вызовов **$GLOBALS['{var_name}']**")

    return modified_content


def remove_obfuscated_code(content, functions_map, globals_map):
    modified_content = content

    for func_name, data in functions_map.items():
        full_code = data['full_code']
        if full_code in modified_content:
            modified_content = modified_content.replace(
                full_code,
                f"\n/* DEOBFUSCATED: function {func_name}() removed */\n"
            )

    for var_name, data in globals_map.items():
        full_code = data['full_code']
        if full_code in modified_content:
            modified_content = modified_content.replace(
                full_code,
                f"\n/* DEOBFUSCATED: $GLOBALS['{var_name}'] removed */\n"
            )

    return modified_content


def process_file_content(content, file_path):
    log = []

    functions_map = extract_function_arrays(content)
    globals_map = extract_globals_arrays(content)

    if not functions_map and not globals_map:
        return content, False, ["Паттерны обфускации не найдены"]

    modified_content = replace_function_calls(content, functions_map, log)
    modified_content = replace_globals_calls(modified_content, globals_map, log)
    modified_content = remove_obfuscated_code(modified_content, functions_map, globals_map)
    modified = (modified_content != content)

    return modified_content, modified, log


def scan_files(start_path):
    suspicious_files = []
    total_files = 0

    for root, dirs, files in os.walk(start_path):
        for file in files:
            if file.endswith(".php"):
                total_files += 1
                full_path = os.path.join(root, file)

                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    is_suspicious = False

                    if re.search(r'function\s+[a-zA-Z0-9_]+\s*\([^)]+\)\s*\{\s*static\s+\$[a-zA-Z0-9_]+\s*=\s*false',
                                 content):
                        if 'base64_decode' in content and 'array(' in content:
                            is_suspicious = True

                    if re.search(r'\$GLOBALS\s*\[\s*[\'"][a-zA-Z0-9_]+[\'"]\s*\]\s*=\s*array\s*\(', content):
                        if 'base64_decode' in content:
                            is_suspicious = True

                    if is_suspicious:
                        suspicious_files.append(full_path)

                except Exception as e:
                    pass

    return suspicious_files, total_files



st.set_page_config(page_title="PHP Deobfuscator", layout="wide")
st.title("PHP Deobfuscator")
st.markdown("Инструмент для деобфускации PHP файлов (функции со static array + $GLOBALS массивы)")

path_input = st.text_input(
    "Введите путь к папке или файлу:",
    value="",
    help="Можно указать путь к папке (будут проверены все PHP файлы) или к конкретному файлу"
)

if 'scan_results' not in st.session_state:
    st.session_state['scan_results'] = []
if 'scan_done' not in st.session_state:
    st.session_state['scan_done'] = False

col1, col2 = st.columns([1, 4])
with col1:
    scan_button = st.button("Сканировать", use_container_width=True)

if scan_button:
    if not path_input or not os.path.exists(path_input):
        st.error("Путь не существует походу...")
    else:
        with st.spinner('Сканирование файловой системы...'):
            if os.path.isfile(path_input):
                suspicious = [path_input] if path_input.endswith('.php') else []
                count = 1
            else:
                suspicious, count = scan_files(path_input)

            st.session_state['scan_results'] = suspicious
            st.session_state['scan_done'] = True

        if len(suspicious) > 0:
            st.warning(f"Найдено файлов с обфускацией: **{len(suspicious)}** (из {count} проверенных)")
        else:
            st.success(f"Вроде чисто. Проверено {count} файлов, обфускация не найдена.")

if st.session_state['scan_done'] and st.session_state['scan_results']:
    st.divider()
    st.subheader("Файлы для обработки:")

    files_to_process = []

    with st.container(height=300):
        select_all = st.checkbox("Выбрать все", value=True)
        st.markdown("---")

        for file_path in st.session_state['scan_results']:
            rel_path = os.path.relpath(file_path, start=path_input) if os.path.isdir(path_input) else os.path.basename(
                file_path)

            if st.checkbox(
                    f"{rel_path}",
                    value=select_all,
                    key=f"file_{file_path}"
            ):
                files_to_process.append(file_path)

    st.info(f"Выбрано для обработки: **{len(files_to_process)}** файлов")

    col1, col2, col3 = st.columns([1, 1, 3])
    with col1:
        process_button = st.button("Деобфусцировать", use_container_width=True)

    if process_button:
        if not files_to_process:
            st.error("Ничего не выбрано!")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()

            processed_count = 0
            error_count = 0

            log_container = st.expander("Подробный лог", expanded=True)

            with log_container:
                for i, file_path in enumerate(files_to_process):
                    rel_path = os.path.relpath(file_path, start=path_input) if os.path.isdir(
                        path_input) else os.path.basename(file_path)
                    status_text.text(f"Обработка: {rel_path}...")

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            original_content = f.read()

                        new_content, modified, logs = process_file_content(original_content, file_path)

                        if modified:
                            backup_path = file_path + '.backup'
                            with open(backup_path, 'w', encoding='utf-8') as f:
                                f.write(original_content)

                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(new_content)

                            st.markdown(f"### Успешно **{rel_path}**")
                            st.caption(f"Бэкап: `{os.path.basename(backup_path)}`")

                            for log_msg in logs:
                                st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;{log_msg}")

                            processed_count += 1
                        else:
                            st.markdown(f"### Варнинг **{rel_path}**")
                            for log_msg in logs:
                                st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;{log_msg}")

                    except Exception as e:
                        st.error(f"Ошибка **{rel_path}**: {str(e)}")
                        error_count += 1
                    progress_bar.progress((i + 1) / len(files_to_process))

            status_text.empty()
            progress_bar.empty()

            st.divider()
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Успешно обработано", processed_count)
            with col2:
                st.metric("Без изменений", len(files_to_process) - processed_count - error_count)
            with col3:
                st.metric("Ошибки", error_count)

            if processed_count > 0:
                st.success("Деобфускация завершена. Что бы не мучать ручки")
                st.info("Бэкапы оригинальных файлов сохранены с расширением `.backup`")
