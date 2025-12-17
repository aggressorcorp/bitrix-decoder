# PHP Deobfuscator Tool
A Streamlit-based utility designed to analyze, clean, and deobfuscate PHP scripts. This tool specifically targets common obfuscation techniques such as `$GLOBALS` array mapping, dynamic function call obfuscation, and Base64-encoded payloads.
## Features
- **Recursive Scanning:** Scan entire directories for suspicious PHP files.
- **Dynamic String Resolution:** Parses PHP concatenations and escapes strings for better readability.
- **Array Mapping Extraction:** Automatically identifies and extracts hidden mapping arrays used in obfuscated `$GLOBALS` or function-based lookups.
- **Automated Replacement:** Replaces obfuscated calls (e.g., `$a = $GLOBALS['var']('payload')`) with their decoded equivalents.
- **Code Cleanup:** Removes boilerplate obfuscation blocks and restores the logic to a more readable state.
- **Safety First:** Includes safe Base64 decoding and creates backups before modifying files.
- **Interactive UI:** Built with Streamlit, providing real-time progress bars, logs, and file selection.

## Project Structure
- : The main Streamlit application for batch processing and deobfuscation logic. `deobfuscator.py`
- / : Specialized tools for targeted function and global variable replacements. `funcreplacer.py``replacer.py`
- : Integration or crawler logic (if related to site analysis). `warnsite.py`

## Installation
1. **Clone the repository:**
``` bash
    git clone <repository-url>
    cd WarmSite
```
1. **Set up a virtual environment:**
``` bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```
1. **Install dependencies:** _Note: Ensure you have and any other required libraries installed.`streamlit`_
``` bash
    pip install streamlit pandas
```
## Usage
1. **Run the application:**
``` bash
    streamlit run deobfuscator.py
```
1. **Configure the scan:**
    - Enter the **directory path** containing your PHP files in the sidebar/input field.
    - Click **Scan Files** to identify suspicious scripts.
    - Select the specific files you wish to process from the generated list.

2. **Process:**
    - Click **Process Files**. The tool will analyze the obfuscation patterns, perform replacements, and save the cleaned versions.
    - Check the **Log Container** for a detailed report of changes made to each file.

## Technical Details
The tool employs several regex-based passes to identify:
- : Locates large global arrays used for character/function mapping. `extract_globals_arrays`
- : Resolves indirect function calls. `replace_function_calls`
- : Strips out the initial "shredder" or "loader" code blocks typically found at the top of obfuscated files. `remove_obfuscated_code`

## Disclaimer
This tool is intended for security research and malware analysis purposes only. Always handle suspicious files in a sandboxed environment. The authors are not responsible for any damage caused by the use of this software.

