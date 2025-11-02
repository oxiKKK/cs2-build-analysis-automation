# CS2 Build Analysis Automation

```
      /$$$$$$  /$$$$$$   /$$$$$$        /$$$$$$$   /$$$$$$   /$$$$$$ 
     /$$__  $$/$$__  $$ /$$__  $$      | $$__  $$ /$$__  $$ /$$__  $$
    | $$  \__/ $$  \__/|__/  \ $$      | $$  \ $$| $$  \ $$| $$  \ $$
    | $$     |  $$$$$$   /$$$$$$/      | $$$$$$$ | $$$$$$$$| $$$$$$$$
    | $$      \____  $$ /$$____/       | $$__  $$| $$__  $$| $$__  $$
    | $$    $$/$$  \ $$| $$            | $$  \ $$| $$  | $$| $$  | $$
    |  $$$$$$/  $$$$$$/| $$$$$$$$      | $$$$$$$/| $$  | $$| $$  | $$
     \______/ \______/ |________/      |_______/ |__/  |__/|__/  |__/

    Automation of Build Analysis for CS2

    =============================================================

2025-07-30 13:27:19 INFO Timestamp: 2025-07-30 13:27:19
2025-07-30 13:27:19 INFO System: NT | Python 3.13.0
2025-07-30 13:27:19 INFO Available CPU Cores: 12
2025-07-30 13:27:19 INFO Initializing depot download and disassembly pipeline...
```

An automation tool for downloading CS2 depot binaries and performing disassembly with IDA Pro.

I use this tool to automate the process of reverse-engineering CS2 builds when new update is released. 

This tool can be used both for Linux and Windows binaries

## Prerequisites

- Windows 10/11
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- [DepotDownloader](https://github.com/SteamRE/DepotDownloader) (auto-downloads if not present)
- IDA Pro

## Installation

Create and activate virtual environment:

```bash
uv venv; .venv/Scripts/activate; uv sync
```

### DepotDownloader Setup

The script will automatically handle DepotDownloader for you:
1. On first run, if DepotDownloader is not found, you'll be prompted to:
   - **Auto-download**: The script will download the latest release from GitHub
   - **Manual path**: Provide the path to an existing DepotDownloader executable
2. The path is saved to `.config.json` for future runs
3. You can also specify the path via `--depotdownloader-path` argument

**Note**: DepotDownloader may prompt you to log in to Steam on first use. Your credentials will be cached for subsequent runs.

## Usage

### Basic usage (auto-generates output directory):
```bash
python main.py --app X --depot X --manifest-id X
```

### With custom output directory:
```bash
python main.py --app X --depot X --manifest-id X --output ./my_output
```

### Disassemble specific files:
```bash
python main.py --app X --depot X --manifest-id X --files-to-disassemble client.dll server.dll engine2.dll
```

### Automated mode (no confirmation prompts):
```bash
python main.py --app X --depot X --manifest-id X --auto-confirm --verbose
```

## Arguments

### Required Arguments:
- `--app` / `-a`: Steam app ID (e.g., 730 for CS2)
- `--depot` / `-d`: Steam depot ID 
- `--manifest-id` / `-m`: Manifest ID

### Optional Arguments:
- `--output` / `-o`: Output directory (auto-generates platform-prefixed directory if not provided)
- `--platform` / `-p`: Target binary format - `windows` (PE), `linux` (ELF), or `both` (default: windows)
- `--ida-path` / `-i`: Path to IDA Pro executable (saves to config for future use)
- `--depotdownloader-path`: Path to DepotDownloader executable (saves to config for future use)
- `--files-to-disassemble` / `-f`: Specific files to disassemble using relative paths
- `--jobs` / `-j`: Number of parallel disassembly jobs (default: CPU count)
- `--auto-confirm` / `-y`: Skip confirmation prompts for automation
- `--verbose` / `-v`: Enable detailed logging
- `--show-config`: Display saved configuration and last run parameters
- `--create-files-config`: Create/recreate the platform-aware files configuration

## Output Directory Format

When `--output` is not specified, directories are automatically generated as:
```
output_YYYY-MM-DD_APPID_DEPOTID_MANIFESTID
```

Example: `output_2025-07-30_730_2347771_1357183157457326032`