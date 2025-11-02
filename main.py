import subprocess
import argparse
import shutil
import os
import sys
import concurrent.futures
import json
import logging
import psutil
import platform
import zipfile
import urllib.request
from pathlib import Path
from tqdm import tqdm
import coloredlogs
from datetime import datetime

VERSION = 1.0


# Setup colored logging
logger = logging.getLogger(__name__)
coloredlogs.install(
    level="INFO",
    logger=logger,
    fmt="%(asctime)s %(levelname)s %(message)s",
    level_styles={
        "debug": {"color": "cyan"},
        "info": {"color": "green"},
        "warning": {"color": "yellow"},
        "error": {"color": "red", "bold": True},
        "critical": {"color": "red", "bold": True, "background": "white"},
    },
)

CONFIG_FILE = Path(__file__).parent / ".config.json"
FILES_CONFIG_FILE = Path(__file__).parent / ".files_config.json"


def load_config():
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load config file: {e}")
    return {}


def save_config(config):
    """Save configuration to file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        logger.debug(f"Configuration saved to {CONFIG_FILE}")
    except IOError as e:
        logger.warning(f"Failed to save config file: {e}")


def load_files_config():
    """Load files configuration from file."""
    if FILES_CONFIG_FILE.exists():
        try:
            with open(FILES_CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load files config file: {e}")
    return {}


def save_files_config(files_config):
    """Save files configuration to file."""
    try:
        with open(FILES_CONFIG_FILE, "w") as f:
            json.dump(files_config, f, indent=2)
        logger.debug(f"Files configuration saved to {FILES_CONFIG_FILE}")
    except IOError as e:
        logger.warning(f"Failed to save files config file: {e}")


def get_depotdownloader_path():
    """Get the path to DepotDownloader executable."""
    script_dir = Path(__file__).parent

    # Check common locations
    if sys.platform == "win32":
        exe_name = "DepotDownloader.exe"
    else:
        exe_name = "DepotDownloader"

    # Check in script directory
    local_path = script_dir / exe_name
    if local_path.exists():
        return str(local_path)

    # Check in DepotDownloader subdirectory
    subdir_path = script_dir / "DepotDownloader" / exe_name
    if subdir_path.exists():
        return str(subdir_path)

    return None


def download_depotdownloader():
    """Download DepotDownloader from GitHub releases."""
    script_dir = Path(__file__).parent
    depot_dir = script_dir / "DepotDownloader"

    info("Downloading DepotDownloader from GitHub...")

    try:
        # Get latest release info from GitHub API
        api_url = "https://api.github.com/repos/SteamRE/DepotDownloader/releases/latest"

        with urllib.request.urlopen(api_url) as response:
            release_data = json.loads(response.read().decode())

        # Find the appropriate asset for the platform
        asset_url = None
        asset_name = None

        machine = platform.machine().lower()
        is_arm = "arm" in machine or "aarch64" in machine

        for asset in release_data.get("assets", []):
            name = asset["name"].lower()

            if sys.platform == "win32":
                # Windows x64
                if (
                    "windows" in name
                    and "x64" in name
                    and not "arm" in name
                    and name.endswith(".zip")
                ):
                    asset_url = asset["browser_download_url"]
                    asset_name = asset["name"]
                    break
                # Fallback: Windows without explicit x64 but not arm
                elif "windows" in name and not "arm" in name and name.endswith(".zip"):
                    asset_url = asset["browser_download_url"]
                    asset_name = asset["name"]
            elif sys.platform == "linux":
                if is_arm:
                    if "linux" in name and "arm64" in name and name.endswith(".zip"):
                        asset_url = asset["browser_download_url"]
                        asset_name = asset["name"]
                        break
                else:
                    if (
                        "linux" in name
                        and "x64" in name
                        and not "arm" in name
                        and name.endswith(".zip")
                    ):
                        asset_url = asset["browser_download_url"]
                        asset_name = asset["name"]
                        break
            elif sys.platform == "darwin":
                if is_arm:
                    if "macos" in name and "arm64" in name and name.endswith(".zip"):
                        asset_url = asset["browser_download_url"]
                        asset_name = asset["name"]
                        break
                else:
                    if "macos" in name and "x64" in name and name.endswith(".zip"):
                        asset_url = asset["browser_download_url"]
                        asset_name = asset["name"]
                        break

        if not asset_url:
            error("Could not find suitable DepotDownloader release for your platform")
            error(f"Platform: {sys.platform}, Architecture: {machine}")
            info("Available assets:")
            for asset in release_data.get("assets", []):
                info(f"  - {asset['name']}")
            return False

        info(f"Detected platform: {sys.platform}, Architecture: {machine}")
        info(f"Downloading {asset_name}...")

        # Create temporary directory for download
        zip_path = script_dir / asset_name

        # Download with progress bar
        with urllib.request.urlopen(asset_url) as response:
            total_size = int(response.headers.get("Content-Length", 0))
            block_size = 8192

            with open(zip_path, "wb") as out_file:
                with tqdm(
                    total=total_size, unit="B", unit_scale=True, desc="Downloading"
                ) as pbar:
                    while True:
                        chunk = response.read(block_size)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        pbar.update(len(chunk))

        info("Extracting DepotDownloader...")

        # Extract the zip file
        depot_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(depot_dir)

        # Clean up zip file
        zip_path.unlink()

        # Find the executable
        depot_path = get_depotdownloader_path()
        if depot_path:
            info(f"DepotDownloader successfully installed at: {depot_path}")
            return depot_path
        else:
            error("DepotDownloader was extracted but executable not found")
            return False

    except Exception as e:
        error(f"Failed to download DepotDownloader: {e}")
        return False


def ensure_depotdownloader(config):
    """Ensure DepotDownloader is available, download if necessary."""
    # Check if path is in config
    depot_path = config.get("depotdownloader_path")

    if depot_path and os.path.exists(depot_path):
        info(f"Using DepotDownloader from config: {depot_path}")
        return depot_path

    # Check local installation
    depot_path = get_depotdownloader_path()
    if depot_path:
        info(f"Found local DepotDownloader: {depot_path}")
        config["depotdownloader_path"] = depot_path
        save_config(config)
        return depot_path

    # Not found, ask user
    info("DepotDownloader not found locally.")
    info("DepotDownloader is required to download Steam depots.")
    info("GitHub: https://github.com/SteamRE/DepotDownloader")

    while True:
        choice = input(
            "\nWould you like to:\n  [1] Auto-download DepotDownloader\n  [2] Enter path to existing DepotDownloader executable\n  [3] Exit\nChoice: "
        ).strip()

        if choice == "1":
            depot_path = download_depotdownloader()
            if depot_path:
                config["depotdownloader_path"] = depot_path
                save_config(config)
                return depot_path
            else:
                error("Failed to download DepotDownloader")
                continue
        elif choice == "2":
            depot_path = input(
                "Enter full path to DepotDownloader executable: "
            ).strip()
            if os.path.exists(depot_path):
                info(f"Using DepotDownloader at: {depot_path}")
                config["depotdownloader_path"] = depot_path
                save_config(config)
                return depot_path
            else:
                error(f"File not found: {depot_path}")
                continue
        elif choice == "3":
            info("Exiting...")
            return None
        else:
            warning("Invalid choice. Please enter 1, 2, or 3.")

    return None


def create_default_files_config():
    """Create a default files configuration file with common CS2 files."""
    default_files = {
        "description": "Configuration file for specifying which DLL/EXE files to disassemble using relative paths from depot base",
        "files_to_disassemble": {
            "windows": [
                "game/bin/win64/engine2.dll",
                "game/bin/win64/tier0.dll",
                "game/bin/win64/animationsystem.dll",
                "game/bin/win64/rendersystemdx11.dll",
                "game/bin/win64/rendersystemempty.dll",
                "game/bin/win64/rendersystemvulkan.dll",
                "game/bin/win64/materialsystem2.dll",
                "game/bin/win64/resourcesystem.dll",
                "game/bin/win64/networksystem.dll",
                "game/bin/win64/schemasystem.dll",
                "game/bin/win64/soundsystem.dll",
                "game/bin/win64/inputsystem.dll",
                "game/bin/win64/panorama.dll",
                "game/bin/win64/panoramauiclient.dll",
                "game/bin/win64/scenesystem.dll",
                "game/bin/win64/cs2.exe",
                "game/bin/win64/filesystem_stdio.dll",
                "game/bin/win64/imemanager.dll",
                "game/bin/win64/meshsystem.dll",
                "game/bin/win64/navsystem.dll",
                "game/bin/win64/valve_avi.dll",
                "game/bin/win64/valve_webm.dll",
                "game/bin/win64/valve_wmf.dll",
                "game/bin/win64/worldrenderer.dll",
                "game/csgo/bin/win64/client.dll",
                "game/csgo/bin/win64/host.dll",
                "game/csgo/bin/win64/matchmaking.dll",
                "game/csgo/bin/win64/server.dll",
            ],
            "linux": [
                "game/bin/linuxsteamrt64/libengine2.so",
                "game/bin/linuxsteamrt64/libtier0.so",
                "game/bin/linuxsteamrt64/libanimationsystem.so",
                "game/bin/linuxsteamrt64/librendersystemvulkan.so",
                "game/bin/linuxsteamrt64/libmaterialsystem2.so",
                "game/bin/linuxsteamrt64/libresourcesystem.so",
                "game/bin/linuxsteamrt64/libnetworksystem.so",
                "game/bin/linuxsteamrt64/libschemasystem.so",
                "game/bin/linuxsteamrt64/libsoundsystem.so",
                "game/bin/linuxsteamrt64/libinputsystem.so",
                "game/bin/linuxsteamrt64/libpanorama.so",
                "game/bin/linuxsteamrt64/libpanoramauiclient.so",
                "game/bin/linuxsteamrt64/libscenesystem.so",
                "game/bin/linuxsteamrt64/cs2",
                "game/bin/linuxsteamrt64/libfilesystem_stdio.so",
                "game/bin/linuxsteamrt64/libmeshsystem.so",
                "game/bin/linuxsteamrt64/libworldrenderer.so",
                "game/csgo/bin/linuxsteamrt64/libclient.so",
                "game/csgo/bin/linuxsteamrt64/libhost.so",
                "game/csgo/bin/linuxsteamrt64/libmatchmaking.so",
                "game/csgo/bin/linuxsteamrt64/libserver.so",
            ],
        },
        "default_platform": "windows",
        "notes": "Specify relative paths from the depot base directory. Use forward slashes for paths. Platform refers to the target binary format (windows=PE, linux=ELF), not the host system running IDA.",
    }

    save_files_config(default_files)
    info(f"Created default files configuration at {FILES_CONFIG_FILE}")
    return default_files


def info(*args) -> None:
    logger.info(" ".join(str(arg) for arg in args))


def warning(*args) -> None:
    logger.warning(" ".join(str(arg) for arg in args))


def error(*args) -> None:
    logger.error(" ".join(str(arg) for arg in args))


verbose_log = False


def resolve_files_to_disassemble(files_arg, files_config, platform=None):
    """Resolve the files to disassemble based on argument, configuration, and platform."""
    if not files_arg:
        # No files specified, use default from config
        files_to_disassemble = files_config.get("files_to_disassemble", {})

        # Handle both old format (list) and new format (dict with platforms)
        if isinstance(files_to_disassemble, list):
            # Old format - treat as windows files
            info(
                f"Using {len(files_to_disassemble)} files from configuration (legacy format)"
            )
            return files_to_disassemble
        elif isinstance(files_to_disassemble, dict):
            # New format with platforms
            default_platform = platform or files_config.get(
                "default_platform", "windows"
            )

            if default_platform == "both":
                # Get both platforms
                windows_files = files_to_disassemble.get("windows", [])
                linux_files = files_to_disassemble.get("linux", [])
                all_files = windows_files + linux_files
                info(
                    f"Using {len(all_files)} files from configuration (both binary formats: {len(windows_files)} PE, {len(linux_files)} ELF)"
                )
                return all_files
            else:
                # Get specific platform
                platform_files = files_to_disassemble.get(default_platform, [])
                info(
                    f"Using {len(platform_files)} {default_platform} binary files from configuration"
                )
                return platform_files

        return []

    # Files specified via command line argument
    resolved_files = []
    for item in files_arg:
        # Normalize path separators for cross-platform compatibility
        normalized_path = item.replace("\\", "/")
        resolved_files.append(normalized_path)

    return resolved_files


verbose_log = False


def verbose(*args) -> None:
    global verbose_log
    if verbose_log:
        logger.debug(" ".join(str(arg) for arg in args))


def print_banner():
    """Print a hacker-style banner when the script starts."""
    banner = rf"""
      /$$$$$$  /$$$$$$   /$$$$$$        /$$$$$$$   /$$$$$$   /$$$$$$ 
     /$$__  $$/$$__  $$ /$$__  $$      | $$__  $$ /$$__  $$ /$$__  $$
    | $$  \__/ $$  \__/|__/  \ $$      | $$  \ $$| $$  \ $$| $$  \ $$
    | $$     |  $$$$$$   /$$$$$$/      | $$$$$$$ | $$$$$$$$| $$$$$$$$
    | $$      \____  $$ /$$____/       | $$__  $$| $$__  $$| $$__  $$
    | $$    $$/$$  \ $$| $$            | $$  \ $$| $$  | $$| $$  | $$
    |  $$$$$$/  $$$$$$/| $$$$$$$$      | $$$$$$$/| $$  | $$| $$  | $$
     \______/ \______/ |________/      |_______/ |__/  |__/|__/  |__/

    Automation of Build Analysis for CS2 V{VERSION}

    ============================================================="""

    print("\033[97m" + banner + "\033[0m")
    print()


class DepotDownloader:
    def __init__(
        self,
        app_id: int,
        depot_id: int,
        manifest_id: int,
        output_path: str,
        ida_path: str,
        depotdownloader_path: str,
        files_to_disassemble: list[str] = None,
        jobs: int = -1,
        disassemble_all: bool = False,
        auto_confirm: bool = False,
        platform: str = "windows",
    ) -> None:
        self._app_id = app_id
        self._depot_id = depot_id
        self._manifest_id = manifest_id
        self._output_path = output_path
        self._ida_path = ida_path
        self._depotdownloader_path = depotdownloader_path
        self._files_to_disassemble = files_to_disassemble or []
        self._jobs = jobs
        self._disassemble_all = disassemble_all
        self._auto_confirm = auto_confirm
        self._platform = platform

    def is_depotdownloader_available(self) -> bool:
        """Check if DepotDownloader is available."""
        return os.path.exists(self._depotdownloader_path)

    def is_ida_installed(self) -> bool:
        """Check if IDA is installed."""
        return shutil.which(self._ida_path) is not None

    def _create_filelist(self) -> str:
        """
        Create a filelist file for DepotDownloader to only download executable files.
        Returns the path to the created filelist file.
        """
        script_dir = Path(__file__).parent
        filelist_path = script_dir / ".depotdownloader_filelist.txt"

        info("Creating filelist for executable files only...")

        # Define regex patterns for executable files based on platform
        patterns = []

        if self._platform == "windows" or self._platform == "both":
            # Match .dll and .exe files
            patterns.append("regex:.*\\.dll$")
            patterns.append("regex:.*\\.exe$")

        if self._platform == "linux" or self._platform == "both":
            # Match .so files (including versioned .so files like .so.1)
            patterns.append("regex:.*\\.so(\\..*)?$")
            # Match common executable paths in bin directories without extensions
            patterns.append("regex:.*/bin/.*/[^/]*$")

        # Write patterns to filelist
        try:
            with open(filelist_path, "w") as f:
                for pattern in patterns:
                    f.write(f"{pattern}\n")

            info(f"Created filelist with {len(patterns)} pattern(s):")
            for pattern in patterns:
                verbose(f"  {pattern}")

            return str(filelist_path)
        except Exception as e:
            error(f"Failed to create filelist: {e}")
            return None

    def download(self) -> None:
        """
        Downloads a Steam depot using DepotDownloader.

        Parameters:
        - app_id: The ID of the app.
        - depot_id: The ID of the depot.
        - manifest_id: The ID of the manifest.
        - output_path: The path where the depot should be saved.
        """

        info(f"Using {self._output_path} as output directory")

        # Check if output directory already exists and has content
        if os.path.exists(self._output_path) and os.listdir(self._output_path):
            info(
                f"Output directory already exists and contains files: {self._output_path}"
            )

            # Check if there are any executable files based on platform
            executable_files = []
            for root, dirs, files in os.walk(self._output_path):
                for file in files:
                    file_path = os.path.join(root, file)

                    # Check for platform-appropriate executables
                    if self._platform == "windows":
                        # Check for Windows PE files
                        if file.lower().endswith((".dll", ".exe")):
                            executable_files.append(file)
                    elif self._platform == "linux":
                        # Check for Linux ELF files
                        is_so = file.lower().endswith(".so")
                        is_executable = (
                            not "." in file
                            and os.access(file_path, os.X_OK)
                            and not os.path.isdir(file_path)
                        )
                        if is_so or is_executable:
                            executable_files.append(file)
                    elif self._platform == "both":
                        # Check for both Windows and Linux executables
                        is_windows = file.lower().endswith((".dll", ".exe"))
                        is_so = file.lower().endswith(".so")
                        is_executable = (
                            not "." in file
                            and os.access(file_path, os.X_OK)
                            and not os.path.isdir(file_path)
                        )
                        if is_windows or is_so or is_executable:
                            executable_files.append(file)
            if executable_files:
                platform_desc = {
                    "windows": "PE binaries (.dll/.exe)",
                    "linux": "ELF binaries (.so/executables)",
                    "both": "PE/ELF binaries",
                }.get(self._platform, "executable files")

                info(
                    f"Found {len(executable_files)} {platform_desc} in existing directory"
                )
                info("Skipping download, proceeding directly to disassembly...")
                self._post_download()
                return
            else:
                platform_desc = {
                    "windows": "PE binaries (.dll/.exe)",
                    "linux": "ELF binaries (.so/executables)",
                    "both": "PE/ELF binaries",
                }.get(self._platform, "executable files")
                info(
                    f"No {platform_desc} found in existing directory, will re-download"
                )

        if not self.is_depotdownloader_available():
            error(f"DepotDownloader is not available at: {self._depotdownloader_path}")
            return

        if not self.is_ida_installed():
            error(f"{self._ida_path} is not installed.")
            return

        info(f"Starting download to: {self._output_path}")
        info(f"Using DepotDownloader: {self._depotdownloader_path}")

        # Create filelist for executable files only
        filelist_path = self._create_filelist()
        if not filelist_path:
            error("Failed to create filelist, aborting download")
            return

        try:
            # DepotDownloader command format:
            # DepotDownloader -app <appid> -depot <depotid> -manifest <manifestid> -dir <output> -filelist <filelist>
            command = [
                self._depotdownloader_path,
                "-app",
                str(self._app_id),
                "-depot",
                str(self._depot_id),
                "-manifest",
                str(self._manifest_id),
                "-dir",
                self._output_path,
                "-filelist",
                filelist_path,
            ]

            info("Running DepotDownloader (this may take a while)...")
            info("Downloading executable files only (.dll, .exe, .so)...")
            info("You may be prompted to login to Steam if credentials are not cached.")

            # Run with real-time output
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )

            # Print output in real-time
            for line in process.stdout:
                print(line, end="")

            process.wait()

            if process.returncode != 0:
                error(f"DepotDownloader failed with return code: {process.returncode}")
                return

            info("Download completed successfully!")
        except subprocess.CalledProcessError as e:
            error("Exception:", e)
            info("Output:", e.output)
            if e.stderr:
                info("Error output:", e.stderr)
        except Exception as e:
            error(f"Failed to run DepotDownloader: {e}")
            return

        self._post_download()

    def _post_download(self) -> None:
        # No need to filter since we're using filelist to download only executables
        info("Download complete, proceeding to disassembly...")
        self._disassemble()

    def _filter_downloaded_files(self) -> None:
        """
        Filters the downloaded files to only include the ones that are needed.
        Note: This is now mostly obsolete since we use filelist, but kept for backwards compatibility
        with existing output directories that may contain .vpk files.
        """
        info("Checking for non-executable files to clean up...")

        files_deleted = 0
        for root, dirs, files in os.walk(self._output_path):
            for file in files:
                if file.endswith(".vpk"):
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                        files_deleted += 1
                        verbose(f"Deleted: {file_path}")
                    except Exception as e:
                        warning(f"Failed to delete {file_path}: {e}")

        if files_deleted > 0:
            info(f"Cleaned up {files_deleted} non-executable file(s)")
            # delete empty directories
            for root, dirs, files in os.walk(self._output_path, topdown=False):
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    try:
                        if not os.listdir(dir_path):  # Check if directory is empty
                            os.rmdir(dir_path)
                            verbose(f"Deleted empty directory: {dir_path}")
                    except Exception as e:
                        warning(f"Failed to delete directory {dir_path}: {e}")

    def _disassemble(self) -> None:
        """
        Disassembles the downloaded files using ida.
        """
        info("Preparing disassembly...")

        # Determine files to disassemble
        if self._disassemble_all or not self._files_to_disassemble:
            # If disassemble_all is True or no specific files specified, disassemble all executables
            files_to_disassemble = []
            for root, dirs, files in os.walk(self._output_path):
                for file in files:
                    # Check for Windows executables (.dll, .exe)
                    is_windows_exe = file.lower().endswith((".dll", ".exe"))
                    file_path = os.path.join(root, file)
                    # Check for Linux executables (.so, or no extension but ELF header)
                    is_linux_exe = False
                    if file.lower().endswith(".so"):
                        is_linux_exe = True
                    elif "." not in file and not os.path.isdir(file_path):
                        # Peek first 4 bytes for ELF header
                        try:
                            with open(file_path, "rb") as f:
                                magic = f.read(4)
                            if magic == b"\x7fELF":
                                is_linux_exe = True
                        except Exception as e:
                            warning(f"Failed to read file header for {file_path}: {e}")
                    if is_windows_exe or is_linux_exe:
                        # Determine platform based on path or file extension
                        platform_type = "Windows" if is_windows_exe else "Linux"
                        files_to_disassemble.append((file_path, platform_type))
            if not files_to_disassemble:
                warning("No executable files (.dll/.exe/.so) found to disassemble.")
                return

            info(f"Found {len(files_to_disassemble)} executable files to disassemble:")
            # Group by binary format for display
            windows_count = sum(
                1 for _, platform in files_to_disassemble if platform == "Windows"
            )
            linux_count = sum(
                1 for _, platform in files_to_disassemble if platform == "Linux"
            )
            info(f"  • PE binaries: {windows_count} files (.dll/.exe)")
            info(f"  • ELF binaries: {linux_count} files (.so/executables)")

            # Extract just the file paths for further processing
            files_to_disassemble = [file_path for file_path, _ in files_to_disassemble]
        else:
            # Get full paths of specific files to disassemble
            files_to_disassemble = []
            for relative_file_path in self._files_to_disassemble:
                # Convert relative path to absolute path within the output directory
                # Normalize path separators for the current OS
                normalized_path = relative_file_path.replace("/", os.sep)
                full_path = os.path.join(self._output_path, normalized_path)

                if os.path.exists(full_path):
                    files_to_disassemble.append(full_path)
                    verbose(f"Found file: {relative_file_path}")
                else:
                    warning(
                        f"File not found: {relative_file_path} (looked for: {full_path})"
                    )

        if not files_to_disassemble:
            warning("No files found to disassemble.")
            return

        # Display files that will be disassembled
        files_to_process = []
        files_already_processed = []

        info("Checking for existing disassembly files...")
        for file_path in files_to_disassemble:
            # Determine the appropriate IDA database extension based on the file type
            if file_path.lower().endswith((".dll", ".exe")):
                # Windows binaries use .i64 extension
                ida_ext = ".i64"
            else:
                # Linux binaries (.so or executables) also use .i64 for 64-bit
                ida_ext = ".i64"

            ida_path = file_path + ida_ext
            if os.path.exists(ida_path):
                files_already_processed.append(file_path)
                verbose(
                    f"Skipping {os.path.basename(file_path)} - {ida_ext} file already exists"
                )
            else:
                files_to_process.append(file_path)

        if files_already_processed:
            info(
                f"Found {len(files_already_processed)} files already disassembled (skipping)"
            )
            for file_path in files_already_processed[:3]:  # Show first 3
                relative_path = os.path.relpath(file_path, self._output_path)
                info(f"  ✓ {relative_path}")
            if len(files_already_processed) > 3:
                info(f"  ... and {len(files_already_processed) - 3} more files")

        if not files_to_process:
            info("All files have already been disassembled!")
            return

        info(f"The following {len(files_to_process)} files will be disassembled:")
        for file_path in files_to_process:
            relative_path = os.path.relpath(file_path, self._output_path)
            file_size = os.path.getsize(file_path)
            size_mb = file_size / (1024 * 1024)

            # Determine platform based on file extension and path
            if file_path.lower().endswith((".dll", ".exe")):
                platform_tag = "[PE]"
            elif file_path.lower().endswith(".so"):
                platform_tag = "[ELF]"
            elif "linux" in file_path.lower():
                platform_tag = "[ELF]"
            else:
                platform_tag = "[?]"

            info(f"  • {platform_tag} {relative_path} ({size_mb:.1f} MB)")

        # Ask for confirmation unless auto-confirm is enabled
        if not self._auto_confirm:
            try:
                confirmation = (
                    input(
                        f"\nProceed with disassembling {len(files_to_process)} files? [y/N]: "
                    )
                    .strip()
                    .lower()
                )
                if confirmation not in ["y", "yes"]:
                    info("Disassembly cancelled by user.")
                    return
            except KeyboardInterrupt:
                info("\nDisassembly cancelled by user.")
                return
        else:
            info(
                f"Auto-confirm enabled, proceeding with {len(files_to_process)} files..."
            )

        info("Starting disassembly... This is going to be hot!")

        # Create progress bar
        with tqdm(
            total=len(files_to_process),
            desc="Disassembly Progress",
            unit="file",
            colour="green",
        ) as pbar:

            # disassemble files in parallel
            max_workers = os.cpu_count() if self._jobs == -1 else self._jobs
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                # Submit all jobs
                future_to_file = {
                    executor.submit(
                        self._disassemble_file_with_monitoring,
                        file_path,
                        self._ida_path,
                    ): file_path
                    for file_path in files_to_process
                }

                # Process completed jobs
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        if result:
                            pbar.set_postfix_str(f"✓ {os.path.basename(file_path)}")
                        else:
                            pbar.set_postfix_str(f"✗ {os.path.basename(file_path)}")
                    except Exception as e:
                        error(
                            f"Failed to disassemble {os.path.basename(file_path)}: {e}"
                        )
                        pbar.set_postfix_str(f"✗ {os.path.basename(file_path)}")
                    finally:
                        pbar.update(1)

        info("Disassembly complete!")

    def _disassemble_file_with_monitoring(self, file_path, ida_path):
        """
        Disassemble a file with process monitoring.
        Returns True if successful, False otherwise.
        """
        try:
            verbose(f"Starting disassembly: {os.path.basename(file_path)}")

            # Start IDA process
            process = subprocess.Popen(
                [ida_path, "-B", "-c", file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Monitor the process
            psutil_process = psutil.Process(process.pid)

            # Wait for process to complete
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                verbose(f"Successfully disassembled: {os.path.basename(file_path)}")
                return True
            else:
                error(
                    f"IDA failed for {os.path.basename(file_path)}: {stderr.decode()}"
                )
                return False

        except Exception as e:
            error(f"Failed to disassemble {os.path.basename(file_path)}: {e}")
            return False

    @staticmethod
    def _disassemble_file(file_path, ida_path):
        try:
            info(f"Disassembling: {file_path}")
            subprocess.run([ida_path, "-B", "-c", file_path], check=True)
        except Exception as e:
            error(f"Failed to disassemble {file_path}: {e}")


def main() -> None:
    print_banner()

    parser = argparse.ArgumentParser(
        description="Download a Steam depot using steamctl and disassemble executables with IDA Pro"
    )
    parser.add_argument(
        "--app",
        "-a",
        type=int,
        required=True,
        help="The ID of the app",
    )
    parser.add_argument(
        "--depot",
        "-d",
        type=int,
        required=True,
        help="The ID of the depot",
    )
    parser.add_argument(
        "--manifest-id",
        "-m",
        type=int,
        required=True,
        help="The ID of the manifest.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="The path where the depot should be saved. If not provided, will generate ./output/output_YYYY-MM-DD automatically.",
    )
    parser.add_argument(
        "--ida-path",
        "-i",
        type=str,
        help="The path where the ida executable is stored. If not provided, will use saved path or prompt.",
    )
    parser.add_argument(
        "--depotdownloader-path",
        type=str,
        help="The path to DepotDownloader executable. If not provided, will check local directory or prompt to download.",
    )
    parser.add_argument(
        "--files-to-disassemble",
        "-f",
        type=str,
        nargs="*",
        help="The list of files to disassemble using relative paths from depot base (e.g., 'game/bin/win64/client.dll'). If not specified, uses files from .files_config.json.",
    )
    parser.add_argument(
        "--platform",
        "-p",
        type=str,
        choices=["windows", "linux", "both"],
        default="windows",
        help="Target binary format for disassembly (windows=PE, linux=ELF, both=mixed). Refers to the depot content, not the host system.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=-1,
        help="The number of jobs to run in parallel. "
        "Default is the number of cores.",
    )
    parser.add_argument(
        "--auto-confirm",
        "-y",
        action="store_true",
        help="Skip confirmation prompt and proceed with disassembly automatically.",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show the saved configuration and last run parameters.",
    )
    parser.add_argument(
        "--create-files-config",
        action="store_true",
        help="Create or recreate the files configuration file with defaults.",
    )

    args = parser.parse_args()

    # Use the colored logging system for info messages
    info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    info(
        f"System: {os.name.upper()} | Python {'.'.join(map(str, sys.version_info[:3]))}"
    )
    info(f"Available CPU Cores: {os.cpu_count()}")
    info("Initializing depot download and disassembly pipeline...")

    global verbose_log
    verbose_log = args.verbose

    # Set logging level based on verbose flag
    if verbose_log:
        coloredlogs.set_level(logging.DEBUG)

    # Generate output directory if not provided
    output_path = args.output
    if not output_path:
        # Generate automatic output directory with timestamp and IDs
        timestamp = datetime.now().strftime("%Y-%m-%d")
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Determine platform prefix for directory name
        platform = args.platform or "windows"  # Default to windows if not specified
        platform_prefix = f"{platform}_" if platform != "both" else "mixed_"

        output_path = os.path.join(
            script_dir,
            "output",
            f"{platform_prefix}output_{timestamp}_{args.app}_{args.depot}_{args.manifest_id}",
        )
        info(f"Auto-generated output directory: {output_path}")

    # Ensure output directory exists
    os.makedirs(output_path, exist_ok=True)

    # Load configuration
    config = load_config()

    # Handle --create-files-config option
    if args.create_files_config:
        info("Creating/recreating files configuration...")
        files_config = create_default_files_config()
        info("Files configuration created successfully!")
        info(f"Edit {FILES_CONFIG_FILE} to customize file groups and selections.")
        return

    # Load files configuration (create default if it doesn't exist)
    files_config = load_files_config()
    if not files_config:
        files_config = create_default_files_config()

    # Handle --show-config option
    if args.show_config:
        info("=== Saved Configuration ===")
        if "ida_path" in config:
            info(f"IDA Path: {config['ida_path']}")
        else:
            info("IDA Path: Not set")

        if "depotdownloader_path" in config:
            info(f"DepotDownloader Path: {config['depotdownloader_path']}")
        else:
            info("DepotDownloader Path: Not set")

        info("=== Files Configuration ===")
        files_to_disassemble = files_config.get("files_to_disassemble", {})

        if isinstance(files_to_disassemble, list):
            # Old format
            info(f"Configured files (legacy format): {len(files_to_disassemble)}")
            for file_path in files_to_disassemble[:3]:
                info(f"  • {file_path}")
            if len(files_to_disassemble) > 3:
                info(f"  ... and {len(files_to_disassemble) - 3} more files")
        elif isinstance(files_to_disassemble, dict):
            # New format with platforms
            default_platform = files_config.get("default_platform", "windows")
            info(f"Default binary format: {default_platform}")

            for platform in ["windows", "linux"]:
                platform_files = files_to_disassemble.get(platform, [])
                if platform_files:
                    binary_type = "PE" if platform == "windows" else "ELF"
                    info(
                        f"{platform.capitalize()} binaries ({binary_type}) - {len(platform_files)} files:"
                    )
                    for file_path in platform_files[:3]:
                        info(f"  • {file_path}")
                    if len(platform_files) > 3:
                        info(f"  ... and {len(platform_files) - 3} more files")
        else:
            info("No files configured")

        if "last_run" in config:
            last_run = config["last_run"]
            info("=== Last Run Parameters ===")
            info(f"App ID: {last_run.get('app_id', 'N/A')}")
            info(f"Depot ID: {last_run.get('depot_id', 'N/A')}")
            info(f"Manifest ID: {last_run.get('manifest_id', 'N/A')}")
            info(f"Output Path: {last_run.get('output_path', 'N/A')}")
            info(f"Files to Disassemble: {last_run.get('files_to_disassemble', 'N/A')}")
            info(f"Jobs: {last_run.get('jobs', 'N/A')}")
            info(f"Verbose: {last_run.get('verbose', 'N/A')}")
            info(f"Auto Confirm: {last_run.get('auto_confirm', 'N/A')}")
            info(f"Timestamp: {last_run.get('timestamp', 'N/A')}")
        else:
            info("No previous run data found")
        return

    # Handle IDA path
    ida_path = args.ida_path
    if not ida_path:
        # Try to get from config
        ida_path = config.get("ida_path")
        if not ida_path:
            # Prompt user for IDA path
            info("IDA Pro executable path not found in configuration.")
            ida_path = input("Please enter the path to IDA Pro executable: ").strip()
            if not ida_path:
                error("IDA path is required")
                return
            else:
                if not os.path.exists(ida_path):
                    error(f"IDA path does not exist: {ida_path}")
                    return
        else:
            info(f"Using saved IDA path: {ida_path}")
            # Verify the saved path still exists
            if not os.path.exists(ida_path):
                warning(f"Saved IDA path no longer exists: {ida_path}")
                ida_path = input(
                    "Please enter a new path to IDA Pro executable: "
                ).strip()
                if not ida_path or not os.path.exists(ida_path):
                    error("Valid IDA path is required")
                    return

    # Save IDA path to config
    config["ida_path"] = ida_path

    # Ensure DepotDownloader is available
    info("Checking for DepotDownloader...")

    # Handle command-line argument for DepotDownloader path
    if args.depotdownloader_path:
        if os.path.exists(args.depotdownloader_path):
            depotdownloader_path = args.depotdownloader_path
            info(f"Using DepotDownloader from command line: {depotdownloader_path}")
            config["depotdownloader_path"] = depotdownloader_path
            save_config(config)
        else:
            error(f"DepotDownloader path does not exist: {args.depotdownloader_path}")
            return
    else:
        depotdownloader_path = ensure_depotdownloader(config)
        if not depotdownloader_path:
            error("DepotDownloader is required but not available")
            return

    # Determine if we should disassemble all files (need to do this before saving config)
    files_to_disassemble_arg = args.files_to_disassemble
    platform = args.platform
    disassemble_all = False

    if files_to_disassemble_arg is None:
        # No --files-to-disassemble specified, use files from config
        files_to_disassemble = resolve_files_to_disassemble(
            None, files_config, platform
        )
        if not files_to_disassemble:
            # If no files configured, disassemble all
            disassemble_all = True
            files_to_disassemble = []
            info("No specific files configured - will disassemble all PE/ELF binaries")
        else:
            platform_info = f" ({platform})" if platform else ""
            info(
                f"Using configured files{platform_info}: {len(files_to_disassemble)} files"
            )
    elif "all" in files_to_disassemble_arg:
        # 'all' specified explicitly
        disassemble_all = True
        files_to_disassemble = []
        info("'all' specified - will disassemble all PE/ELF binaries")
    else:
        # Specific files provided via command line
        files_to_disassemble = resolve_files_to_disassemble(
            files_to_disassemble_arg, files_config, platform
        )
        info(f"Will disassemble specified files: {files_to_disassemble}")

    # Save current command-line options to config for future use
    config["last_run"] = {
        "app_id": args.app,
        "depot_id": args.depot,
        "manifest_id": args.manifest_id,
        "output_path": output_path,
        "files_to_disassemble": files_to_disassemble,
        "jobs": args.jobs,
        "verbose": args.verbose,
        "auto_confirm": args.auto_confirm,
        "timestamp": datetime.now().isoformat(),
    }

    save_config(config)
    info(f"IDA path saved: {ida_path}")
    info(f"DepotDownloader path saved: {depotdownloader_path}")
    verbose(f"Configuration saved with current run parameters")

    depot_downloader = DepotDownloader(
        app_id=args.app,
        depot_id=args.depot,
        manifest_id=args.manifest_id,
        output_path=output_path,
        ida_path=ida_path,
        depotdownloader_path=depotdownloader_path,
        files_to_disassemble=files_to_disassemble,
        jobs=args.jobs,
        disassemble_all=disassemble_all,
        auto_confirm=args.auto_confirm,
        platform=platform,
    )
    depot_downloader.download()


if __name__ == "__main__":
    main()
