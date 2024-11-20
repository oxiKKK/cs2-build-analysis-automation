import subprocess
import argparse
import shutil
import os
import concurrent.futures


def info(*args) -> None:
    print(*args)


def warning(*args) -> None:
    print("⚠️ ", *args)


def error(*args) -> None:
    print("❌ ", *args)


verbose_log = False


def verbose(*args) -> None:
    global verbose_log
    if verbose_log:
        print(*args)


class DepotDownloader:
    def __init__(
        self,
        app_id: int,
        depot_id: int,
        manifest_id: int,
        output_path: str,
        ida_path: str,
        files_to_disassemble: list[str],
        jobs: int,
    ) -> None:
        self._app_id = app_id
        self._depot_id = depot_id
        self._manifest_id = manifest_id
        self._output_path = output_path
        self._ida_path = ida_path
        self._files_to_disassemble = files_to_disassemble
        self._jobs = jobs

    def is_steamctl_installed(self) -> bool:
        """Check if steamctl is installed."""
        return shutil.which("steamctl") is not None

    def is_ida_installed(self) -> bool:
        """Check if IDA is installed."""
        return shutil.which(self._ida_path) is not None

    def download(self) -> None:
        """
        Downloads a Steam depot using steamctl.

        Parameters:
        - app_id: The ID of the app.
        - depot_id: The ID of the depot.
        - manifest_id: The ID of the manifest.
        - output_path: The path where the depot should be saved.
        """
        if not self.is_steamctl_installed():
            error("steamctl is not installed.")
            return
        
        if not self.is_ida_installed():
            error(f"{self._ida_path} is not installed.")
            return

        try:
            command = [
                "steamctl",
                "--anonymous",
                "depot",
                "download",
                "--app",
                str(self._app_id),
                "--depot",
                str(self._depot_id),
                "--manifest",
                str(self._manifest_id),
                "-o",
                self._output_path,
            ]

            result = subprocess.run(command, check=True)

            if result.returncode != 0:
                error("stderr: %s", result.stderr)
                return

            if result.stdout:
                info("Command output:", result.stdout)
            if result.stderr:
                info("Command error (if any):", result.stderr)
        except subprocess.CalledProcessError as e:
            error("Exception:", e)
            info("Output:", e.output)
            info("Error output:", e.stderr)

        self._post_download()

    def _post_download(self) -> None:
        self._filter_downloaded_files()
        self._disassemble()

    def _filter_downloaded_files(self) -> None:
        """
        Filters the downloaded files to only include the ones that are needed.
        """
        info("Filtering downloaded files...")

        for root, dirs, files in os.walk(self._output_path):
            for file in files:
                if file.endswith(".vpk"):
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                        verbose(f"Deleted: {file_path}")
                    except Exception as e:
                        warning(f"Failed to delete {file_path}: {e}")

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
        info("Disassembling downloaded files...")

        # get full paths of files to disassemble
        files_to_disassemble = []
        for root, dirs, files in os.walk(self._output_path):
            for file in files:
                if file.endswith(".dll") and file in self._files_to_disassemble:
                    file_path = os.path.join(root, file)
                    files_to_disassemble.append(file_path)

        info(f"Files to disassemble: {files_to_disassemble}")

        # disassemble files in parallel
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=os.cpu_count() if self._jobs == -1 else self._jobs
        ) as executor:
            futures = [
                executor.submit(
                    DepotDownloader._disassemble_file,
                    file_path,
                    self._ida_path,
                )
                for file_path in files_to_disassemble
            ]
            for future in concurrent.futures.as_completed(futures):
                future.result()

        info("Disassembly complete!")

    @staticmethod
    def _disassemble_file(file_path, ida_path):
        try:
            info(f"Disassembling: {file_path}")
            subprocess.run([ida_path, "-B", "-c", file_path], check=True)
        except Exception as e:
            error(f"Failed to disassemble {file_path}: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download a Steam depot using steamctl"
    )
    parser.add_argument(
        "--app",
        type=int,
        required=True,
        help="The ID of the app",
    )
    parser.add_argument(
        "--depot",
        type=int,
        required=True,
        help="The ID of the depot",
    )
    parser.add_argument(
        "--manifest-id",
        type=int,
        required=True,
        help="The ID of the manifest.",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="The path where the depot should be saved.",
    )
    parser.add_argument(
        "--ida-path",
        type=str,
        required=True,
        help="The path where the ida executable is stored.",
    )
    parser.add_argument(
        "--files_to_disassemble",
        type=str,
        nargs="+",
        default=[
            "client.dll",
            "server.dll",
            "engine2.dll",
        ],
        help="The list of files to whitelist for disassembly.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=-1,
        help="The number of jobs to run in parallel. "
        "Default is the number of cores.",
    )

    args = parser.parse_args()

    global verbose_log
    verbose_log = args.verbose

    depot_downloader = DepotDownloader(
        app_id=args.app,
        depot_id=args.depot,
        manifest_id=args.manifest_id,
        output_path=args.output,
        ida_path=args.ida_path,
        files_to_disassemble=args.files_to_disassemble,
        jobs=args.jobs,
    )
    depot_downloader.download()


if __name__ == "__main__":
    main()
