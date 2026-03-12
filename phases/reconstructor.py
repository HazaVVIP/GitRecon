"""
phases/reconstructor.py
Opsional: rekonstruksi source code ke disk jika user pakai --save.
Hanya berjalan setelah streaming selesai.
"""

import os
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http_client import HttpClient
from core.git_parser   import ObjectParser, obj_path


class Reconstructor:
    """
    Download dan tulis blob ke disk.
    Dipakai hanya ketika --save flag aktif.
    """

    def __init__(self, client: HttpClient, workers: int = 10):
        self._client     = client
        self._workers    = workers
        self._obj_parser = ObjectParser()

    def run(self, git_url: str, sha1_to_file: dict,
            output_dir: str, progress_cb=None) -> dict:
        """
        Rekonstruksi working tree ke disk.

        sha1_to_file: {sha1: filename} — dari index entries
        Returns: {"saved": N, "failed": N}
        """
        git_url = git_url.rstrip("/")
        os.makedirs(output_dir, exist_ok=True)

        saved  = 0
        failed = 0
        total  = len(sha1_to_file)
        done   = 0

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = {
                pool.submit(self._save_blob, git_url, sha1, filename, output_dir): sha1
                for sha1, filename in sha1_to_file.items()
            }
            for future in as_completed(futures):
                done += 1
                try:
                    ok = future.result()
                    if ok:
                        saved += 1
                    else:
                        failed += 1
                except Exception:
                    failed += 1

                if progress_cb:
                    progress_cb(done, total)

        return {"saved": saved, "failed": failed}

    def _save_blob(self, git_url: str, sha1: str,
                   filename: str, output_dir: str) -> bool:
        url  = f"{git_url}/{obj_path(sha1)}"
        resp = self._client.get(url)
        if not resp.ok:
            return False

        obj = self._obj_parser.parse(resp.body, sha1)
        if not obj or obj.obj_type != "blob":
            return False

        # Sanitasi path
        parts = [p for p in filename.replace("\\", "/").split("/")
                 if p and p != ".." and p != "."]
        if not parts:
            return False

        local_path = os.path.join(output_dir, *parts)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        with open(local_path, "wb") as f:
            f.write(obj.data)
        return True
