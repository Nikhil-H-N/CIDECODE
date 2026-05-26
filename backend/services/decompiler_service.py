import asyncio
import logging
import os
import tempfile
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)


class DecompilerService:
    @staticmethod
    async def decompile_with_jadx(apk_path: str, output_dir: Optional[str] = None) -> Optional[str]:
        if not os.path.isfile(apk_path):
            logger.error("APK not found: %s", apk_path)
            return None
        if output_dir is None:
            os.makedirs(settings.EXTRACT_DIR, exist_ok=True)
            output_dir = tempfile.mkdtemp(prefix="jadx_", dir=settings.EXTRACT_DIR)
        try:
            os.makedirs(output_dir, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                settings.JADX_PATH,
                "-d", output_dir,
                "--show-bad-code",
                apk_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if proc.returncode != 0:
                logger.error(
                    "JADX decompile failed (exit %d): %s",
                    proc.returncode,
                    stderr.decode(errors="replace").strip(),
                )
                return None
            logger.info(
                "JADX decompile succeeded for %s -> %s",
                os.path.basename(apk_path),
                output_dir,
            )
            return output_dir
        except asyncio.TimeoutError:
            logger.error("JADX decompile timed out for %s", apk_path)
            return None
        except FileNotFoundError:
            logger.error(
                "JADX executable '%s' not found on PATH. Install JADX or add it to PATH.",
                settings.JADX_PATH,
            )
            return None
        except Exception:
            logger.exception("Unexpected error during JADX decompile")
            return None

    @staticmethod
    async def decode_with_apktool(apk_path: str, output_dir: str) -> bool:
        if not os.path.isfile(apk_path):
            logger.error("APK not found: %s", apk_path)
            return False
        try:
            os.makedirs(output_dir, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                settings.APKTOOL_PATH,
                "d",
                apk_path,
                "-o", output_dir,
                "-f",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if proc.returncode != 0:
                logger.error(
                    "APKTool decode failed (exit %d): %s",
                    proc.returncode,
                    stderr.decode(errors="replace").strip(),
                )
                return False
            logger.info(
                "APKTool decode succeeded for %s -> %s",
                os.path.basename(apk_path),
                output_dir,
            )
            return True
        except asyncio.TimeoutError:
            logger.error("APKTool decode timed out for %s", apk_path)
            return False
        except FileNotFoundError:
            logger.error(
                "APKTool executable '%s' not found on PATH. Install APKTool or add it to PATH.",
                settings.APKTOOL_PATH,
            )
            return False
        except Exception:
            logger.exception("Unexpected error during APKTool decode")
            return False

    @staticmethod
    async def is_jadx_available() -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.JADX_PATH,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            return proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError):
            return False
        except Exception:
            logger.exception("Error checking JADX availability")
            return False

    @staticmethod
    async def is_apktool_available() -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.APKTOOL_PATH,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            return proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError):
            return False
        except Exception:
            logger.exception("Error checking APKTool availability")
            return False
