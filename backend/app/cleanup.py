import asyncio
import logging
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .database import db_connection

logger = logging.getLogger("safegate.cleanup")

UPLOAD_ROOT = Path(tempfile.gettempdir()) / "safegate" / "uploads"
REMOTE_ROOT = Path(tempfile.gettempdir()) / "safegate" / "remote"

async def cleanup_loop(file_retention_minutes: int = 15, db_retention_hours: int = 720) -> None:
    """
    Background loop that runs indefinitely, cleaning up old files and database records.
    """
    logger.info("Background cleanup task started.")
    
    while True:
        try:
            logger.info("Starting automatic cleanup cycle...")
            now = datetime.now(timezone.utc)
            
            # 1. Cleanup local temporary files on disk
            file_cutoff = now - timedelta(minutes=file_retention_minutes)
            cleaned_files_count = 0
            
            for folder in (UPLOAD_ROOT, REMOTE_ROOT):
                if folder.exists():
                    for file_path in folder.iterdir():
                        if file_path.is_file():
                            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime, timezone.utc)
                            if file_mtime < file_cutoff:
                                try:
                                    file_path.unlink()
                                    cleaned_files_count += 1
                                    logger.debug(f"Deleted temp file: {file_path}")
                                except Exception as e:
                                    logger.error(f"Failed to delete temp file {file_path}: {e}")
            
            if cleaned_files_count > 0:
                logger.info(f"Cleaned up {cleaned_files_count} expired temporary files from disk.")
                
            # 2. Cleanup old database records from Supabase
            db_cutoff = now - timedelta(hours=db_retention_hours)
            deleted_rows = 0
            with db_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM uploads WHERE created_at < %s",
                        (db_cutoff,)
                    )
                    deleted_rows = cursor.rowcount
            
            if deleted_rows > 0:
                logger.info(f"Purged {deleted_rows} expired scan records from Supabase.")
                
        except Exception as exc:
            logger.error(f"Error during cleanup cycle: {exc}")
            
        # Run the cleanup check every 5 minutes (300 seconds)
        await asyncio.sleep(300)
