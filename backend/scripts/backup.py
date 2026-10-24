"""
TrustVault Backup CLI Utility
Usage:
  python -m backend.scripts.backup create [--dir /path/to/backups] [--key <passphrase>]
  python -m backend.scripts.backup list [--dir /path/to/backups]
"""

import sys
import os
import argparse
import json

# Add backend directory to sys.path so app imports resolve cleanly
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.services.backup import create_backup, list_backups, BackupConcurrencyError, BackupIntegrityError

def main():
    parser = argparse.ArgumentParser(description="TrustVault Encrypted Disaster Recovery Backup Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="Generate a new encrypted backup archive")
    create_parser.add_argument("--dir", dest="backup_dir", default=None, help="Custom output directory for backups")
    create_parser.add_argument("--key", dest="encryption_key", default=None, help="Encryption passphrase / key")

    list_parser = subparsers.add_parser("list", help="List all available encrypted backups")
    list_parser.add_argument("--dir", dest="backup_dir", default=None, help="Directory to scan")

    args = parser.parse_args()

    if args.command == "create":
        db = SessionLocal()
        try:
            print("[TrustVault Backup] Initiating disaster recovery backup...")
            result = create_backup(
                db=db,
                backup_dir=args.backup_dir,
                encryption_key=args.encryption_key
            )
            print("[TrustVault Backup] SUCCESS! Verified backup generated:")
            print(json.dumps(result, indent=2))
        except BackupConcurrencyError as e:
            print(f"[TrustVault Backup] ERROR (Concurrency): {e}", file=sys.stderr)
            sys.exit(2)
        except BackupIntegrityError as e:
            print(f"[TrustVault Backup] ERROR (Integrity): {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[TrustVault Backup] FATAL: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            db.close()

    elif args.command == "list":
        items = list_backups(backup_dir=args.backup_dir)
        print(f"[TrustVault Backup] Found {len(items)} backup archive(s):")
        for item in items:
            print(f" - ID: {item['backup_id']} | Date: {item['created_at']} | Size: {item['size_bytes']:,} bytes | Docs: {item['total_documents']} | Verified: {item['verified']}")

if __name__ == "__main__":
    main()
