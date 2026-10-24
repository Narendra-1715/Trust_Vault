"""
TrustVault Restore & Disaster Recovery CLI Utility
Usage:
  python -m backend.scripts.restore verify <backup_file_or_id> [--key <passphrase>]
  python -m backend.scripts.restore execute <backup_file_or_id> --confirm-destructive-overwrite [--key <passphrase>]
"""

import sys
import os
import argparse
import json

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.services.restore import verify_backup_archive, execute_restore

def main():
    parser = argparse.ArgumentParser(description="TrustVault Disaster Recovery Verification & Restore Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="Run isolated dry-run disaster recovery verification test")
    verify_parser.add_argument("backup", help="Path to backup archive (.tar.gz.enc) or backup ID")
    verify_parser.add_argument("--key", dest="encryption_key", default=None, help="Decryption passphrase / key")
    verify_parser.add_argument("--dir", dest="backup_dir", default=None, help="Backup directory if ID provided")

    restore_parser = subparsers.add_parser("execute", help="Execute actual disaster recovery restoration (Destructive!)")
    restore_parser.add_argument("backup", help="Path to backup archive (.tar.gz.enc) or backup ID")
    restore_parser.add_argument("--confirm-destructive-overwrite", action="store_true", required=True,
                                help="Explicit safety barrier required to overwrite active environment")
    restore_parser.add_argument("--key", dest="encryption_key", default=None, help="Decryption passphrase / key")
    restore_parser.add_argument("--dir", dest="backup_dir", default=None, help="Backup directory if ID provided")

    args = parser.parse_args()

    if args.command == "verify":
        print(f"[TrustVault DR] Running isolated sandbox verification for '{args.backup}'...")
        report = verify_backup_archive(
            backup_path_or_id=args.backup,
            encryption_key=args.encryption_key,
            backup_dir=args.backup_dir
        )
        print(json.dumps(report, indent=2))
        if report["is_valid"]:
            print(f"[TrustVault DR] PASS: Backup is 100% valid and verified for disaster recovery (RTO: {report['rto_seconds']}s).")
            sys.exit(0)
        else:
            print(f"[TrustVault DR] FAIL: Integrity or compatibility errors found!", file=sys.stderr)
            sys.exit(1)

    elif args.command == "execute":
        db = SessionLocal()
        try:
            print(f"[TrustVault DR] Executing disaster recovery restoration from '{args.backup}'...")
            res = execute_restore(
                backup_path_or_id=args.backup,
                db=db,
                encryption_key=args.encryption_key,
                backup_dir=args.backup_dir,
                confirm_destructive_overwrite=args.confirm_destructive_overwrite,
                operator_id="cli_disaster_recovery"
            )
            print("[TrustVault DR] SUCCESS! Service restored:")
            print(json.dumps(res, indent=2))
        finally:
            db.close()

if __name__ == "__main__":
    main()
