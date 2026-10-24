import argparse
import sys
import os

from app.db.session import SessionLocal
from app.audit.verifier import verify_audit_integrity
from app.audit.checkpoint import verify_checkpoint_files, create_signed_checkpoint

def main(args_list=None, db_session=None):
    parser = argparse.ArgumentParser(
        prog="python -m trustvault.audit",
        description="TrustVault Audit Ledger Verification & Checkpoint CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. verify command
    verify_parser = subparsers.add_parser("verify", help="Verify cryptographic chain integrity, HMACs, sequence numbers, and checkpoints")
    verify_parser.add_argument("--from", dest="from_date", default=None, help="Optional start date/timestamp (ISO-8601 UTC)")
    verify_parser.add_argument("--to", dest="to_date", default=None, help="Optional end date/timestamp (ISO-8601 UTC)")
    verify_parser.add_argument("--checkpoints-dir", default=None, help="Directory containing signed checkpoints")
    verify_parser.add_argument("--key", default=None, help="Audit HMAC key (defaults to settings.AUDIT_HMAC_KEY)")
    verify_parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed verification steps")

    # 2. checkpoint command
    checkpoint_parser = subparsers.add_parser("checkpoint", help="Generate an external signed checkpoint anchor")
    checkpoint_parser.add_argument("--output-dir", default=None, help="Destination directory for checkpoint file")
    checkpoint_parser.add_argument("--key", default=None, help="Audit HMAC key (defaults to settings.AUDIT_HMAC_KEY)")

    args = parser.parse_args(args_list)

    should_close = False
    if db_session is not None:
        db = db_session
    else:
        db = SessionLocal()
        should_close = True

    try:
        if args.command == "verify":
            print("[*] Starting TrustVault Audit Ledger Verification...")
            chain_res = verify_audit_integrity(
                db=db,
                from_date=args.from_date,
                to_date=args.to_date,
                audit_key=args.key
            )

            if not chain_res["is_valid"]:
                print(f"[FAIL] Cryptographic audit chain verification failed!", file=sys.stderr)
                print(f"       Reason: {chain_res['error_reason']}", file=sys.stderr)
                print(f"       Tampered Event ID: {chain_res.get('tampered_event_id')}", file=sys.stderr)
                return 1

            # Checkpoint verification
            cp_res = verify_checkpoint_files(db=db, checkpoint_dir=args.checkpoints_dir, audit_key=args.key)
            if not cp_res["is_valid"]:
                print(f"[FAIL] Checkpoint verification failed!", file=sys.stderr)
                print(f"       File: {cp_res.get('filename')}", file=sys.stderr)
                print(f"       Reason: {cp_res.get('error_reason')}", file=sys.stderr)
                return 2

            print(f"[SUCCESS] Audit ledger verified cleanly!")
            print(f"          Total records verified: {chain_res['total_events']}")
            print(f"          Signed checkpoints verified: {cp_res.get('checkpoints_verified', 0)}")
            print(f"          Integrity status: VALID (No modifications, deletions, re-orderings, or breaks detected).")
            return 0

        elif args.command == "checkpoint":
            print("[*] Generating signed audit checkpoint anchor...")
            cp = create_signed_checkpoint(db=db, output_dir=args.output_dir, audit_key=args.key)
            print(f"[SUCCESS] Checkpoint generated successfully!")
            print(f"          Checkpoint ID: {cp['checkpoint_id']}")
            print(f"          Anchored Sequence: {cp['sequence_number']}")
            print(f"          Latest Event ID: {cp['latest_event_id']}")
            print(f"          Latest Hash: {cp['latest_record_hash']}")
            print(f"          File: {cp.get('filepath')}")
            return 0

    except Exception as e:
        print(f"[ERROR] Verification failed with exception: {str(e)}", file=sys.stderr)
        return 3
    finally:
        if should_close:
            db.close()

if __name__ == "__main__":
    sys.exit(main())
