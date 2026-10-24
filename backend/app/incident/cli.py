import argparse
import sys
from app.db.session import SessionLocal
from app.services.incident import IncidentService

def main(args_list=None, db_session=None):
    parser = argparse.ArgumentParser(
        prog="python -m trustvault.incident",
        description="TrustVault Incident Response & Security Containment CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # isolate-user command
    isolate_parser = subparsers.add_parser("isolate-user", help="Isolate a compromised user account immediately")
    isolate_parser.add_argument("user_id", help="UUID of compromised user to isolate")
    isolate_parser.add_argument("--reason", default="Manual security containment via CLI", help="Containment reason")
    isolate_parser.add_argument("--actor", default="SYSTEM_CLI", help="Operator identifier")

    args = parser.parse_args(args_list)

    should_close = False
    if db_session is not None:
        db = db_session
    else:
        db = SessionLocal()
        should_close = True

    try:
        if args.command == "isolate-user":
            print(f"[*] Initiating immediate security isolation for user: {args.user_id}...")
            result = IncidentService.isolate_user(
                db=db,
                user_id=args.user_id,
                actor_id=args.actor,
                reason=args.reason
            )
            print("[SUCCESS] User account isolated successfully!")
            print(f"          Target Email: {result['user_email']}")
            print(f"          Sessions Terminated: {result['sessions_terminated']}")
            print(f"          Documents Frozen: {result['documents_frozen']}")
            print(f"          Outgoing Grants Revoked: {result['outgoing_grants_revoked']}")
            return 0
    except Exception as e:
        print(f"[FAIL] Incident containment failed: {e}", file=sys.stderr)
        return 1
    finally:
        if should_close:
            db.close()

if __name__ == "__main__":
    sys.exit(main())
