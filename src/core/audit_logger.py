import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, Optional


class AuditLogger:
    """Maintains a cryptographically tamper-evident, SHA-256 hash-chained JSONL log

    of all operational events, probe requests, and scanner telemetry.
    """

    def __init__(self, log_filename: str = "audit_log.jsonl"):
        self.log_filename = log_filename
        self.last_hash: str = "0" * 64
        self._recover_last_hash()

    def _recover_last_hash(self) -> None:
        """Reads the last line of an existing log file to recover the previous entry hash."""
        if not os.path.exists(self.log_filename):
            return

        try:
            with open(self.log_filename, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    last_entry = json.loads(lines[-1])
                    self.last_hash = last_entry.get("entry_hash", "0" * 64)
        except Exception:
            # Fallback to zero hash if file is unreadable or malformed
            self.last_hash = "0" * 64

    def log_action(self, action_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a timestamped entry, chains the SHA-256 hash of the previous entry,

        and appends the new record to the log.
        """
        timestamp = datetime.utcnow().isoformat() + "Z"

        record_to_hash = {
            "timestamp": timestamp,
            "action": action_type,
            "prev_hash": self.last_hash,
            "data": payload,
        }

        # Calculate cryptographic hash over serialized canonical JSON
        serialized = json.dumps(record_to_hash, sort_keys=True)
        entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        final_record = {
            **record_to_hash,
            "entry_hash": entry_hash,
        }

        with open(self.log_filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(final_record) + "\n")

        self.last_hash = entry_hash
        return final_record

    def verify_integrity(self) -> bool:
        """Verifies the unbroken cryptographic chain across the entire log file."""
        if not os.path.exists(self.log_filename):
            return True

        current_prev = "0" * 64
        with open(self.log_filename, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                recorded_hash = record.get("entry_hash")
                prev_hash = record.get("prev_hash")

                if prev_hash != current_prev:
                    return False

                # Recompute hash
                check_obj = {
                    "timestamp": record["timestamp"],
                    "action": record["action"],
                    "prev_hash": prev_hash,
                    "data": record["data"],
                }
                serialized = json.dumps(check_obj, sort_keys=True)
                calc_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

                if calc_hash != recorded_hash:
                    return False

                current_prev = recorded_hash

        return True
