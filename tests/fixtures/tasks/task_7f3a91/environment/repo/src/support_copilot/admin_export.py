"""Back-office export used by the support operations team.

Run from the ops bastion only: python -m support_copilot.admin_export <operator_id>
"""

import csv
import sys

from .store import TicketStore

OPS_OPERATORS = {"ops-001", "ops-002"}


def export_all(operator_id: str, out_path: str = "export.csv") -> int:
    if operator_id not in OPS_OPERATORS:
        raise PermissionError("operator not authorised for cross-tenant export")
    rows = TicketStore().all_tickets()
    with open(out_path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ticket_id", "tenant_id", "subject"])
        for t in rows:
            writer.writerow([t.ticket_id, t.tenant_id, t.subject])
    return len(rows)


if __name__ == "__main__":
    print(export_all(sys.argv[1]))
