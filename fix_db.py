"""
fix_db.py  --  one-shot database repair.

Run this ONCE from your project root (D:\\AICyber\\soc):

    python fix_db.py

It finds every SQLite database in the project, and for any that has an
`alerts` table, adds the enrichment columns (severity, MITRE, recommended
actions) that the new AlertDB model expects but the old on-disk table is
missing. Safe to run repeatedly -- it only adds columns that don't exist.

No imports from your app, so it works regardless of what main.py /
init_db.py currently contain.
"""
import glob
import os
import sqlite3

# column name -> SQLite storage type (JSON is stored as TEXT in SQLite)
NEEDED = {
    "severity": "TEXT",
    "severity_score": "REAL",
    "mitre_technique_id": "TEXT",
    "mitre_technique": "TEXT",
    "mitre_tactic": "TEXT",
    "recommended_actions": "TEXT",
}


def candidate_dbs():
    pats = ["*.db", "*.sqlite", "*.sqlite3",
            "**/*.db", "**/*.sqlite", "**/*.sqlite3"]
    found = []
    for p in pats:
        found += glob.glob(p, recursive=True)
    # de-dupe, skip anything inside the virtualenv
    return sorted({os.path.normpath(f) for f in found if "venv" not in f.split(os.sep)})


def fix_one(path: str) -> bool:
    con = sqlite3.connect(path)
    try:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        if not cur.fetchone():
            return False  # no alerts table here
        cur.execute("PRAGMA table_info(alerts)")
        existing = {row[1] for row in cur.fetchall()}
        added = []
        for col, col_type in NEEDED.items():
            if col not in existing:
                cur.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}")
                added.append(col)
        con.commit()
        print(f"[fixed] {path}: added {added if added else 'nothing (already up to date)'}")
        return True
    finally:
        con.close()


if __name__ == "__main__":
    dbs = candidate_dbs()
    if not dbs:
        print("No SQLite database found. Run this from your project root (D:\\AICyber\\soc).")
        raise SystemExit(1)

    touched = False
    for db in dbs:
        try:
            touched |= fix_one(db)
        except Exception as e:
            print(f"[skip]  {db}: {e}")

    if not touched:
        print("Found DB files but none had an 'alerts' table. "
              "Simplest alternative: delete the .db file named in api/db/init_db.py and restart.")
    else:
        print("\nDone. Restart the server:  python -m uvicorn api.main:app --reload")