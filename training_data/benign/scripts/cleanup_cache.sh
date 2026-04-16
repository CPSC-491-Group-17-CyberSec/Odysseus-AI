#!/bin/bash
# cleanup_cache.sh - Clean old scan cache entries
# Safe maintenance script for Odysseus-AI

DB_PATH="${ODYSSEUS_DB:-odysseus_scans.db}"
MAX_AGE_DAYS=30

echo "Odysseus-AI Cache Cleanup"
echo "========================="
echo "Database: $DB_PATH"
echo "Max age: $MAX_AGE_DAYS days"

if [ ! -f "$DB_PATH" ]; then
    echo "Database not found at $DB_PATH"
    exit 1
fi

# Count entries before cleanup
BEFORE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM scan_cache;")
echo "Entries before: $BEFORE"

# Remove old entries
sqlite3 "$DB_PATH" "DELETE FROM scan_cache WHERE last_modified < datetime('now', '-${MAX_AGE_DAYS} days');"

# Count entries after
AFTER=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM scan_cache;")
REMOVED=$((BEFORE - AFTER))

echo "Entries after:  $AFTER"
echo "Removed:        $REMOVED"

# Vacuum to reclaim space
sqlite3 "$DB_PATH" "VACUUM;"
echo "Database vacuumed."
echo "Done."
