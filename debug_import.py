import sys
import traceback

sys.path.insert(0, "src")
try:
    import cybermcp.server
    print("SERVER IMPORT OK")
except Exception:
    traceback.print_exc()
    sys.exit(1)
