import os

# Ensure QS_PEPPER is always defined for module imports
os.environ.setdefault("QS_PEPPER", "x" * 32)
