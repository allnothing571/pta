import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

loader = unittest.TestLoader()
suite = loader.discover(os.path.join(ROOT, "tests"), top_level_dir=os.path.join(ROOT, "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
