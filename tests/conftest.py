"""Run the suite without a bootstrapped stack.

server.config reads its environment at import time, and no test talks to
Keycloak or OpenFGA, so the suite gets a fixed stand-in rather than whatever the
last `make bootstrap` wrote. Set before any test module imports server.
"""

import os
from pathlib import Path

os.environ["WARRANT_ENV_FILE"] = str(Path(__file__).with_name("test.env"))
