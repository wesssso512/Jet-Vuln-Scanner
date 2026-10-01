"""``python -m jetscanner`` — same as the ``jet`` command."""
import sys

from .cli import main

sys.exit(main())
