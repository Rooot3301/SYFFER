"""Point d'entree console de Syffer."""

from __future__ import annotations

import logging
import sys

from syffer.cli import menu
from syffer.cli.session import Session
from syffer.utils import logging_setup

logger = logging.getLogger(__name__)


def main() -> int:
    """Point d'entree principal : configure logging + lance le menu."""
    logging_setup.configure(verbose=False)
    session = Session()
    try:
        return menu.run(session)
    except KeyboardInterrupt:
        return 130
    except Exception:
        logger.exception("erreur non recuperable")
        sys.stderr.write("erreur interne, activez les logs verbeux pour plus de details\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
