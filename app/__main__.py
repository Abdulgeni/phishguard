"""`python -m app`: load settings, configure logging, print the startup line."""

from app.config import get_settings
from app.logging_setup import configure_logging, log_startup
from app.services.clock import SystemClock


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, SystemClock())
    log_startup(settings)


if __name__ == "__main__":
    main()
