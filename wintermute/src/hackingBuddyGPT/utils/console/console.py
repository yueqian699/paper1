from rich import console

from hackingBuddyGPT.utils.configurable import configurable


@configurable("console", "Console")
class Console(console.Console):
    """
    Simple wrapper around the rich Console class, to allow for dependency injection and configuration.
    """

    def __init__(self):
        # Batch runs redirect Rich to files opened as UTF-8, but keep console
        # output tolerant of redirected legacy Windows encodings as well.
        super().__init__(
            force_terminal=False,
            legacy_windows=False,
            soft_wrap=True,
            width=120,
        )
