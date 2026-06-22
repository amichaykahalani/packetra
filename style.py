class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    MAGENTA = "\033[35m"
    RED = "\033[31m"

    @staticmethod
    def title(text: str) -> str:
        bar = "═" * (len(text) + 2)
        return f"\n{Style.CYAN}╔{bar}╗\n║ {Style.BOLD}{text}{Style.RESET}{Style.CYAN} ║\n╚{bar}╝{Style.RESET}"

    @staticmethod
    def section(text: str) -> str:
        return f"\n{Style.MAGENTA}── {text} {'─' * max(0, 40 - len(text))}{Style.RESET}"

    @staticmethod
    def prompt(text: str) -> str:
        return f"{Style.GREEN}›{Style.RESET} {text}"

    @staticmethod
    def option(key, label) -> str:
        return f"  {Style.DIM}{key}.{Style.RESET} {label}"

    @staticmethod
    def error(text: str) -> str:
        return f"{Style.RED}✗ {text}{Style.RESET}"

    @staticmethod
    def info(text: str) -> str:
        return f"{Style.YELLOW}{text}{Style.RESET}"

    @staticmethod
    def success(text: str) -> str:
        return f"{Style.GREEN}{text}{Style.RESET}"
