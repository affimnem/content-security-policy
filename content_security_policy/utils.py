import string


def kebab_to_pascal(text: str) -> str:
    return string.capwords(text, "-").replace("-", "")


def kebab_to_snake(text: str) -> str:
    return "_".join(text.split("-"))
