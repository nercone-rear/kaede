class Characters:
    DIGIT = frozenset("0123456789")
    LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
    UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    HEXDIG = frozenset(b"0123456789abcdefABCDEF")
    BASE64 = frozenset("+/=") | DIGIT | LOWER | UPPER
