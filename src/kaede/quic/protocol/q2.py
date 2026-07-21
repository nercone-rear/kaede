from .base import QUICConnection, QUICProtocol

class Q2Connection(QUICConnection):
    name = "QUICv2"
    wire = 0x6B3343CF

class Q2Protocol(QUICProtocol):
    name = "QUICv2"
    wire = 0x6B3343CF
