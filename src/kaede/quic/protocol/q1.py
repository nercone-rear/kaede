from .base import QUICConnection, QUICProtocol

class Q1Connection(QUICConnection):
    name = "QUICv1"
    wire = 0x00000001

class Q1Protocol(QUICProtocol):
    name = "QUICv1"
    wire = 0x00000001
