from enum import Enum

class HTTPState(Enum):
    CONNECTION_STARTED = "Connection Started"
    CONNECTION_ENDED   = "Connection Ended"

    SENT           = "Sent"
    SENT_STARTLINE = "Sent Start line"
    SENT_HEADERS   = "Sent Headers"
    SENT_BODY      = "Sent Body"
    SENT_TRAILERS  = "Sent Trailers"

    RECEIVED           = "Received"
    RECEIVED_STARTLINE = "Received Start line"
    RECEIVED_HEADERS   = "Received Headers"
    RECEIVED_BODY      = "Received Body"
    RECEIVED_TRAILERS  = "Received Trailers"
