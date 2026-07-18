import pickle

import pytest

from kaede.quic.models import QUICStreamID
from kaede.quic.errors import QUICError, QUICStreamError

# RFC 9000 section 2.1 fixes the shape of a stream identifier: a 62 bit varint
# whose two least significant bits name the type. Everything asserted here is
# read from that section and from section 16, never from what Kaede happens to
# produce, so an implementation that drifts from the specification fails.

# RFC 9000 section 2.1, table 1: (bits, client initiated, bidirectional)
TYPES = [
    (0x00, True,  True),
    (0x01, False, True),
    (0x02, True,  False),
    (0x03, False, False)
]

class TestType:
    @pytest.mark.parametrize("bits, client, bidirectional", TYPES)
    def test_the_low_bits_name_the_type(self, bits, client, bidirectional):
        identifier = QUICStreamID(bits)

        assert identifier.client is client
        assert identifier.server is not client
        assert identifier.bidirectional is bidirectional
        assert identifier.unidirectional is not bidirectional

    @pytest.mark.parametrize("bits, client, bidirectional", TYPES)
    def test_the_type_survives_a_higher_ordinal(self, bits, client, bidirectional):
        # Only the low two bits are the type, so the same four answers have to
        # come back for every stream of that type, not just the first one.
        identifier = QUICStreamID(bits + 4 * 1000)

        assert identifier.client is client
        assert identifier.bidirectional is bidirectional

    def test_the_four_types_are_exactly_the_first_four_identifiers(self):
        assert [bits for bits, _, _ in TYPES] == [0, 1, 2, 3]

class TestOrdinal:
    def test_the_ordinal_is_what_sits_above_the_type_bits(self):
        assert QUICStreamID(0).ordinal == 0
        assert QUICStreamID(4).ordinal == 1
        assert QUICStreamID(8).ordinal == 2

    @pytest.mark.parametrize("bits, _client, _bidirectional", TYPES)
    def test_each_type_counts_from_zero_independently(self, bits, _client, _bidirectional):
        # RFC 9000 section 2.1: the streams of each type are numbered separately,
        # so the first stream of every type has ordinal zero.
        assert QUICStreamID(bits).ordinal == 0
        assert QUICStreamID(bits + 4).ordinal == 1

    @pytest.mark.parametrize("value", [0, 1, 2, 3, 4, 17, 65535, 2 ** 61])
    def test_the_ordinal_agrees_with_the_shift(self, value):
        assert QUICStreamID(value).ordinal == value >> 2

class TestMake:
    @pytest.mark.parametrize("bits, client, bidirectional", TYPES)
    def test_builds_each_type_of_the_table(self, bits, client, bidirectional):
        assert QUICStreamID.make(0, server=not client, unidirectional=not bidirectional) == bits

    @pytest.mark.parametrize("bits, client, bidirectional", TYPES)
    @pytest.mark.parametrize("ordinal", [0, 1, 2, 9, 1000])
    def test_round_trips_through_the_properties(self, bits, client, bidirectional, ordinal):
        identifier = QUICStreamID.make(ordinal, server=not client, unidirectional=not bidirectional)

        assert identifier.ordinal == ordinal
        assert identifier.client is client
        assert identifier.bidirectional is bidirectional

    def test_consecutive_ordinals_are_four_apart(self):
        # The type occupies the low two bits, so successive streams of one type
        # cannot be adjacent integers.
        first = QUICStreamID.make(0)
        second = QUICStreamID.make(1)

        assert second - first == 4

    def test_rejects_a_negative_ordinal(self):
        with pytest.raises(ValueError):
            QUICStreamID.make(-1)

    def test_rejects_a_non_integer_ordinal(self):
        with pytest.raises(TypeError):
            QUICStreamID.make("0")

class TestRange:
    @pytest.mark.parametrize("value", [0, 1, 2, 3, 4, 1000, 2 ** 62 - 1])
    def test_accepts_the_whole_varint_space(self, value):
        # RFC 9000 section 16: the largest value a varint encodes is 2**62 - 1.
        assert QUICStreamID(value) == value

    @pytest.mark.parametrize("value", [2 ** 62, 2 ** 62 + 1, 2 ** 64])
    def test_rejects_beyond_the_varint_space(self, value):
        with pytest.raises(ValueError):
            QUICStreamID(value)

    @pytest.mark.parametrize("value", [-1, -4])
    def test_rejects_negative(self, value):
        with pytest.raises(ValueError):
            QUICStreamID(value)

    @pytest.mark.parametrize("value", ["0", 0.0, None, b"0", [0]])
    def test_rejects_non_integer(self, value):
        with pytest.raises(TypeError):
            QUICStreamID(value)

    def test_rejects_bool(self):
        # bool is a subclass of int, but True/False are not stream identifiers.
        with pytest.raises(TypeError):
            QUICStreamID(True)

    def test_defaults_to_zero(self):
        assert QUICStreamID() == 0

class TestBehaviour:
    def test_is_an_int(self):
        assert isinstance(QUICStreamID(4), int)

    def test_compares_and_hashes_as_int(self):
        assert QUICStreamID(4) == 4
        assert hash(QUICStreamID(4)) == hash(4)
        assert {QUICStreamID(4): "second"}[4] == "second"

    def test_survives_pickling(self):
        assert pickle.loads(pickle.dumps(QUICStreamID(8))) == QUICStreamID(8)

    def test_repr_names_the_type(self):
        assert repr(QUICStreamID(8)) == "QUICStreamID(8)"

class TestErrors:
    def test_a_stream_error_carries_the_application_code(self):
        # RFC 9000 section 19.4: a RESET_STREAM frame states an application error
        # code, which is the only account of why the stream was abandoned.
        error = QUICStreamError("the peer reset the stream", 0x10F)

        assert error.code == 0x10F
        assert isinstance(error, QUICError)

    def test_the_code_defaults_to_zero(self):
        assert QUICStreamError("the peer reset the stream").code == 0
