import unittest
from uas.git_sources import AdvertisedRefs


def pkt(value): return f'{len(value) + 4:04x}'.encode() + value


class SourceTests(unittest.TestCase):
    def test_fragmented_actual_advertisement_and_unretained_pack(self):
        data = (pkt(b'a' * 40 + b' HEAD\0multi_ack thin-pack side-band side-band-64k\n')
                + pkt(b'b' * 40 + b' refs/heads/main\n') + b'0000' + b'PACK' * 30000)
        decoder = AdvertisedRefs()
        for offset in range(0, len(data), 7): decoder.feed(data[offset:offset + 7])
        self.assertEqual(decoder.result(transport_succeeded=True), ('a' * 40, 'b' * 40))
        self.assertEqual(decoder.buffer, b'')

    def test_no_completed_source_on_failed_or_partial_transport(self):
        for data in (pkt(b'a' * 40 + b' HEAD\n'), b'0008xxx', b'zzzz', b'0001', b'0004',
                     pkt(b'version 2\n') + b'0000', b'x' * 65537):
            decoder = AdvertisedRefs(); decoder.feed(data)
            self.assertEqual(decoder.result(transport_succeeded=True), ())
        decoder = AdvertisedRefs(); decoder.feed(pkt(b'a' * 40 + b' HEAD\n') + b'0000')
        self.assertEqual(decoder.result(transport_succeeded=False), ())

    def test_empty_repository_and_version_one(self):
        decoder = AdvertisedRefs(); decoder.feed(pkt(b'0' * 40 + b' capabilities^{}\0report-status\n') + b'0000')
        self.assertTrue(decoder.valid); self.assertTrue(decoder.complete)
        self.assertEqual(decoder.result(transport_succeeded=True), ())
        decoder = AdvertisedRefs(); decoder.feed(pkt(b'version 1\n') + pkt(b'a' * 40 + b' HEAD\n') + b'0000')
        self.assertEqual(decoder.result(transport_succeeded=True), ('a' * 40,))

    def test_duplicate_ref_invalid_names_capability_after_first_ref_and_budget(self):
        first = pkt(b'a' * 40 + b' HEAD\0side-band\n')
        for bad in (b'b' * 40 + b' HEAD\n', b'b' * 40 + b' refs/../heads/main\n',
                    b'b' * 40 + b' refs/heads/b\0late-capability\n', b'Z' * 40 + b' refs/heads/b\n',
                    b'b' * 40 + b' refs/heads/b\r\n'):
            decoder = AdvertisedRefs(); decoder.feed(first + pkt(bad) + b'0000')
            self.assertFalse(decoder.valid)
            self.assertEqual(decoder.result(transport_succeeded=True), ())


if __name__ == '__main__': unittest.main()
