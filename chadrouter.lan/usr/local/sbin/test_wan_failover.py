import argparse
import io
import unittest
from unittest.mock import Mock, patch

import wan_failover


class WanProbeTests(unittest.TestCase):
    apple_url = "https://www.apple.com/library/test/success.html"
    apple_body = (
        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
    )

    def check_response(self, status, url, body, expected_status=200,
                       expected_body=None):
        response = Mock(status=status, url=url)
        response.read.side_effect = io.BytesIO(body).read
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch.object(wan_failover.urllib.request, "build_opener",
                          return_value=opener):
            return wan_failover.can_wan_connect_to_url(
                wan_failover.WANS[0], self.apple_url,
                expected_status, expected_body)

    def test_accepts_apple_success(self):
        self.assertTrue(self.check_response(
            200, self.apple_url, self.apple_body + b"\n",
            expected_body=self.apple_body))

    def test_rejects_wrong_status_redirect_and_body(self):
        for status, url, body in (
            (204, self.apple_url, self.apple_body),
            (200, "https://portal.example/", self.apple_body),
            (200, self.apple_url, b"Login required"),
            (200, self.apple_url, self.apple_body + b" extra"),
        ):
            with self.subTest(status=status, url=url, body=body):
                self.assertFalse(self.check_response(
                    status, url, body, expected_body=self.apple_body))

    def test_preserves_204_probe_behavior(self):
        self.assertTrue(self.check_response(
            204, self.apple_url, b"", expected_status=204))
        self.assertFalse(self.check_response(
            200, self.apple_url, b"", expected_status=204))

    def test_apple_is_third_fallback(self):
        with patch.object(wan_failover, "can_wan_connect_to_url",
                          side_effect=[TimeoutError(), False, True]) as probe:
            with self.assertLogs(wan_failover.logger, level="WARNING"):
                self.assertTrue(wan_failover.is_wan_healthy(wan_failover.WANS[0]))
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(probe.call_args.args,
                         (wan_failover.WANS[0], self.apple_url,
                          200, self.apple_body))

    def test_stops_after_first_success(self):
        with patch.object(wan_failover, "can_wan_connect_to_url",
                          return_value=True) as probe:
            self.assertTrue(wan_failover.is_wan_healthy(wan_failover.WANS[0]))
        probe.assert_called_once()

    def test_marks_wan_unhealthy_when_all_probes_fail(self):
        with patch.object(wan_failover, "can_wan_connect_to_url",
                          return_value=False) as probe:
            with self.assertLogs(wan_failover.logger, level="WARNING"):
                self.assertFalse(wan_failover.is_wan_healthy(wan_failover.WANS[0]))
        self.assertEqual(probe.call_count, 3)

    def test_polling_default_and_override(self):
        for arguments, expected_interval in (([], 30), (["--interval", "10"], 10)):
            parser = argparse.ArgumentParser()
            with self.subTest(arguments=arguments):
                with patch.object(wan_failover.argparse, "ArgumentParser",
                                  return_value=parser):
                    with patch.object(parser, "parse_args", side_effect=RuntimeError):
                        with self.assertRaises(RuntimeError):
                            wan_failover.main()
                parsed = parser.parse_args(arguments)
                self.assertEqual(parsed.interval, expected_interval)
                self.assertEqual(parsed.samples, 5)


if __name__ == "__main__":
    unittest.main()
