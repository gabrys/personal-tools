import datetime as dt
import unittest
from unittest.mock import patch

import ai_usage as usage


class SummaryTests(unittest.TestCase):
    def test_zero_weekly_usage_counts_towards_four_extremes(self):
        now = dt.datetime(2026, 11, 14, 23, 57, tzinfo=dt.timezone.utc)

        def group(name, used, days_left):
            return usage.UsageGroup(name, [
                usage.UsageWindow('5h', 0, now + usage.FIVE_HOURS,
                                  duration=usage.FIVE_HOURS),
                usage.UsageWindow('Weekly', used,
                                  now + dt.timedelta(days=days_left),
                                  duration=usage.ONE_WEEK),
            ])

        results = {
            'agy': usage.ProviderResult('agy', 'test', groups=[
                group('Gemini models', 0, 7),
                group('Claude and GPT models', 80, 4),
                group('Gemini 4 Argon', 0, 7),
            ]),
            'claude': usage.ProviderResult('claude', 'test', groups=[
                group('All models', 0, 5.5),
            ]),
            'codex': usage.ProviderResult('codex', 'test', groups=[
                group('Codex', 11, 4),
            ]),
        }

        scores = usage.agent_scores(results, now)
        self.assertLess(scores['claude'], 0)
        self.assertEqual(scores['agy-gemini'], 0)
        self.assertEqual(scores['agy-argon'], 0)
        with patch.object(usage, 'now_local', return_value=now):
            raw_summary = usage.summary_line(results)
        self.assertEqual(len(raw_summary.split('    ')), 4)
        summary = raw_summary.split()
        self.assertEqual(summary[1::2], ['cdx', 'cld', 'agx', 'arg'])

    def test_unstarted_session_does_not_hide_weekly_headroom(self):
        now = dt.datetime.now(dt.timezone.utc)
        result = usage.ProviderResult('codex', 'test', groups=[
            usage.UsageGroup('Codex', [
                usage.UsageWindow('5h', 0, now + usage.FIVE_HOURS,
                                  duration=usage.FIVE_HOURS),
                usage.UsageWindow('Weekly', 0, now + dt.timedelta(days=3.5),
                                  duration=usage.ONE_WEEK),
            ]),
        ])
        self.assertEqual(usage.agent_scores({'codex': result}, now)['codex'], -50)

    def test_five_hour_window_uses_six_hour_progress(self):
        now = dt.datetime(2026, 11, 15, 0, 0, tzinfo=dt.timezone.utc)
        w5_mid = usage.UsageWindow(
            '5h', 50, now + dt.timedelta(hours=2, minutes=45),
            duration=usage.FIVE_HOURS,
        )
        self.assertAlmostEqual(w5_mid.expected(now), 50.0)

        w5_start = usage.UsageWindow(
            '5h', 10, now + usage.FIVE_HOURS, duration=usage.FIVE_HOURS
        )
        self.assertAlmostEqual(w5_start.expected(now), 100 * 0.75 / 6)

        w5_at_reset = usage.UsageWindow(
            '5h', 90, now, duration=usage.FIVE_HOURS
        )
        self.assertAlmostEqual(w5_at_reset.expected(now), 100 * 5.75 / 6)

        w5_after_reset = usage.UsageWindow(
            '5h', 90, now - dt.timedelta(minutes=15), duration=usage.FIVE_HOURS
        )
        self.assertAlmostEqual(w5_after_reset.expected(now), 100.0)

        w7 = usage.UsageWindow(
            'Weekly', 50, now + dt.timedelta(days=3.5), duration=usage.ONE_WEEK
        )
        self.assertAlmostEqual(w7.expected(now), 50.0)
