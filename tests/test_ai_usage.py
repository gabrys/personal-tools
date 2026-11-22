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
        self.assertAlmostEqual(scores['agy-gemini'], -100 * 0.75 / 8)
        self.assertAlmostEqual(scores['agy-argon'], -100 * 0.75 / 8)
        with patch.object(usage, 'now_local', return_value=now):
            data = usage.usage_data(results=results)
            raw_summary = usage.summary_line(data)
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
        self.assertAlmostEqual(
            usage.agent_scores({'codex': result}, now)['codex'],
            -100 * 4.25 / 8,
        )

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

        other = usage.UsageWindow(
            'Daily', 50, now + dt.timedelta(hours=12),
            duration=dt.timedelta(days=1),
        )
        self.assertAlmostEqual(other.expected(now), 50.0)

    def test_weekly_window_uses_eight_day_progress(self):
        now = dt.datetime(2026, 11, 15, 0, 0, tzinfo=dt.timezone.utc)
        w7_mid = usage.UsageWindow(
            'Weekly', 50, now + dt.timedelta(days=3, hours=18),
            duration=usage.ONE_WEEK,
        )
        self.assertAlmostEqual(w7_mid.expected(now), 50.0)

        w7_start = usage.UsageWindow(
            'Weekly', 10, now + usage.ONE_WEEK, duration=usage.ONE_WEEK
        )
        self.assertAlmostEqual(w7_start.expected(now), 100 * 0.75 / 8)

        w7_at_reset = usage.UsageWindow(
            'Weekly', 90, now, duration=usage.ONE_WEEK
        )
        self.assertAlmostEqual(w7_at_reset.expected(now), 100 * 7.75 / 8)

        w7_after_reset = usage.UsageWindow(
            'Weekly', 90, now - dt.timedelta(hours=6), duration=usage.ONE_WEEK
        )
        self.assertAlmostEqual(w7_after_reset.expected(now), 100.0)

    def test_session_pace_shortens_to_earlier_weekly_reset(self):
        now = dt.datetime(2026, 11, 18, 21, 17, tzinfo=dt.timezone.utc)
        session = usage.UsageWindow(
            '5h', 39, now + dt.timedelta(hours=4, minutes=23),
            duration=usage.FIVE_HOURS,
        )
        weekly = usage.UsageWindow(
            'Weekly', 81, now + dt.timedelta(hours=2, minutes=25),
            duration=usage.ONE_WEEK,
        )
        group = usage.UsageGroup('Codex', [session, weekly])
        results = {'codex': usage.ProviderResult('Codex', 'test', groups=[group])}
        # Preserve the virtual start (82 minutes ago), end at the weekly reset.
        expected = 100 * 82 / (82 + 145)
        self.assertAlmostEqual(group.expected(session, now), expected)
        data = usage.usage_data(results=results, now=now)
        window = data['providers']['codex']['groups'][0]['windows'][0]
        self.assertEqual(window['expected_percent'], 36)
        self.assertEqual(window['reset'], weekly.reset.isoformat())
        self.assertIsNone(window['reset_text'])
        self.assertAlmostEqual(data['agents']['codex'], 39 - expected)
        self.assertAlmostEqual(group.expected(weekly, now), weekly.expected(now))
        self.assertAlmostEqual(
            group.expected(session, weekly.reset - dt.timedelta(seconds=1)),
            100, delta=0.01,
        )

    def test_session_pace_ignores_later_unknown_or_expired_weekly_reset(self):
        now = dt.datetime(2026, 11, 18, 21, 17, tzinfo=dt.timezone.utc)
        session = usage.UsageWindow(
            '5h', 39, now + dt.timedelta(hours=4), duration=usage.FIVE_HOURS,
        )
        for reset in (None, now - dt.timedelta(seconds=1), now,
                      session.reset, now + usage.ONE_WEEK):
            with self.subTest(reset=reset):
                group = usage.UsageGroup('Codex', [session, usage.UsageWindow(
                    'Weekly', 81, reset, duration=usage.ONE_WEEK,
                )])
                self.assertEqual(group.expected(session, now), session.expected(now))

    def test_failed_fetch_falls_back_to_history_within_12_minutes(self):
        t0 = dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.timezone.utc)
        good = usage.ProviderResult('Codex', 'test', groups=[
            usage.UsageGroup('Codex', [
                usage.UsageWindow('5h', 25, t0 + usage.FIVE_HOURS,
                                  duration=usage.FIVE_HOURS),
            ]),
        ])
        failed = usage.ProviderResult('Codex', 'test', error='timeout')

        with patch.dict(usage._HISTORY, {}, clear=True):
            with patch.dict(usage.FETCHERS, {'codex': lambda: good}):
                data0 = usage.usage_data(only='codex', now=t0)
            self.assertIsNone(data0['providers']['codex']['error'])
            self.assertEqual(
                data0['providers']['codex']['groups'][0]['windows'][0]['used_percent'],
                25,
            )

            # 12 minutes later: failed fetch still returns the historical data.
            t1 = t0 + dt.timedelta(minutes=12)
            with patch.dict(usage.FETCHERS, {'codex': lambda: failed}):
                data1 = usage.usage_data(only='codex', now=t1)
            self.assertIsNone(data1['providers']['codex']['error'])
            self.assertEqual(
                data1['providers']['codex']['groups'][0]['windows'][0]['used_percent'],
                25,
            )

            # More than 12 minutes later: historical data is too old, error is shown.
            t2 = t0 + dt.timedelta(minutes=12, seconds=1)
            with patch.dict(usage.FETCHERS, {'codex': lambda: failed}):
                data2 = usage.usage_data(only='codex', now=t2)
            self.assertEqual(data2['providers']['codex']['error'], 'timeout')
            self.assertEqual(data2['providers']['codex']['groups'], [])
