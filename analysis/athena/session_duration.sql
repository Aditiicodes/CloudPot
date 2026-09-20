-- ===========================================================================
-- Session duration
--
-- Answers: how long did they stay, and is this a script or a person?
--
-- Duration is the cheapest human-versus-automation signal available. Scripted
-- sessions are short and tightly clustered - connect, authenticate, run a
-- fixed command sequence, disconnect, often in under ten seconds and with
-- almost no variance. A session that runs for minutes, especially one with
-- gaps between commands, suggests someone typing.
--
-- Two caveats worth writing into the report. First, Cowrie's
-- interactive_timeout is 300 seconds, so any session at or very near 300
-- was ended by us, not by the attacker, and its duration is censored - it is
-- a lower bound, not a measurement. Second, a long duration with zero
-- commands is usually a connection left open by a scanner, not engagement.
-- ===========================================================================

SELECT
  s.session,
  s.src_ip,
  s.duration                    AS duration_seconds,
  s.ts                          AS closed_at,
  c.commands,
  c.first_command,
  CASE
    WHEN s.duration >= 299         THEN 'censored - hit interactive_timeout'
    WHEN c.commands = 0            THEN 'no interaction'
    WHEN s.duration < 10           THEN 'likely scripted'
    WHEN s.duration < 60           THEN 'short'
    ELSE                                'extended - candidate for tty review'
  END                           AS interpretation
FROM (
  SELECT session, src_ip, duration, ts
  FROM cloudpot.cowrie
  WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
    AND eventid = 'cowrie.session.closed'
    AND duration IS NOT NULL
) s
LEFT JOIN (
  SELECT
    session,
    count(*)                            AS commands,
    min_by(input, ts)                   AS first_command
  FROM cloudpot.cowrie
  WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
    AND eventid = 'cowrie.command.input'
  GROUP BY session
) c ON c.session = s.session
ORDER BY s.duration DESC
LIMIT 100;


-- ---------------------------------------------------------------------------
-- Distribution rather than the top of the tail. Report the median and the
-- quartiles; a mean duration is dominated by a handful of parked connections
-- and is close to meaningless on this data.
-- ---------------------------------------------------------------------------

-- SELECT
--   count(*)                                       AS closed_sessions,
--   round(approx_percentile(duration, 0.50), 2)    AS p50_seconds,
--   round(approx_percentile(duration, 0.90), 2)    AS p90_seconds,
--   round(approx_percentile(duration, 0.99), 2)    AS p99_seconds,
--   round(max(duration), 2)                        AS max_seconds,
--   count_if(duration >= 299)                      AS censored_at_timeout
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND eventid = 'cowrie.session.closed'
--   AND duration IS NOT NULL;
