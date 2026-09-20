-- ===========================================================================
-- Post-authentication commands
--
-- Answers: once they were in, what did they actually do?
--
-- This is the highest-value query in the set and the whole reason the
-- honeypot accepts weak credentials at all. Everything before authentication
-- tells you who is knocking; this tells you what they came for.
--
-- Read it in three passes:
--
--   1. The raw frequency table below - what gets typed most.
--   2. The first-command-per-session query - the opening move is the most
--      diagnostic single field in the dataset, because it is chosen before
--      the attacker has learned anything about the host.
--   3. The intent buckets at the bottom - a rough classification into
--      reconnaissance, persistence, defence evasion and payload staging.
--
-- Caveat: Cowrie emulates. A command appearing here means it was TYPED, not
-- that it succeeded or that it would have succeeded on a real host. Report
-- these as attempted behaviour. The tty recordings (var/lib/cowrie/tty) are
-- the ground truth for what the attacker saw in response.
-- ===========================================================================

SELECT
  input                   AS command,
  count(*)                AS times_run,
  count(DISTINCT session) AS sessions,
  count(DISTINCT src_ip)  AS distinct_source_ips,
  min(ts)                 AS first_seen,
  max(ts)                 AS last_seen
FROM cloudpot.cowrie
WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
  AND eventid IN ('cowrie.command.input', 'cowrie.command.failed')
  AND input IS NOT NULL
GROUP BY input
ORDER BY times_run DESC
LIMIT 200;


-- ---------------------------------------------------------------------------
-- The opening move. Group by this to find distinct playbooks: sessions that
-- start with `uname -a` are fingerprinting, sessions that start with `cd /tmp`
-- are staging, sessions that start with `cat /proc/cpuinfo` are almost always
-- cryptomining deployment checking what they have landed on.
-- ---------------------------------------------------------------------------

-- SELECT
--   first_command,
--   count(*)               AS sessions,
--   count(DISTINCT src_ip) AS distinct_source_ips
-- FROM (
--   SELECT session, min_by(input, ts) AS first_command
--   FROM cloudpot.cowrie
--   WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--     AND eventid = 'cowrie.command.input'
--   GROUP BY session
-- )
-- GROUP BY first_command
-- ORDER BY sessions DESC
-- LIMIT 50;


-- ---------------------------------------------------------------------------
-- Intent buckets.
--
-- This is a blunt keyword classifier and it should be labelled as such in the
-- report - it will miscount obfuscated and base64-wrapped commands, and a
-- single command line can belong to two buckets. It is a way to see the shape
-- of the data quickly, not a measurement. Anything you intend to state as a
-- finding should be confirmed by reading the sessions.
-- ---------------------------------------------------------------------------

-- SELECT
--   CASE
--     WHEN regexp_like(input, '(?i)(uname|/proc/cpuinfo|lscpu|whoami|^id$|free -|nproc|lsb_release)')      THEN 'discovery'
--     WHEN regexp_like(input, '(?i)(authorized_keys|\.ssh|crontab|systemctl enable|rc\.local|useradd|passwd)') THEN 'persistence'
--     WHEN regexp_like(input, '(?i)(history -c|unset HISTFILE|rm -rf /var/log|chattr|iptables -F)')        THEN 'defence evasion'
--     WHEN regexp_like(input, '(?i)(wget|curl|tftp|ftpget|scp )')                                          THEN 'payload staging (blocked)'
--     WHEN regexp_like(input, '(?i)(nmap|masscan|ssh |for i in|/dev/tcp/)')                                THEN 'lateral movement / scanning'
--     WHEN regexp_like(input, '(?i)(xmrig|minerd|stratum\+tcp|pool\.)')                                    THEN 'cryptomining'
--     ELSE 'unclassified'
--   END AS intent,
--   count(*)                AS commands,
--   count(DISTINCT session) AS sessions
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND eventid IN ('cowrie.command.input', 'cowrie.command.failed')
--   AND input IS NOT NULL
-- GROUP BY 1
-- ORDER BY commands DESC;
