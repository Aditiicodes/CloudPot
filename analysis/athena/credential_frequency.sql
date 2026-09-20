-- ===========================================================================
-- Credential frequency
--
-- Answers: what are they actually guessing?
--
-- This query is only meaningful because the honeypot does NOT accept every
-- password. Cowrie is configured with an explicit allow-list (cowrie/
-- userdb.example), so failures stay failures and the distribution below
-- reflects what the attacking population is trying, not what we let through.
-- A honeypot configured with a wildcard accept produces a 100% success rate
-- and this analysis becomes impossible.
--
-- The interesting output is rarely the top of the list - root/123456 tops
-- every dataset ever published. The interesting output is the tail: vendor
-- default credentials for specific appliances, application service accounts,
-- and passwords that encode a campaign name or a year.
-- ===========================================================================

SELECT
  username,
  password,
  count(*)                                    AS attempts,
  count(DISTINCT src_ip)                      AS distinct_source_ips,
  count_if(eventid = 'cowrie.login.success')  AS accepted,
  min(ts)                                     AS first_seen,
  max(ts)                                     AS last_seen
FROM cloudpot.cowrie
WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
  AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
GROUP BY username, password
ORDER BY attempts DESC
LIMIT 100;


-- ---------------------------------------------------------------------------
-- Usernames alone. Username selection says more about targeting than password
-- selection does: `root` and `admin` are universal, but `oracle`, `jenkins`,
-- `postgres` or `deploy` mean the list was built for servers.
-- ---------------------------------------------------------------------------

-- SELECT
--   username,
--   count(*)               AS attempts,
--   count(DISTINCT src_ip) AS distinct_source_ips,
--   count(DISTINCT password) AS distinct_passwords_tried
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
-- GROUP BY username
-- ORDER BY attempts DESC
-- LIMIT 50;


-- ---------------------------------------------------------------------------
-- Password reuse across sources. A password tried by many unrelated addresses
-- is a shared dictionary; a password tried by exactly one address may be
-- targeted, or may be that operator's own typo.
-- ---------------------------------------------------------------------------

-- SELECT
--   password,
--   count(DISTINCT src_ip) AS distinct_source_ips,
--   count(*)               AS attempts
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
--   AND password IS NOT NULL
-- GROUP BY password
-- HAVING count(DISTINCT src_ip) > 1
-- ORDER BY distinct_source_ips DESC
-- LIMIT 50;
