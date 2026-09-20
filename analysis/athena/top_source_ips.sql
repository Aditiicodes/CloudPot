-- ===========================================================================
-- Top source IPs
--
-- Answers: who generated the most traffic, and did they get in?
--
-- Read the ratio columns, not just the totals. An address with thousands of
-- failures and zero successes is a dumb sprayer working a dictionary. An
-- address with a handful of attempts and one success is either lucky or
-- working from a list that already contains the credential - and the second
-- is far more interesting.
--
-- Caveat to carry into the report: a source IP is not an actor. Proxy and
-- VPN exit nodes, compromised hosts and cloud egress addresses are all shared,
-- and one operator rotating a pool of a hundred addresses looks exactly like
-- a hundred operators. Cross-reference with the `hassh` clustering query at
-- the bottom of this file before making any claim about actor counts.
-- ===========================================================================

SELECT
  src_ip,
  count(*)                                                      AS events,
  count(DISTINCT session)                                       AS sessions,
  count_if(eventid = 'cowrie.login.failed')                     AS failed_logins,
  count_if(eventid = 'cowrie.login.success')                    AS successful_logins,
  count_if(eventid = 'cowrie.command.input')                    AS commands_run,
  count(DISTINCT username)                                      AS distinct_usernames,
  min(ts)                                                       AS first_seen,
  max(ts)                                                       AS last_seen,
  count(DISTINCT dt)                                            AS days_active
FROM cloudpot.cowrie
WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
  AND src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY events DESC
LIMIT 50;


-- ---------------------------------------------------------------------------
-- Same population, clustered by client fingerprint instead of address.
--
-- This is the query that tells you whether "N unique source IPs" means N
-- actors. A single hassh spread across dozens of addresses is one toolkit
-- behind a proxy pool; many hassh values on one address is a host running
-- several different tools, or a NAT gateway.
-- ---------------------------------------------------------------------------

-- SELECT
--   hassh,
--   count(DISTINCT src_ip)  AS distinct_source_ips,
--   count(DISTINCT session) AS sessions,
--   arbitrary(version)      AS example_client_banner,
--   min(ts)                 AS first_seen,
--   max(ts)                 AS last_seen
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND hassh IS NOT NULL
-- GROUP BY hassh
-- ORDER BY distinct_source_ips DESC
-- LIMIT 25;
