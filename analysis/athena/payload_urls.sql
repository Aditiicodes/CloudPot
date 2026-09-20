-- ===========================================================================
-- Attempted payload URLs
--
-- Answers: where were they going to fetch their second stage from?
--
-- -------------------------------------------------------------------------
-- NOTHING WAS DOWNLOADED. This query returns URLs and attempts only.
-- -------------------------------------------------------------------------
--
-- Payload retrieval is blocked twice over in this deployment. At the network
-- layer the security group permits outbound TCP only to 443 and to the VPC
-- resolver, so the emulated wget/curl cannot reach a staging server on port
-- 80 or an arbitrary high port - the connection fails before any bytes move.
-- At the application layer Cowrie's download size limit is set to 1 byte, so
-- even a reachable fetch is refused. No binary was ever written to disk, no
-- binary was ever uploaded to S3, and no binary is referenced anywhere in
-- this repository. The rationale is in docs/SAFETY.md.
--
-- What that means for the data: expect cowrie.session.file_download.failed
-- rather than cowrie.session.file_download, and expect `shasum` to be null.
-- A URL with no hash is still a perfectly good indicator - it is an
-- attacker-controlled host, it is actionable in a blocklist, and it is
-- pivotable against passive DNS and public sandbox reports without anyone
-- here having to touch a sample.
--
-- Note also that many staging URLs never reach this table at all: an attacker
-- who types `wget http://.../x.sh` produces a cowrie.command.input event, and
-- the URL has to be extracted from the command line. Run the second query
-- below as well, or you will undercount.
-- ===========================================================================

SELECT
  url,
  count(*)                AS attempts,
  count(DISTINCT session) AS sessions,
  count(DISTINCT src_ip)  AS distinct_source_ips,
  min(ts)                 AS first_seen,
  max(ts)                 AS last_seen,
  -- Present for schema completeness only. With downloads blocked this is
  -- expected to be null on every row; a non-null value here means something
  -- was stored and you should stop and read docs/SAFETY.md.
  count_if(shasum IS NOT NULL) AS rows_with_stored_artifact
FROM cloudpot.cowrie
WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
  AND eventid IN (
        'cowrie.session.file_download',
        'cowrie.session.file_download.failed',
        'cowrie.session.file_upload'
      )
  AND url IS NOT NULL
GROUP BY url
ORDER BY attempts DESC
LIMIT 200;


-- ---------------------------------------------------------------------------
-- URLs extracted from typed command lines. Catches the staging attempts that
-- never became a download event because the command was malformed, chained,
-- or piped straight to a shell.
-- ---------------------------------------------------------------------------

-- SELECT
--   regexp_extract(input, '(https?://[^\s;|''"`)]+)', 1) AS extracted_url,
--   count(*)                AS times_seen,
--   count(DISTINCT src_ip)  AS distinct_source_ips,
--   min(ts)                 AS first_seen,
--   max(ts)                 AS last_seen
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND eventid IN ('cowrie.command.input', 'cowrie.command.failed')
--   AND regexp_like(input, 'https?://')
-- GROUP BY 1
-- ORDER BY times_seen DESC
-- LIMIT 100;


-- ---------------------------------------------------------------------------
-- Staging infrastructure by host rather than by full URL. Useful because one
-- operator typically rotates the filename while keeping the host, so counting
-- distinct URLs overstates how much infrastructure is actually in play.
-- ---------------------------------------------------------------------------

-- SELECT
--   url_extract_host(url)   AS staging_host,
--   url_extract_port(url)   AS staging_port,
--   count(DISTINCT url)     AS distinct_urls,
--   count(*)                AS attempts,
--   count(DISTINCT src_ip)  AS distinct_source_ips
-- FROM cloudpot.cowrie
-- WHERE dt BETWEEN '2026-03-01' AND '2026-03-31'
--   AND eventid IN ('cowrie.session.file_download', 'cowrie.session.file_download.failed')
--   AND url IS NOT NULL
-- GROUP BY 1, 2
-- ORDER BY attempts DESC
-- LIMIT 100;
