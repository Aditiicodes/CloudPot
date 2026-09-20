-- ===========================================================================
-- CloudPot - Athena schema over the Cowrie JSON in S3
--
-- Before running: replace <TELEMETRY_BUCKET> with the bucket name from
-- `terraform output telemetry_bucket`, and set projection.dt.range to your
-- own deployment window. `make athena-ddl` renders both for you.
--
-- Two decisions in here are worth understanding.
--
-- 1. PARTITION PROJECTION, not a partition catalogue.
--
--    The conventional pattern is ALTER TABLE ADD PARTITION per day, or a
--    periodic MSCK REPAIR TABLE that lists the whole prefix to discover new
--    ones. Projection replaces both: the TBLPROPERTIES below describe the
--    partition key as a rule (a date, one per day, laid out at this path
--    template), so Athena computes the partition locations it needs from the
--    query's WHERE clause instead of looking them up.
--
--    That matters here for a specific reason. MSCK REPAIR issues S3 LIST
--    calls across every prefix in the table, and its cost and latency grow
--    with the number of partitions, not with the size of the query. It is
--    also a stateful step someone has to remember to run - and the failure
--    mode when they forget is not an error, it is a query that silently
--    returns fewer rows than it should. In a security analysis, quietly
--    missing a day of data is far worse than a query that errors out.
--    Projection has no such step and no such failure mode.
--
-- 2. The `timestamp` column is renamed.
--
--    Cowrie emits a JSON key called "timestamp", which is a reserved word in
--    Athena's SQL dialect - every query would need it quoted, and anyone who
--    forgets gets a parse error. The SerDe mapping below binds the Hive
--    column `ts` to the JSON key `timestamp`, so queries just use `ts`.
--
-- The SerDe is the OpenX one because it can be told to skip malformed
-- records. Cowrie output is well-formed, but the stream can be truncated
-- mid-line if an instance is terminated while a write is in flight, and one
-- torn line at the end of a file should not fail a whole query.
-- ===========================================================================

CREATE DATABASE IF NOT EXISTS cloudpot;

CREATE EXTERNAL TABLE IF NOT EXISTS cloudpot.cowrie (
  -- Core event identity ----------------------------------------------------
  eventid   string,   -- e.g. cowrie.login.failed, cowrie.command.input
  ts        string,   -- mapped from the JSON key "timestamp" (ISO-8601, UTC)
  session   string,   -- joins every event belonging to one connection
  sensor    string,
  message   string,   -- Cowrie's human-readable rendering of the event

  -- Network ----------------------------------------------------------------
  src_ip    string,
  src_port  int,
  dst_ip    string,
  dst_port  int,
  protocol  string,

  -- Authentication ---------------------------------------------------------
  username  string,
  password  string,

  -- Post-authentication behaviour -------------------------------------------
  input     string,   -- the command line the attacker typed
  duration  double,   -- seconds, present on cowrie.session.closed

  -- Attempted payload retrieval ---------------------------------------------
  -- Downloads are blocked by design, so these carry the attempt, not a file.
  -- `url` is the indicator of value. `shasum` is declared because Cowrie's
  -- schema includes it, but it is populated only when Cowrie actually stored
  -- something - which, with the download limit and the egress restrictions in
  -- place, it does not. Expect it to be null.
  url       string,
  outfile   string,
  shasum    string,

  -- Client fingerprinting ----------------------------------------------------
  -- `version` is the client's self-declared SSH banner and is trivially
  -- spoofed. `hassh` is a hash of the client's key exchange, cipher, MAC and
  -- compression lists, which reflects the actual TLS-like handshake the
  -- library performs - far harder to fake casually, and it stays constant
  -- across a rotating source-IP pool. Clustering on hassh is what separates
  -- "one toolkit behind many IPs" from "many independent actors".
  version      string,
  hassh        string,
  kexalgs      array<string>,
  encecs       array<string>,
  fingerprint  string
)
PARTITIONED BY (dt string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
WITH SERDEPROPERTIES (
  'mapping.ts'          = 'timestamp',
  'mapping.kexalgs'     = 'kexAlgs',
  'mapping.encecs'      = 'encCS',
  'ignore.malformed.json' = 'true',
  'dots.in.keys'        = 'true'
)
STORED AS TEXTFILE
LOCATION 's3://<TELEMETRY_BUCKET>/cowrie/'
TBLPROPERTIES (
  'projection.enabled'             = 'true',
  'projection.dt.type'             = 'date',
  'projection.dt.format'           = 'yyyy-MM-dd',
  'projection.dt.interval'         = '1',
  'projection.dt.interval.unit'    = 'DAYS',
  -- Narrow this to your actual deployment window. A range that starts years
  -- before the first partition makes Athena compute and probe thousands of
  -- empty locations on every query.
  'projection.dt.range'            = '2026-03-01,NOW',
  'storage.location.template'      = 's3://<TELEMETRY_BUCKET>/cowrie/dt=${dt}/'
);

-- Sanity check after creating the table. If this returns zero rows, the data
-- is not where the LOCATION says it is, or the dt= prefixes are missing -
-- it does NOT mean nobody attacked the honeypot. Check S3 before drawing any
-- conclusion from an empty result.
--
--   SELECT dt, count(*) AS events
--   FROM cloudpot.cowrie
--   GROUP BY dt
--   ORDER BY dt;
