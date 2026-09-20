# figures/

Generated, not committed. `make plot` writes four PNGs here:

| File | Produced from |
| --- | --- |
| `attempts_per_day.png` | login events grouped by UTC date |
| `top_credentials.png` | username/password pairs by attempt count |
| `hourly_distribution.png` | login events by UTC hour, all 24 bins |
| `source_country_bar.png` | **only when `--geo` is supplied** |

`*.png` is gitignored. The figures are derived data - regenerate them from
`findings/raw/` rather than committing them, so a figure can never drift from
the dataset it claims to describe.

`source_country_bar.png` is skipped unless you pass an `ip,country` CSV:

```bash
python3 analysis/plots.py --input findings/raw/ --geo findings/geo.csv
```

`plots.py` does no geolocation of its own. Resolving addresses would mean
either bundling a licensed database or sending every attacker IP to a third
party - a network dependency, a licence question, and a disclosure of the
sensor's observations to someone else. Building that mapping is the operator's
step, with a source they are entitled to use. The script will not guess.
