# aranya

Evidence layer over public internet-infrastructure data. See `../proj.txt` for
the full brief.

## Status

Phase 0, raw-minimal prototype: fetch a single source for a single IP, keep the
raw response in SQLite, show the normalized field.

## Usage

```sh
python3 aranya.py 8.8.8.8
python3 -m unittest discover -s tests
```
