#!/usr/bin/env python3
"""Build the city list Kutup searches on the device (docs/plans/maps.md).

Source: GeoNames `cities15000` (every place with more than 15,000 people),
CC BY 4.0 (https://www.geonames.org/). Output: one compact JSON array of
[name, asciiName or "", countryCode, lat, lon] (about 100 m), most
populous first, written to frontend/packages/map/assets/cities.json.

    python3 scripts/build-cities.py [path/to/cities15000.zip]

Without an argument the zip is downloaded.
"""
import io
import json
import pathlib
import sys
import urllib.request
import zipfile

URL = "https://download.geonames.org/export/dump/cities15000.zip"
OUT = pathlib.Path(__file__).resolve().parent.parent / "frontend/packages/map/assets/cities.json"


def main() -> None:
    data = pathlib.Path(sys.argv[1]).read_bytes() if len(sys.argv) > 1 else urllib.request.urlopen(URL).read()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        text = archive.read("cities15000.txt").decode("utf-8")
    rows = []
    for line in text.splitlines():
        f = line.split("\t")
        name, ascii_name, country = f[1], f[2], f[8]
        lat, lon, population = float(f[4]), float(f[5]), int(f[14] or 0)
        rows.append((population, [name, "" if ascii_name == name else ascii_name, country, round(lat, 3), round(lon, 3)]))
    rows.sort(key=lambda row: (-row[0], row[1][0]))
    rows = [row for _, row in rows]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"{len(rows)} cities -> {OUT} ({OUT.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
