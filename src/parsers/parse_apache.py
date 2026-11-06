from pathlib import Path
import csv
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pandas as pd


PROJECT_DIR = Path.home() / "dissertation_model"

METADATA_FILE = (
    PROJECT_DIR / "experiments" / "experiment_metadata.csv"
)

OUTPUT_FILE = (
    PROJECT_DIR / "data" / "processed" / "events.csv"
)

SUMMARY_FILE = (
    PROJECT_DIR / "outputs" / "tables" / "parsing_summary.csv"
)


# Apache "combined" format used by our Moodle server:
#
# %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"
#
LOG_PATTERN = re.compile(
    r'^(?P<client_ip>\S+) '
    r'(?P<ident>\S+) '
    r'(?P<authuser>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<bytes_out>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"$'
)


def parse_timestamp(value):
    dt = datetime.strptime(
        value,
        "%d/%b/%Y:%H:%M:%S %z"
    )

    return dt.astimezone(timezone.utc)


def parse_request(request):
    parts = request.split()

    if len(parts) < 3:
        return None, None, None, None, None

    method = parts[0]
    target = parts[1]
    protocol = parts[-1]

    parsed = urlsplit(target)

    path = parsed.path
    query = parsed.query

    return method, target, path, query, protocol


def parse_log_line(line):
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    (
        method,
        request_target,
        path,
        query,
        protocol
    ) = parse_request(data["request"])

    if method is None:
        return None

    try:
        timestamp = parse_timestamp(
            data["timestamp"]
        )
    except ValueError:
        return None

    if data["bytes_out"] == "-":
        bytes_out = 0
    else:
        try:
            bytes_out = int(
                data["bytes_out"]
            )
        except ValueError:
            bytes_out = 0

    return {
        "timestamp_utc": timestamp,
        "client_ip": data["client_ip"],
        "method": method,
        "request_target": request_target,
        "path": path,
        "query": query,
        "protocol": protocol,
        "status": int(data["status"]),
        "bytes_out": bytes_out,
        "referer": data["referer"],
        "user_agent": data["user_agent"],
    }


def main():

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    SUMMARY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    all_events = []
    summaries = []

    with open(
        METADATA_FILE,
        newline="",
        encoding="utf-8"
    ) as f:

        reader = csv.DictReader(f)

        for experiment in reader:

            scenario_id = experiment[
                "scenario_id"
            ]

            # TEST was only used to validate
            # the capture mechanism.
            if scenario_id == "TEST":
                continue

            access_file = Path(
                experiment["access_file"]
            )

            if not access_file.exists():

                print(
                    f"[WARNING] File not found: "
                    f"{access_file}"
                )

                continue

            total_lines = 0
            parsed_lines = 0
            failed_lines = 0

            with open(
                access_file,
                encoding="utf-8",
                errors="replace"
            ) as log_file:

                for line in log_file:

                    total_lines += 1

                    event = parse_log_line(
                        line
                    )

                    if event is None:
                        failed_lines += 1
                        continue

                    parsed_lines += 1

                    event["scenario_id"] = (
                        scenario_id
                    )

                    event["label"] = (
                        experiment["label"]
                    )

                    event["run"] = (
                        experiment["run"]
                    )

                    all_events.append(event)

            summaries.append({
                "scenario_id": scenario_id,
                "label": experiment["label"],
                "run": experiment["run"],
                "file": access_file.name,
                "total_lines": total_lines,
                "parsed_lines": parsed_lines,
                "failed_lines": failed_lines,
            })

    if not all_events:
        raise RuntimeError(
            "No Apache events were parsed."
        )

    events_df = pd.DataFrame(
        all_events
    )

    events_df["timestamp_utc"] = (
        pd.to_datetime(
            events_df["timestamp_utc"],
            utc=True
        )
    )

    events_df = (
        events_df
        .sort_values(
            [
                "timestamp_utc",
                "scenario_id",
                "run",
            ]
        )
        .reset_index(drop=True)
    )

    events_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    summary_df = pd.DataFrame(
        summaries
    )

    summary_df.to_csv(
        SUMMARY_FILE,
        index=False
    )

    print()
    print(
        "Apache preprocessing completed"
    )
    print(
        "--------------------------------"
    )

    print(
        f"Experiments processed : "
        f"{len(summary_df)}"
    )

    print(
        f"HTTP events parsed    : "
        f"{len(events_df)}"
    )

    print(
        f"Parsing failures      : "
        f"{summary_df['failed_lines'].sum()}"
    )

    print(
        f"Dataset               : "
        f"{OUTPUT_FILE}"
    )

    print(
        f"QA summary            : "
        f"{SUMMARY_FILE}"
    )

    print()

    print("Events by experiment:")

    print(
        events_df
        .groupby(
            [
                "scenario_id",
                "run",
                "label",
            ]
        )
        .size()
    )


if __name__ == "__main__":
    main()
