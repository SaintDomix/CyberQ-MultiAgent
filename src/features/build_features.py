from pathlib import Path
import argparse

import pandas as pd


PROJECT_DIR = Path.home() / "dissertation_model"

EVENTS_FILE = (
    PROJECT_DIR / "data" / "processed" / "events.csv"
)

METADATA_FILE = (
    PROJECT_DIR / "experiments" / "experiment_metadata.csv"
)

OUTPUT_FILE = (
    PROJECT_DIR / "data" / "processed" / "features.csv"
)

SUMMARY_FILE = (
    PROJECT_DIR / "outputs" / "tables" / "feature_summary.csv"
)


def compute_features(group, window_seconds):
    group = group.sort_values("timestamp_utc")

    request_count = len(group)

    paths = group["path"].fillna("")
    query = group["query"].fillna("")

    status = pd.to_numeric(
        group["status"],
        errors="coerce"
    ).fillna(0)

    bytes_out = pd.to_numeric(
        group["bytes_out"],
        errors="coerce"
    ).fillna(0)

    timestamps = group["timestamp_utc"].sort_values()

    differences = (
        timestamps
        .diff()
        .dt.total_seconds()
        .dropna()
    )

    if len(timestamps) > 1:
        active_span_sec = (
            timestamps.iloc[-1]
            - timestamps.iloc[0]
        ).total_seconds()

        mean_inter_request_sec = differences.mean()
        min_inter_request_sec = differences.min()

    else:
        active_span_sec = 0.0
        mean_inter_request_sec = 0.0
        min_inter_request_sec = 0.0

    unique_paths = paths.nunique()

    get_count = (group["method"] == "GET").sum()
    post_count = (group["method"] == "POST").sum()

    status_2xx_count = (
        (status >= 200) & (status < 300)
    ).sum()

    status_3xx_count = (
        (status >= 300) & (status < 400)
    ).sum()

    status_4xx_count = (
        (status >= 400) & (status < 500)
    ).sum()

    status_5xx_count = (
        (status >= 500) & (status < 600)
    ).sum()

    error_count = (
        status_4xx_count
        + status_5xx_count
    )

    login_path_count = (
        paths.str.contains(
            r"/login/",
            regex=True
        )
    ).sum()

    admin_path_count = (
        paths.str.contains(
            r"/admin/",
            regex=True
        )
    ).sum()

    ajax_request_count = (
        paths.str.contains(
            r"/lib/ajax/|_ajax\.php",
            regex=True
        )
    ).sum()

    query_request_count = (
        query.str.len() > 0
    ).sum()

    return {
        "request_count": request_count,

        "requests_per_second":
            request_count / window_seconds,

        "unique_paths": unique_paths,

        "unique_path_ratio":
            unique_paths / request_count,

        "get_count": get_count,

        "post_count": post_count,

        "post_ratio":
            post_count / request_count,

        "status_2xx_count":
            status_2xx_count,

        "status_3xx_count":
            status_3xx_count,

        "status_4xx_count":
            status_4xx_count,

        "status_5xx_count":
            status_5xx_count,

        "error_ratio":
            error_count / request_count,

        "bytes_out_total":
            bytes_out.sum(),

        "bytes_out_mean":
            bytes_out.mean(),

        "login_path_count":
            login_path_count,

        "admin_path_count":
            admin_path_count,

        "ajax_request_count":
            ajax_request_count,

        "query_request_count":
            query_request_count,

        "active_span_sec":
            active_span_sec,

        "mean_inter_request_sec":
            mean_inter_request_sec,

        "min_inter_request_sec":
            min_inter_request_sec,
    }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Behavioral window size in seconds"
    )

    args = parser.parse_args()

    window_seconds = args.window

    events = pd.read_csv(EVENTS_FILE)

    metadata = pd.read_csv(
        METADATA_FILE,
        dtype={"run": str}
    )

    events["run"] = (
        events["run"]
        .astype(str)
        .str.zfill(2)
    )

    metadata["run"] = (
        metadata["run"]
        .astype(str)
        .str.zfill(2)
    )

    events["timestamp_utc"] = pd.to_datetime(
        events["timestamp_utc"],
        utc=True
    )

    metadata["start_utc"] = pd.to_datetime(
        metadata["start_utc"],
        utc=True
    )

    metadata["end_utc"] = pd.to_datetime(
        metadata["end_utc"],
        utc=True
    )

    metadata = metadata[
        metadata["scenario_id"] != "TEST"
    ].copy()

    feature_rows = []

    for _, experiment in metadata.iterrows():

        scenario_id = experiment["scenario_id"]
        run = experiment["run"]
        label = experiment["label"]

        start = experiment["start_utc"]
        end = experiment["end_utc"]

        experiment_events = events[
            (events["scenario_id"] == scenario_id)
            & (events["run"] == run)
            & (events["label"] == label)
            & (events["timestamp_utc"] >= start)
            & (events["timestamp_utc"] < end)
        ].copy()

        if experiment_events.empty:
            print(
                f"[WARNING] No events for "
                f"{scenario_id} run {run}"
            )
            continue

        experiment_events["elapsed_sec"] = (
            experiment_events["timestamp_utc"]
            - start
        ).dt.total_seconds()

        experiment_events["window_id"] = (
            experiment_events["elapsed_sec"]
            // window_seconds
        ).astype(int)

        grouped = experiment_events.groupby(
            [
                "client_ip",
                "user_agent",
                "window_id",
            ],
            sort=True
        )

        for (
            client_ip,
            user_agent,
            window_id
        ), group in grouped:

            window_start = (
                start
                + pd.to_timedelta(
                    window_id * window_seconds,
                    unit="s"
                )
            )

            window_end = (
                window_start
                + pd.to_timedelta(
                    window_seconds,
                    unit="s"
                )
            )

            features = compute_features(
                group,
                window_seconds
            )

            row = {
                "scenario_id": scenario_id,
                "label": label,
                "run": run,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "window_id": window_id,
                "window_start_utc": window_start,
                "window_end_utc": window_end,
            }

            row.update(features)

            feature_rows.append(row)

    if not feature_rows:
        raise RuntimeError(
            "No behavioral windows were created."
        )

    features_df = pd.DataFrame(feature_rows)

    features_df = (
        features_df
        .sort_values(
            [
                "scenario_id",
                "run",
                "window_id",
                "client_ip",
            ]
        )
        .reset_index(drop=True)
    )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    SUMMARY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    features_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    summary = (
        features_df
        .groupby(
            [
                "scenario_id",
                "run",
                "label",
            ]
        )
        .agg(
            windows=("window_id", "count"),
            total_requests=("request_count", "sum"),
            mean_requests=("request_count", "mean"),
            max_requests=("request_count", "max"),
            mean_unique_paths=("unique_paths", "mean"),
            mean_post_ratio=("post_ratio", "mean"),
            mean_error_ratio=("error_ratio", "mean"),
        )
        .reset_index()
    )

    summary.to_csv(
        SUMMARY_FILE,
        index=False
    )

    print()
    print("Feature engineering completed")
    print("--------------------------------")
    print(f"Window size           : {window_seconds} sec")
    print(f"Behavioral windows    : {len(features_df)}")
    print(f"Feature dataset       : {OUTPUT_FILE}")
    print(f"Feature summary       : {SUMMARY_FILE}")
    print()

    print("Windows per experiment:")

    print(
        features_df
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
