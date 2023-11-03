import argparse
import json
import psycopg


def upload_metrics(metrics, connection: str):
    with psycopg.connect(connection) as conn:
        with conn.cursor() as cur:
            for name, value in metrics.items():
                cur.execute(
                    "INSERT INTO amp_metrics (metric_name, metric_value) VALUES (%s, %s)",
                    (name, value))


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--metrics",
        help="The location of the `weekly-metrics.json` file",
        required=True,
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "--connection",
        help="The connection string for the Postgres instance to upload metrics to",
        required=True,
        type=str,
    )

    args = parser.parse_args()

    metrics = json.load(args.metrics)

    upload_metrics(metrics, args.connection)


if __name__ == "__main__":
    main()
