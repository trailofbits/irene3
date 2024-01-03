# AMP Metrics Dashboard

Some of our testing is too time-consuming to execute in our pull-request workflow.
Instead, we've opted to create a [weekly workflow](../.github/workflows/metrics.yml) to run the more intensive tasks and [a Grafana dashboard](https://grafana.trailofbits.network/d/e641a227-d6a1-477a-b4fc-5f3cfa44a861/amp-metrics?orgId=1) to track these metrics.
This document is to keep track of how our workflow operates and interacts with infrastructure that exists outside of the IRENE-3 repository.

## Building metrics

Since the dashboard displays metrics from multiple jobs in the weekly workflow, we have a step to combine these disparate data formats into a single metrics JSON file.

The relevant job is called `build-metrics` and runs after all testing tasks have completed.

### Metric naming conventions

At the moment, we're trying to have each job publish their stats under their own prefix.
For example, IRENE-3's challenge testing metrics are all prefixed with `challenge`, but we have further subcategories to group stats at a level of granularity appropriate for a single dashboard (`challenge.ghidra` for metrics relating to IRENE-3's Ghidra plugin, `challenge.decompiler` for metrics relating to Anvill, etc).

## Connecting to the metrics database

The remaining steps are performed as part of the `publish-metrics` job.

The weekly workflow writes metrics to our Google Cloud SQL PostgreSQL instance, which is connected to our Grafana instance as a data source.

In order to connect to the PostgreSQL instance, we need to use the Google Cloud SQL Auth Proxy.
We currently achieve this via the GitHub Action `mattes/gce-cloudsql-proxy-action` like so:

```yaml
      - name: Start Google Cloud SQL Proxy
        uses: mattes/gce-cloudsql-proxy-action@v1
        with:
          creds: ${{ secrets.GOOGLE_APPLICATION_CREDENTIALS }}
          instance: data-warehouse-392820:us-central1:warehouse
```

We supply the instance connection name (`data-warehouse-392820:us-central1:warehouse`) as well as the credentials JSON object.
Once we're connected, the database can be accessed to via this connection string:

```
postgresql://amp_write:${{ secrets.AMP_WRITE_PASSWORD }}@127.0.0.1/warehouse
```

## Writing to the metrics database

The `warehouse` database has a table named `amp_metrics` which was created with the following command:

```sql
CREATE TABLE amp_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(255),
    metric_value DECIMAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

We iterate over the metrics JSON file and do a series of insertions into our database to be accessed via the Grafana dashboard.
