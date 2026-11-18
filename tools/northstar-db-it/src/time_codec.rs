//! northstar-time must reproduce chrono 0.4.45's frozen PostgreSQL results.
use sqlx::{postgres::PgRow, Connection, Encode, PgConnection, Postgres, Type};

mod cases;
mod support;

use support::{column, outcome, Records};

async fn bound_pair<T, U>(
    connection: &mut PgConnection,
    sql: &'static str,
    first: T,
    second: U,
) -> Result<PgRow, sqlx::Error>
where
    T: for<'q> Encode<'q, Postgres> + Type<Postgres> + Send,
    U: for<'q> Encode<'q, Postgres> + Type<Postgres> + Send,
{
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(first)
        .bind(second)
        .fetch_one(connection)
        .await
}

fn encoded_columns(records: &mut Records, label: &str, northstar: &Result<PgRow, sqlx::Error>) {
    records.push(
        format!("{label}/text"),
        column::<Option<String>>(northstar, 0),
    );
    records.push(
        format!("{label}/equal"),
        column::<Option<bool>>(northstar, 1),
    );
}

async fn encode_timestamps(connection: &mut PgConnection, records: &mut Records) {
    const SQL: &str = "SELECT $1::timestamptz::text, \
        $1::timestamptz = $2::timestamptz, extract(epoch from $1::timestamptz)::text";
    for instant in cases::instants() {
        let northstar = northstar_time::DateTime::<northstar_time::Utc>::from_timestamp(
            instant.seconds,
            instant.nanos,
        );
        records.push(
            format!("construct/timestamptz/{}", instant.label),
            outcome(Ok(northstar)),
        );
        if let Some(northstar) = northstar {
            let northstar_row = bound_pair(connection, SQL, northstar, northstar).await;
            let label = format!("encode/timestamptz/{}", instant.label);
            encoded_columns(records, &label, &northstar_row);
            records.push(
                format!("{label}/epoch"),
                column::<Option<String>>(&northstar_row, 2),
            );
        }
    }

    const NULL_SQL: &str = "SELECT $1::timestamptz::text, \
        $1::timestamptz = $2::timestamptz, $1::timestamptz";
    let northstar = None::<northstar_time::DateTime<northstar_time::Utc>>;
    let northstar_row = bound_pair(connection, NULL_SQL, northstar, northstar).await;
    encoded_columns(records, "encode/timestamptz/null", &northstar_row);
    records.push(
        "encode/timestamptz/null/value",
        column::<Option<northstar_time::DateTime<northstar_time::Utc>>>(&northstar_row, 2),
    );

    // Avoid putting the server-rejected MIN_UTC in a vector: it would mask all
    // successful element encodings, including pre-epoch rounding and leaps.
    let values = [
        (0, 0),
        (-1, 999_999_999),
        (946_684_799, 999_999_999),
        (1_483_228_799, 1_500_000_000),
        (1_788_350_400, 123_456_789),
    ];
    let northstar: Vec<_> = values
        .iter()
        .map(|&(seconds, nanos)| {
            northstar_time::DateTime::<northstar_time::Utc>::from_timestamp(seconds, nanos)
                .expect("representable array instant")
        })
        .collect();
    const ARRAY_SQL: &str = "SELECT $1::timestamptz[]::text, \
        $1::timestamptz[] = $2::timestamptz[], $1::timestamptz[]";
    for (label, northstar) in [("values", northstar), ("empty", Vec::new())] {
        let northstar_row = bound_pair(connection, ARRAY_SQL, northstar.clone(), northstar).await;
        let label = format!("encode/timestamptz_array/{label}");
        encoded_columns(records, &label, &northstar_row);
        records.push(
            format!("{label}/value"),
            column::<Vec<northstar_time::DateTime<northstar_time::Utc>>>(&northstar_row, 2),
        );
    }
}

async fn fetch(
    connection: &mut PgConnection,
    sql: String,
    text: bool,
) -> Result<PgRow, sqlx::Error> {
    if text {
        // Simple query protocol is essential: prepared queries return binary.
        sqlx::Executor::fetch_one(connection, sqlx::raw_sql(sqlx::AssertSqlSafe(sql.as_str())))
            .await
    } else {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .fetch_one(connection)
            .await
    }
}

fn timestamp_columns(records: &mut Records, label: &str, row: &Result<PgRow, sqlx::Error>) {
    records.push(
        format!("{label}/utc"),
        column::<northstar_time::DateTime<northstar_time::Utc>>(row, 0),
    );
    records.push(
        format!("{label}/fixed_offset"),
        column::<northstar_time::DateTime<northstar_time::FixedOffset>>(row, 0),
    );
    records.push(
        format!("{label}/option_utc"),
        column::<Option<northstar_time::DateTime<northstar_time::Utc>>>(row, 0),
    );
}

async fn decode_timestamps(
    connection: &mut PgConnection,
    records: &mut Records,
    protocol: &str,
    text: bool,
) {
    for &(label, literal) in cases::TIMESTAMPS {
        let row = fetch(connection, format!("SELECT {literal}::timestamptz"), text).await;
        timestamp_columns(
            records,
            &format!("decode/{protocol}/timestamptz/{label}"),
            &row,
        );
        // Each boundary also gets its own singleton array, so an earlier
        // overflowing element cannot hide the next element's behaviour.
        let row = fetch(
            connection,
            format!("SELECT ARRAY[{literal}]::timestamptz[]"),
            text,
        )
        .await;
        records.push(
            format!("decode/{protocol}/timestamptz_array/{label}"),
            column::<Vec<northstar_time::DateTime<northstar_time::Utc>>>(&row, 0),
        );
    }
    let literals: Vec<_> = cases::TIMESTAMPS
        .iter()
        .map(|(_, literal)| *literal)
        .collect();
    for (label, sql) in [
        (
            "all",
            format!("SELECT ARRAY[{}]::timestamptz[]", literals.join(",")),
        ),
        ("empty", "SELECT ARRAY[]::timestamptz[]".into()),
    ] {
        let row = fetch(connection, sql, text).await;
        records.push(
            format!("decode/{protocol}/timestamptz_array/{label}"),
            column::<Vec<northstar_time::DateTime<northstar_time::Utc>>>(&row, 0),
        );
    }
    let row = fetch(connection, "SELECT NULL::timestamptz".into(), text).await;
    records.push(
        format!("decode/{protocol}/timestamptz/null"),
        column::<Option<northstar_time::DateTime<northstar_time::Utc>>>(&row, 0),
    );
}

async fn encode_dates(connection: &mut PgConnection, records: &mut Records) {
    for &(label, year, month, day) in cases::DATES {
        let northstar = northstar_time::NaiveDate::from_ymd_opt(year, month, day);
        records.push(format!("construct/date/{label}"), outcome(Ok(northstar)));
        if let Some(northstar) = northstar {
            let northstar_row = sqlx::query("SELECT $1::date::text")
                .bind(northstar)
                .fetch_one(&mut *connection)
                .await;
            records.push(
                format!("encode/date/{label}"),
                column::<String>(&northstar_row, 0),
            );
        }
    }
}

async fn decode_naive_and_dates(
    connection: &mut PgConnection,
    records: &mut Records,
    protocol: &str,
    text: bool,
) {
    for &(label, literal) in cases::NAIVE_TIMESTAMPS {
        let row = fetch(connection, format!("SELECT {literal}::timestamp"), text).await;
        records.push(
            format!("decode/{protocol}/timestamp/{label}"),
            column::<northstar_time::NaiveDateTime>(&row, 0),
        );
    }
    let mut dates: Vec<_> = cases::DATES
        .iter()
        .map(|(literal, _, _, _)| {
            (
                format!("decode/{protocol}/date/{literal}"),
                format!("'{literal}'::date"),
            )
        })
        .collect();
    for literal in ["infinity", "-infinity"] {
        dates.push((
            format!("decode/{protocol}/date/{literal}"),
            format!("'{literal}'::date"),
        ));
    }
    for (label, expression) in dates {
        let row = fetch(connection, format!("SELECT {expression}"), text).await;
        records.push(label, column::<northstar_time::NaiveDate>(&row, 0));
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and TEST_DATABASE_URL to replay frozen chrono 0.4.45 results"]
async fn northstar_time_and_chrono_store_and_read_identical_postgres_timestamps_and_dates(
) -> anyhow::Result<()> {
    let url = std::env::var("TEST_DATABASE_URL")?;
    let mut connection = PgConnection::connect(&url).await?;
    if let Ok(role) = std::env::var("TEST_DATABASE_ROLE") {
        sqlx::query("SELECT pg_catalog.set_config('role',$1,FALSE)")
            .bind(role)
            .execute(&mut connection)
            .await?;
    }
    sqlx::query("SET DateStyle TO 'ISO, MDY'")
        .execute(&mut connection)
        .await?;
    sqlx::query("SET TIME ZONE 'UTC'")
        .execute(&mut connection)
        .await?;

    let mut records = Records::default();
    encode_timestamps(&mut connection, &mut records).await;
    encode_dates(&mut connection, &mut records).await;
    decode_timestamps(&mut connection, &mut records, "binary/UTC", false).await;
    decode_naive_and_dates(&mut connection, &mut records, "binary/UTC", false).await;
    for zone in ["UTC", "Asia/Tokyo", "America/St_Johns"] {
        sqlx::query("SELECT pg_catalog.set_config('TimeZone',$1,FALSE)")
            .bind(zone)
            .execute(&mut connection)
            .await?;
        decode_timestamps(&mut connection, &mut records, &format!("text/{zone}"), true).await;
        if zone == "UTC" {
            decode_naive_and_dates(&mut connection, &mut records, "text/UTC", true).await;
        }
    }
    records.compare_fixture()?;
    Ok(())
}
