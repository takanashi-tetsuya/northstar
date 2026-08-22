use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn get_private_xml(
    pool: &PgPool,
    user_id: Uuid,
    element_name: &str,
    element_ns: &str,
) -> Result<Option<String>> {
    let result = sqlx::query_scalar::<_, String>(
        "SELECT xml_data FROM private_xml WHERE user_id = $1 AND element_name = $2 AND element_ns = $3",
    )
    .bind(user_id)
    .bind(element_name)
    .bind(element_ns)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

pub async fn set_private_xml(
    pool: &PgPool,
    user_id: Uuid,
    element_name: &str,
    element_ns: &str,
    xml_data: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO private_xml (user_id, element_name, element_ns, xml_data) 
         VALUES ($1, $2, $3, $4) 
         ON CONFLICT (user_id, element_name, element_ns) DO UPDATE SET xml_data = EXCLUDED.xml_data",
    )
    .bind(user_id)
    .bind(element_name)
    .bind(element_ns)
    .bind(xml_data)
    .execute(pool)
    .await?;

    Ok(())
}
