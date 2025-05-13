use serde::Serializer;
use time::{OffsetDateTime, macros::format_description};

pub fn serialize_offset_datetime<S>(dt: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match dt {
        Some(value) => {
            const FORMAT: &[time::format_description::FormatItem<'_>]
            = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

            let formatted = value.format(&FORMAT).unwrap_or_else(|_| "Invalid Date".to_string());
            serializer.serialize_str(&formatted)
        },
        None => serializer.serialize_none(),
    }
}
