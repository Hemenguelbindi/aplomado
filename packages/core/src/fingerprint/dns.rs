use std::net::IpAddr;

/// Reverse DNS lookup. Возвращает hostname для IP.
/// Если PTR недоступен — None.
///
/// Полноценный reverse DNS требует hickory-resolver.
/// Пока заглушка — всегда None.
pub async fn reverse_lookup(_ip: IpAddr) -> Option<String> {
    // TODO: добавить hickory-resolver для настоящего PTR запроса
    // let resolver = TokioAsyncResolver::tokio_from_system_conf().await.ok()?;
    // let lookup = resolver.reverse_lookup(ip).await.ok()?;
    // lookup.iter().next().map(|name| name.to_string().trim_end_matches('.').to_string())
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reverse_lookup_returns_none() {
        let result = reverse_lookup(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(result.is_none());
    }
}
