use anyhow::Result;
use zeroize::Zeroize;

/// Per-connection channel-binding data. Neither binding type is inferred from
/// the other: RFC 5929 `tls-server-end-point` is unavailable for certificate
/// signature algorithms such as Ed25519, while RFC 9266 `tls-exporter` is
/// derived from the negotiated TLS connection rather than the certificate.
/// At least one binding must be present before this value is constructed.
#[derive(Clone, Debug)]
pub struct ChannelBindings {
    tls_server_end_point: Option<Vec<u8>>,
    tls_exporter: Option<Vec<u8>>,
}

impl Drop for ChannelBindings {
    fn drop(&mut self) {
        self.tls_server_end_point.zeroize();
        self.tls_exporter.zeroize();
    }
}

impl ChannelBindings {
    pub fn new(tls_server_end_point: Vec<u8>, tls_exporter: Option<Vec<u8>>) -> Result<Self> {
        Self::from_available(Some(tls_server_end_point), tls_exporter)?.ok_or_else(|| {
            anyhow::anyhow!("at least one TLS channel-binding type must be available")
        })
    }

    pub fn from_available(
        tls_server_end_point: Option<Vec<u8>>,
        tls_exporter: Option<Vec<u8>>,
    ) -> Result<Option<Self>> {
        if tls_server_end_point
            .as_ref()
            .is_some_and(|value| value.is_empty())
            || tls_exporter.as_ref().is_some_and(|value| value.len() != 32)
        {
            anyhow::bail!("invalid TLS channel-binding data");
        }
        if tls_server_end_point.is_none() && tls_exporter.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            tls_server_end_point,
            tls_exporter,
        }))
    }

    pub fn get(&self, kind: &str) -> Option<&[u8]> {
        match kind {
            "tls-server-end-point" => self.tls_server_end_point.as_deref(),
            "tls-exporter" => self.tls_exporter.as_deref(),
            _ => None,
        }
    }

    pub fn feature_xml(&self) -> String {
        let endpoint = if self.tls_server_end_point.is_some() {
            "<channel-binding type='tls-server-end-point'/>"
        } else {
            ""
        };
        let exporter = if self.tls_exporter.is_some() {
            "<channel-binding type='tls-exporter'/>"
        } else {
            ""
        };
        format!(
            "<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>{endpoint}{exporter}</sasl-channel-binding>"
        )
    }

    /// Channel-binding bytes used by the hash-token SASL mechanisms from
    /// XEP-0484. Keeping this mapping next to the SCRAM binding container
    /// prevents the two authentication profiles from silently disagreeing.
    pub fn for_fast_mechanism(&self, mechanism: &str) -> Option<&[u8]> {
        match mechanism {
            "HT-SHA-256-ENDP" => self.get("tls-server-end-point"),
            "HT-SHA-256-EXPR" => self.get("tls-exporter"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_binding_advertisement_matches_available_tls_capabilities() {
        let exporter_only = ChannelBindings::from_available(None, Some(vec![0x11; 32]))
            .unwrap()
            .unwrap();
        assert!(exporter_only.get("tls-server-end-point").is_none());
        assert_eq!(exporter_only.get("tls-exporter"), Some(&[0x11; 32][..]));
        assert_eq!(
            exporter_only.feature_xml(),
            "<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-exporter'/></sasl-channel-binding>"
        );

        let endpoint_only = ChannelBindings::from_available(Some(vec![0x22; 32]), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            endpoint_only.get("tls-server-end-point"),
            Some(&[0x22; 32][..])
        );
        assert!(endpoint_only.get("tls-exporter").is_none());
        assert_eq!(
            endpoint_only.feature_xml(),
            "<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/></sasl-channel-binding>"
        );

        assert!(ChannelBindings::from_available(None, None)
            .unwrap()
            .is_none());
        assert!(ChannelBindings::from_available(None, Some(vec![0; 31])).is_err());
        assert!(ChannelBindings::from_available(Some(Vec::new()), None).is_err());
    }
}
