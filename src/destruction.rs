//! Terminal, signed network destruction records. Relaying requires no admin privilege.
use super::*;

pub(super) const ALPN: &[u8] = b"esp/destruction/cbor/3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
#[cbor(array)]
pub struct Certificate {
    #[n(0)]
    pub version: u8,
    #[n(1)]
    pub network_id: String,
    #[n(2)]
    #[cbor(with = "cbor::endpoint_id")]
    pub issuer: EndpointId,
    #[n(3)]
    pub issued_at_unix: u64,
    #[n(4)]
    pub authority: Vec<MembershipCertificate>,
    #[n(5)]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub certificate: Certificate,
    pub pending: Vec<EndpointId>,
}
impl Record {
    pub(super) fn new(certificate: Certificate, peers: &[Peer]) -> Self {
        Self {
            certificate,
            pending: peers.iter().map(|p| p.node_id).collect(),
        }
    }
}
impl Certificate {
    pub(super) fn issue(cfg: &Config) -> Result<Self> {
        cfg.ensure_local_admin()?;
        let key = cfg.secret_key()?;
        let mut certificate = Self {
            version: 3,
            network_id: cfg.network_id.clone(),
            issuer: key.public(),
            issued_at_unix: current_unix_time()?,
            authority: cfg.local_membership_chain()?,
            signature: String::new(),
        };
        certificate.signature = encode_signature(&key.sign(&certificate.payload()?));
        Ok(certificate)
    }
    fn payload(&self) -> Result<Vec<u8>> {
        if self.version != 3 {
            bail!(
                "unsupported destruction certificate version {}",
                self.version
            );
        }
        validate_network_id(&self.network_id)?;
        if self.authority.len() > ABSOLUTE_MAX_KNOWN_PEERS + 1 {
            bail!("destruction authority chain is too long");
        }
        Ok(minicbor::to_vec((
            "esp/destruction/3",
            self.version,
            &self.network_id,
            self.issuer.to_string(),
            self.issued_at_unix,
            &self.authority,
        ))?)
    }
    pub(super) fn verify(&self, cfg: &Config) -> Result<()> {
        if self.network_id != cfg.network_id {
            bail!("destruction certificate is for a different network");
        }
        self.issuer
            .verify(&self.payload()?, &decode_signature(&self.signature)?)
            .context("invalid destruction signature")?;
        let issuer = self
            .authority
            .iter()
            .find(|m| m.subject_node_id == self.issuer)
            .ok_or_else(|| anyhow!("missing destruction authority"))?;
        verify_membership_chain(cfg, issuer, &self.authority)?;
        if issuer.role != MembershipRole::Admin {
            bail!("destruction issuer must be an admin");
        }
        Ok(())
    }
}

pub(super) async fn receive(conn: Connection, actor: ConfigActorHandle) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let certificate: Certificate = read_cbor_frame(
            &mut recv,
            MAX_CONTROL_MESSAGE_LEN,
            "destruction certificate",
        )
        .await?;
        let result = actor
            .request(|respond| ConfigActorCommand::Destroy {
                certificate: Some(certificate),
                respond,
            })
            .await;
        let response: Option<String> = result.err().map(|e| e.to_string());
        write_cbor_frame(
            &mut send,
            &response,
            MAX_CONTROL_MESSAGE_LEN,
            "destruction acknowledgement",
        )
        .await?;
        finish_control_send(&mut send).await
    })
    .await
    .context("destruction notification timed out")?
}

static DELIVERY_BUDGET: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();

pub(super) async fn deliver(
    endpoint: &Endpoint,
    target: EndpointId,
    certificate: &Certificate,
) -> Result<()> {
    let budget = DELIVERY_BUDGET
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(8)))
        .clone();
    let _permit = budget
        .try_acquire_owned()
        .map_err(|_| anyhow!("destruction delivery budget busy; retry later"))?;
    timeout(Duration::from_secs(15), async {
        let conn = endpoint.connect(target, ALPN).await?;
        let _close = CloseConnectionOnDrop(conn.clone());
        let (mut send, mut recv) = conn.open_bi().await?;
        write_cbor_frame(
            &mut send,
            certificate,
            MAX_CONTROL_MESSAGE_LEN,
            "destruction certificate",
        )
        .await?;
        finish_control_send(&mut send).await?;
        let error: Option<String> = read_cbor_frame(
            &mut recv,
            MAX_CONTROL_MESSAGE_LEN,
            "destruction acknowledgement",
        )
        .await?;
        if let Some(error) = error {
            bail!(error);
        }
        Ok(())
    })
    .await
    .context("destruction delivery timed out")?
}

/// Each network owns one bounded retry loop. Delivery state survives restarts.
pub(super) async fn retry(endpoint: Endpoint, actor: ConfigActorHandle) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let Ok(cfg) = actor
            .request(|respond| ConfigActorCommand::Snapshot { respond })
            .await
        else {
            return;
        };
        if let Some(record) = cfg.destruction {
            endpoint.set_alpns(vec![ALPN.to_vec()]);
            for node_id in record.pending {
                if deliver(&endpoint, node_id, &record.certificate)
                    .await
                    .is_ok()
                {
                    let _ = actor
                        .request(|respond| ConfigActorCommand::Delivered { node_id, respond })
                        .await;
                }
            }
            backoff = (backoff * 2).min(Duration::from_secs(300));
        }
        tokio::time::sleep(backoff).await;
    }
}
