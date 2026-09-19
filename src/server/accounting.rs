//! What a public ProxyMode session owes when it ends: its lease back, and
//! its relayed bytes charged to the client's windows. Settled on the normal
//! path and, through `Drop`, on every other one.

use std::sync::Arc;

use tracing::warn;

use super::NotaryState;
use crate::{
    client_ip::ClientKey,
    limits::DataCap,
    store::{
        Dimension,
        LeaseId,
        LimitStore,
        Store,
        WindowLimits,
    },
};

/// What one public session owes the store when it ends: the bytes it
/// relayed, charged to its client's windows, and its lease back.
///
/// Settled on the way out of the handler; if the handler never gets there --
/// a panic, or the task cancelled under it -- the drop settles from a task
/// of its own, so no lease outlives its session and no bytes go uncharged.
/// Neither can fail the session: a store that will not take the charge is
/// logged and the session has already ended.
pub(super) struct Accounting {
    bill: Option<Bill>,
}

/// The client a public session ran as, the lease it held, and the bytes it
/// relayed, with the store and the windows they are charged to.
struct Bill {
    store: Store,
    client: ClientKey,
    lease: Option<LeaseId>,
    relayed: Arc<DataCap>,
    windows: WindowLimits,
}

impl Accounting {
    /// `client`'s session on `state`, holding `lease`, with its relayed
    /// bytes counted in `relayed`.
    pub(super) fn new(
        state: &NotaryState,
        client: ClientKey,
        lease: Option<LeaseId>,
        relayed: &Arc<DataCap>,
    ) -> Self {
        Self {
            bill: Some(Bill {
                store: state.limits.clone(),
                client,
                lease,
                relayed: Arc::clone(relayed),
                windows: state.per_ip_bytes.clone(),
            }),
        }
    }

    pub(super) async fn settle(mut self) {
        if let Some(bill) = self.bill.take() {
            bill.settle().await;
        }
    }
}

impl Drop for Accounting {
    fn drop(&mut self) {
        let Some(bill) = self.bill.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(bill.settle());
            }
            // The runtime itself is going away; the lease expires by itself.
            Err(_) => {
                warn!(client = %bill.client, "ProxyMode: no runtime to settle a session's accounting")
            }
        }
    }
}

impl Bill {
    async fn settle(self) {
        let used = self.relayed.used();
        if used > 0 {
            if let Err(error) = self
                .store
                .charge(&self.client, Dimension::Bytes, used as u64, &self.windows)
                .await
            {
                warn!(client = %self.client, used, %error, "ProxyMode: relayed bytes not charged");
            }
        }
        if let Some(lease) = self.lease {
            if let Err(error) = self.store.release(&lease).await {
                warn!(client = %self.client, %error, "ProxyMode: session lease not released; it expires by itself");
            }
        }
    }
}
