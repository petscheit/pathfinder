use std::collections::HashMap;

use anyhow::Context;
use futures::stream::BoxStream;
use futures::{Stream, StreamExt, TryStreamExt};
use p2p::client::peer_agnostic::Client as P2PClient;
use p2p::PeerData;
use pathfinder_common::event::Event;
use pathfinder_common::{BlockHash, BlockHeader, BlockNumber, SignedBlockHeader, TransactionHash};
use pathfinder_storage::Storage;
use tokio_stream::wrappers::ReceiverStream;

use crate::sync::error::SyncError2;
use crate::sync::events::{self, BlockEvents};
use crate::sync::headers;
use crate::sync::stream::{ProcessStage, SyncReceiver, SyncResult};

pub struct Sync<L> {
    latest: L,
    p2p: P2PClient,
    storage: Storage,
}

impl<L> Sync<L>
where
    L: Stream<Item = (BlockNumber, BlockHash)> + Clone + Send + 'static,
{
    pub async fn run(
        self,
        next: BlockNumber,
        parent_hash: BlockHash,
    ) -> Result<(), PeerData<SyncError2>> {
        let storage_connection = self
            .storage
            .connection()
            .context("Creating database connection")
            // FIXME: PeerData should allow for None peers.
            .map_err(|e| PeerData {
                peer: p2p::libp2p::PeerId::random(),
                data: SyncError2::from(e),
            })?;

        let mut headers = HeaderSource {
            p2p: self.p2p.clone(),
            latest_onchain: self.latest.clone(),
            start: next,
        }
        .spawn()
        .pipe(headers::ForwardContinuity::new(next, parent_hash), 100)
        .pipe(headers::VerifyHash {}, 100);

        let HeaderFanout { headers, events } = HeaderFanout::from_source(headers, 10);

        let events = EventSource {
            p2p: self.p2p.clone(),
            headers: events,
        }
        .spawn()
        .pipe(events::VerifyCommitment, 10);

        BlockStream {
            header: headers,
            events,
        }
        .spawn()
        .pipe(StoreBlock::new(storage_connection), 10)
        .into_stream()
        .try_fold((), |_, _| std::future::ready(Ok(())))
        .await
    }
}

struct HeaderSource<L> {
    p2p: P2PClient,
    latest_onchain: L,
    start: BlockNumber,
}

impl<L> HeaderSource<L>
where
    L: Stream<Item = (BlockNumber, BlockHash)> + Send + 'static,
{
    fn spawn(self) -> SyncReceiver<SignedBlockHeader> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let Self {
            p2p,
            latest_onchain,
            mut start,
        } = self;

        tokio::spawn(async move {
            let mut latest_onchain = Box::pin(latest_onchain);
            while let Some(latest_onchain) = latest_onchain.next().await {
                // Ignore reorgs for now. Unsure how to handle this properly.

                // TODO: Probably need a loop here if we don't get enough headers?
                let mut headers =
                    Box::pin(p2p.clone().header_stream(start, latest_onchain.0, false));

                while let Some(header) = headers.next().await {
                    start = header.data.header.number + 1;

                    if tx.send(Ok(header)).await.is_err() {
                        return;
                    }
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct HeaderFanout {
    headers: SyncReceiver<SignedBlockHeader>,
    events: BoxStream<'static, BlockHeader>,
}

impl HeaderFanout {
    fn from_source(mut source: SyncReceiver<SignedBlockHeader>, buffer: usize) -> Self {
        let (h_tx, h_rx) = tokio::sync::mpsc::channel(buffer);
        let (e_tx, e_rx) = tokio::sync::mpsc::channel(buffer);

        tokio::spawn(async move {
            while let Some(signed_header) = source.recv().await {
                let is_err = signed_header.is_err();

                if h_tx.send(signed_header.clone()).await.is_err() || is_err {
                    return;
                }

                let header = signed_header
                    .expect("Error case already handled")
                    .data
                    .header;

                if e_tx.send(header).await.is_err() {
                    return;
                }
            }
        });

        Self {
            headers: SyncReceiver::from_receiver(h_rx),
            events: ReceiverStream::new(e_rx).boxed(),
        }
    }
}

struct EventSource {
    p2p: P2PClient,
    headers: BoxStream<'static, BlockHeader>,
}

impl EventSource {
    fn spawn(self) -> SyncReceiver<BlockEvents> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let Self { p2p, mut headers } = self;

            while let Some(header) = headers.next().await {
                let (peer, mut events) = loop {
                    if let Some(stream) = p2p.clone().events_for_block(header.number).await {
                        break stream;
                    }
                };

                let event_count = header.event_count;
                let mut block_events = BlockEvents {
                    header,
                    events: Default::default(),
                };

                // Receive the exact amount of expected events for this block.
                for _ in 0..event_count {
                    let Some((tx_hash, event)) = events.next().await else {
                        let err = PeerData::new(peer, SyncError2::TooFewEvents);
                        let _ = tx.send(Err(err)).await;
                        return;
                    };

                    block_events.events.entry(tx_hash).or_default().push(event);
                }

                // Ensure that the stream is exhausted.
                if events.next().await.is_some() {
                    let err = PeerData::new(peer, SyncError2::TooManyEvents);
                    let _ = tx.send(Err(err)).await;
                    return;
                }

                let block_events = PeerData::new(peer, block_events);
                if tx.send(Ok(block_events)).await.is_err() {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }
}

struct BlockStream {
    pub header: SyncReceiver<SignedBlockHeader>,
    pub events: SyncReceiver<BlockEvents>,
}

impl BlockStream {
    fn spawn(mut self) -> SyncReceiver<BlockData> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            loop {
                let Some(result) = self.next().await else {
                    return;
                };

                let is_err = result.is_err();

                if tx.send(result).await.is_err() || is_err {
                    return;
                }
            }
        });

        SyncReceiver::from_receiver(rx)
    }

    async fn next(&mut self) -> Option<SyncResult<BlockData>> {
        let header = self.header.recv().await?;
        let header = match header {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let events = self.events.recv().await?;
        let events = match events {
            Ok(x) => x,
            Err(err) => return Some(Err(err)),
        };

        let data = BlockData {
            header: header.data,
            events: events.data.events,
        };

        Some(Ok(PeerData::new(header.peer, data)))
    }
}

struct BlockData {
    pub header: SignedBlockHeader,
    pub events: HashMap<TransactionHash, Vec<Event>>,
}

struct StoreBlock {
    connection: pathfinder_storage::Connection,
}

impl StoreBlock {
    pub fn new(connection: pathfinder_storage::Connection) -> Self {
        Self { connection }
    }
}

impl ProcessStage for StoreBlock {
    type Input = BlockData;
    type Output = ();

    fn map(&mut self, input: Self::Input) -> Result<Self::Output, SyncError2> {
        let BlockData { header, events } = input;

        let db = self
            .connection
            .transaction()
            .context("Creating database connection")?;

        // TODO: write all the data to storage

        db.commit()
            .context("Committing transaction")
            .map_err(Into::into)
    }
}
