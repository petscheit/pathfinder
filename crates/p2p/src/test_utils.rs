use std::collections::{HashMap, HashSet};

use libp2p::kad::{QueryId, QueryResult};
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, PeerId};
use tokio::sync::{mpsc, oneshot};

use super::{behaviour, Command, Event, TestCommand, TestEvent};
use crate::peers::Peer;

#[derive(Clone)]
pub(super) struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    pub(super) fn new(sender: mpsc::Sender<Command>) -> Self {
        Self { sender }
    }
}

impl Client {
    pub async fn get_peers_from_dht(&self) -> HashSet<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::_Test(TestCommand::GetPeersFromDHT(sender)))
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn get_connected_peers(&self) -> HashMap<PeerId, Peer> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::_Test(TestCommand::GetConnectedPeers(sender)))
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }
}

pub(super) async fn handle_event(
    event_sender: &mpsc::Sender<Event>,
    event: SwarmEvent<behaviour::Event>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            send_event(event_sender, TestEvent::NewListenAddress(address)).await;
        }
        SwarmEvent::Behaviour(behaviour::Event::Gossipsub(gossipsub::Event::Subscribed {
            peer_id,
            topic,
        })) => {
            send_event(
                event_sender,
                TestEvent::Subscribed {
                    remote: peer_id,
                    topic: topic.into_string(),
                },
            )
            .await;
        }
        _ => {}
    }
}

pub(super) async fn handle_command(
    behavior: &mut behaviour::Behaviour,
    command: TestCommand,
    _pending_test_queries: &mut PendingQueries,
) {
    match command {
        TestCommand::GetPeersFromDHT(sender) => {
            let peers = behavior
                .kademlia_mut()
                .kbuckets()
                // Cannot .into_iter() a KBucketRef, hence the inner collect followed by flat_map
                .map(|kbucket_ref| {
                    kbucket_ref
                        .iter()
                        .map(|entry_ref| *entry_ref.node.key.preimage())
                        .collect::<Vec<_>>()
                })
                .flat_map(|peers_in_bucket| peers_in_bucket.into_iter())
                .collect::<HashSet<_>>();
            sender.send(peers).expect("Receiver not to be dropped")
        }
        TestCommand::GetConnectedPeers(sender) => {
            let peers = behavior
                .peers()
                .filter_map(|(peer_id, peer)| {
                    if peer.is_connected() {
                        Some((peer_id, peer.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            sender.send(peers).expect("Receiver not to be dropped")
        }
    }
}

pub(super) async fn send_event(event_sender: &mpsc::Sender<Event>, event: TestEvent) {
    event_sender
        .send(Event::Test(event))
        .await
        .expect("Event receiver not to be dropped");
}

pub(super) async fn query_completed(
    _pending_test_queries: &mut PendingQueries,
    event_sender: &mpsc::Sender<Event>,
    _id: QueryId,
    result: QueryResult,
) {
    if let QueryResult::StartProviding(result) = result {
        use libp2p::kad::AddProviderOk;

        let result = match result {
            Ok(AddProviderOk { key }) => Ok(key),
            Err(error) => Err(error.into_key()),
        };
        send_event(event_sender, TestEvent::StartProvidingCompleted(result)).await
    }
}

pub(super) async fn query_progressed(
    _pending_test_queries: &PendingQueries,
    _id: QueryId,
    _result: QueryResult,
) {
    // QueryResult::GetProviders used to be handled here, but now just keeping
    // this fn as a placeholder for future query types in tests.
}

#[derive(Debug, Default)]
pub(super) struct PendingQueries {
    // QueryResult::GetProviders used to be handled here, but now just keeping this struct
    // as a placeholder for future query types in tests.
}
