#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type AgentId = u32;
pub type ChannelId = u64;
pub type SchemaId = u64;

pub const DEFAULT_MAX_MSG_BYTES: usize = 65_536;
pub const DEFAULT_MAX_QUEUE_PER_RECEIVER: usize = 1_024;
pub const DEFAULT_BASE_SEND_COST: u64 = 4;
pub const DEFAULT_PER_BYTE_COST: u64 = 1;
pub const DEFAULT_MAX_SENDS_PER_WINDOW: u32 = u32::MAX;

pub const BUS_REASON_ALLOWED: u32 = 0;
pub const BUS_REASON_CAP_SEND_DENIED: u32 = 1;
pub const BUS_REASON_CAP_RECV_DENIED: u32 = 2;
pub const BUS_REASON_MSG_TOO_LARGE: u32 = 3;
pub const BUS_REASON_QUEUE_FULL: u32 = 4;
pub const BUS_REASON_FUEL_EXHAUSTED: u32 = 5;
pub const BUS_REASON_EMPTY: u32 = 6;
pub const BUS_REASON_UNKNOWN_CHANNEL: u32 = 7;
pub const BUS_REASON_CHANNEL_CLOSED: u32 = 8;
pub const BUS_REASON_SCHEMA_MISMATCH: u32 = 9;
pub const BUS_REASON_RATE_LIMIT: u32 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub req_id: u64,
    pub channel_id: ChannelId,
    pub sender: AgentId,
    pub sender_seq: u64,
    pub seq: u64,
    pub kind: u16,
    pub schema_id: SchemaId,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusCapabilities {
    pub allow_send: bool,
    pub allow_recv: bool,
}

impl Default for BusCapabilities {
    fn default() -> Self {
        Self {
            allow_send: true,
            allow_recv: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelLimits {
    pub max_message_size: u32,
    pub max_queue_depth: u32,
    pub max_sends_per_window: u32,
}

impl Default for ChannelLimits {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MSG_BYTES as u32,
            max_queue_depth: DEFAULT_MAX_QUEUE_PER_RECEIVER as u32,
            max_sends_per_window: DEFAULT_MAX_SENDS_PER_WINDOW,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChannelState {
    schema_id: SchemaId,
    limits: ChannelLimits,
    open: bool,
    sends_in_window: u32,
    next_sender_seq: BTreeMap<AgentId, u64>,
    by_sender: BTreeMap<AgentId, VecDeque<Message>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendOutcome {
    pub req_id: u64,
    pub channel_id: ChannelId,
    pub sender_seq: u64,
    pub schema_id: SchemaId,
    pub payload_hash64: u64,
    pub allowed: bool,
    pub reason_code: u32,
    pub ok: bool,
    pub fuel_cost: u32,
    pub bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecvOutcome {
    pub allowed: bool,
    pub reason_code: u32,
    pub message: Option<Message>,
}

#[derive(Debug)]
pub struct Mailbox {
    // Legacy receiver mailboxes kept for compatibility with existing generated runtime code.
    pub queues_by_sender: BTreeMap<AgentId, BTreeMap<AgentId, VecDeque<Message>>>,

    // Enhanced deterministic channel bus.
    channels: BTreeMap<ChannelId, ChannelState>,
    next_channel_id: ChannelId,

    pub next_req_id: u64,
    pub capabilities: BusCapabilities,
    pub max_msg_bytes: usize,
    pub max_queue_per_receiver: usize,
    pub fuel_remaining: u64,
    pub base_send_cost: u64,
    pub per_byte_cost: u64,

    send_caps: BTreeMap<AgentId, BTreeSet<ChannelId>>,
    recv_caps: BTreeMap<AgentId, BTreeSet<ChannelId>>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox {
    #[inline]
    pub fn new() -> Self {
        Self {
            queues_by_sender: BTreeMap::new(),
            channels: BTreeMap::new(),
            next_channel_id: 1,
            next_req_id: 1,
            capabilities: BusCapabilities::default(),
            max_msg_bytes: DEFAULT_MAX_MSG_BYTES,
            max_queue_per_receiver: DEFAULT_MAX_QUEUE_PER_RECEIVER,
            fuel_remaining: u64::MAX,
            base_send_cost: DEFAULT_BASE_SEND_COST,
            per_byte_cost: DEFAULT_PER_BYTE_COST,
            send_caps: BTreeMap::new(),
            recv_caps: BTreeMap::new(),
        }
    }

    pub fn set_capabilities(&mut self, allow_send: bool, allow_recv: bool) {
        self.capabilities = BusCapabilities {
            allow_send,
            allow_recv,
        };
    }

    pub fn set_limits(&mut self, max_msg_bytes: usize, max_queue_per_receiver: usize) {
        self.max_msg_bytes = max_msg_bytes;
        self.max_queue_per_receiver = max_queue_per_receiver;
    }

    pub fn set_fuel(&mut self, remaining: u64, base_send_cost: u64, per_byte_cost: u64) {
        self.fuel_remaining = remaining;
        self.base_send_cost = base_send_cost;
        self.per_byte_cost = per_byte_cost;
    }

    pub fn schema_id_from_type(canonical_type_sig: &str) -> SchemaId {
        fnv1a64(canonical_type_sig.as_bytes())
    }

    pub fn channel_create(&mut self, schema_id: SchemaId, limits: ChannelLimits) -> ChannelId {
        let channel_id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.saturating_add(1);
        self.channels.insert(
            channel_id,
            ChannelState {
                schema_id,
                limits,
                open: true,
                sends_in_window: 0,
                next_sender_seq: BTreeMap::new(),
                by_sender: BTreeMap::new(),
            },
        );
        channel_id
    }

    pub fn channel_close(&mut self, channel_id: ChannelId) -> bool {
        if let Some(ch) = self.channels.get_mut(&channel_id) {
            ch.open = false;
            ch.by_sender.clear();
            true
        } else {
            false
        }
    }

    pub fn grant_send_capability(&mut self, sender: AgentId, channel_id: ChannelId) {
        self.send_caps.entry(sender).or_default().insert(channel_id);
    }

    pub fn grant_recv_capability(&mut self, receiver: AgentId, channel_id: ChannelId) {
        self.recv_caps
            .entry(receiver)
            .or_default()
            .insert(channel_id);
    }

    pub fn clear_channel_capabilities(&mut self) {
        self.send_caps.clear();
        self.recv_caps.clear();
    }

    pub fn channel_send(
        &mut self,
        sender: AgentId,
        channel_id: ChannelId,
        schema_id: SchemaId,
        payload: Vec<u8>,
    ) -> SendOutcome {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.saturating_add(1);

        let payload_len = payload.len();
        let bytes_u32 = u32::try_from(payload_len).unwrap_or(u32::MAX);
        let payload_hash64 = fnv1a64(&payload);

        let mut denied = |reason_code: u32| SendOutcome {
            req_id,
            channel_id,
            sender_seq: 0,
            schema_id,
            payload_hash64,
            allowed: false,
            reason_code,
            ok: false,
            fuel_cost: 0,
            bytes: bytes_u32,
        };

        if !self.capabilities.allow_send {
            return denied(BUS_REASON_CAP_SEND_DENIED);
        }

        if let Some(allowed) = self.send_caps.get(&sender) {
            if !allowed.contains(&channel_id) {
                return denied(BUS_REASON_CAP_SEND_DENIED);
            }
        }

        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return denied(BUS_REASON_UNKNOWN_CHANNEL);
        };

        if !channel.open {
            return denied(BUS_REASON_CHANNEL_CLOSED);
        }

        if schema_id != channel.schema_id {
            return denied(BUS_REASON_SCHEMA_MISMATCH);
        }

        if payload_len > channel.limits.max_message_size as usize {
            return denied(BUS_REASON_MSG_TOO_LARGE);
        }

        let depth: usize = channel.by_sender.values().map(VecDeque::len).sum();
        if depth >= channel.limits.max_queue_depth as usize {
            return denied(BUS_REASON_QUEUE_FULL);
        }

        if channel.sends_in_window >= channel.limits.max_sends_per_window {
            return denied(BUS_REASON_RATE_LIMIT);
        }

        let payload_u64 = u64::try_from(payload_len).unwrap_or(u64::MAX);
        let raw_cost = self
            .base_send_cost
            .saturating_add(self.per_byte_cost.saturating_mul(payload_u64));
        if self.fuel_remaining < raw_cost {
            return denied(BUS_REASON_FUEL_EXHAUSTED);
        }

        self.fuel_remaining = self.fuel_remaining.saturating_sub(raw_cost);

        let sender_seq = *channel.next_sender_seq.entry(sender).or_insert(1);
        if let Some(next) = channel.next_sender_seq.get_mut(&sender) {
            *next = next.saturating_add(1);
        }

        let message = Message {
            req_id,
            channel_id,
            sender,
            sender_seq,
            seq: sender_seq,
            kind: 0,
            schema_id,
            payload,
        };

        channel
            .by_sender
            .entry(sender)
            .or_default()
            .push_back(message);
        channel.sends_in_window = channel.sends_in_window.saturating_add(1);

        SendOutcome {
            req_id,
            channel_id,
            sender_seq,
            schema_id,
            payload_hash64,
            allowed: true,
            reason_code: BUS_REASON_ALLOWED,
            ok: true,
            fuel_cost: u32::try_from(raw_cost).unwrap_or(u32::MAX),
            bytes: bytes_u32,
        }
    }

    pub fn channel_recv(&mut self, receiver: AgentId, channel_id: ChannelId) -> RecvOutcome {
        if !self.capabilities.allow_recv {
            return RecvOutcome {
                allowed: false,
                reason_code: BUS_REASON_CAP_RECV_DENIED,
                message: None,
            };
        }

        if let Some(allowed) = self.recv_caps.get(&receiver) {
            if !allowed.contains(&channel_id) {
                return RecvOutcome {
                    allowed: false,
                    reason_code: BUS_REASON_CAP_RECV_DENIED,
                    message: None,
                };
            }
        }

        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return RecvOutcome {
                allowed: false,
                reason_code: BUS_REASON_UNKNOWN_CHANNEL,
                message: None,
            };
        };

        if !channel.open {
            return RecvOutcome {
                allowed: false,
                reason_code: BUS_REASON_CHANNEL_CLOSED,
                message: None,
            };
        }

        let Some(sender) = Self::pick_sender_for_channel(channel_id, &channel.by_sender) else {
            return RecvOutcome {
                allowed: true,
                reason_code: BUS_REASON_EMPTY,
                message: None,
            };
        };

        let queue = channel
            .by_sender
            .get_mut(&sender)
            .expect("sender queue exists");
        let message = queue.pop_front();
        if queue.is_empty() {
            channel.by_sender.remove(&sender);
        }

        RecvOutcome {
            allowed: true,
            reason_code: BUS_REASON_ALLOWED,
            message,
        }
    }

    // Legacy API retained to avoid behavior changes in existing generated code/tests.
    pub fn send(&mut self, sender: AgentId, receiver: AgentId, mut msg: Message) -> SendOutcome {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.saturating_add(1);

        msg.req_id = req_id;
        msg.channel_id = u64::from(receiver);
        msg.sender = sender;
        msg.sender_seq = msg.seq;

        let payload_len = msg.payload.len();
        let bytes_u32 = u32::try_from(payload_len).unwrap_or(u32::MAX);
        let payload_hash64 = fnv1a64(&msg.payload);

        if !self.capabilities.allow_send {
            return SendOutcome {
                req_id,
                channel_id: u64::from(receiver),
                sender_seq: msg.sender_seq,
                schema_id: msg.schema_id,
                payload_hash64,
                allowed: false,
                reason_code: BUS_REASON_CAP_SEND_DENIED,
                ok: false,
                fuel_cost: 0,
                bytes: bytes_u32,
            };
        }

        if payload_len > self.max_msg_bytes {
            return SendOutcome {
                req_id,
                channel_id: u64::from(receiver),
                sender_seq: msg.sender_seq,
                schema_id: msg.schema_id,
                payload_hash64,
                allowed: false,
                reason_code: BUS_REASON_MSG_TOO_LARGE,
                ok: false,
                fuel_cost: 0,
                bytes: bytes_u32,
            };
        }

        if self.receiver_depth(receiver) >= self.max_queue_per_receiver {
            return SendOutcome {
                req_id,
                channel_id: u64::from(receiver),
                sender_seq: msg.sender_seq,
                schema_id: msg.schema_id,
                payload_hash64,
                allowed: false,
                reason_code: BUS_REASON_QUEUE_FULL,
                ok: false,
                fuel_cost: 0,
                bytes: bytes_u32,
            };
        }

        let payload_u64 = u64::try_from(payload_len).unwrap_or(u64::MAX);
        let raw_cost = self
            .base_send_cost
            .saturating_add(self.per_byte_cost.saturating_mul(payload_u64));

        if self.fuel_remaining < raw_cost {
            return SendOutcome {
                req_id,
                channel_id: u64::from(receiver),
                sender_seq: msg.sender_seq,
                schema_id: msg.schema_id,
                payload_hash64,
                allowed: false,
                reason_code: BUS_REASON_FUEL_EXHAUSTED,
                ok: false,
                fuel_cost: 0,
                bytes: bytes_u32,
            };
        }

        self.fuel_remaining = self.fuel_remaining.saturating_sub(raw_cost);

        self.queues_by_sender
            .entry(receiver)
            .or_default()
            .entry(sender)
            .or_default()
            .push_back(msg.clone());

        SendOutcome {
            req_id,
            channel_id: u64::from(receiver),
            sender_seq: msg.sender_seq,
            schema_id: msg.schema_id,
            payload_hash64,
            allowed: true,
            reason_code: BUS_REASON_ALLOWED,
            ok: true,
            fuel_cost: u32::try_from(raw_cost).unwrap_or(u32::MAX),
            bytes: bytes_u32,
        }
    }

    pub fn recv(&mut self, receiver: AgentId) -> RecvOutcome {
        if !self.capabilities.allow_recv {
            return RecvOutcome {
                allowed: false,
                reason_code: BUS_REASON_CAP_RECV_DENIED,
                message: None,
            };
        }

        let sender = {
            let by_sender = match self.queues_by_sender.get(&receiver) {
                Some(v) => v,
                None => {
                    return RecvOutcome {
                        allowed: true,
                        reason_code: BUS_REASON_EMPTY,
                        message: None,
                    };
                }
            };

            match Self::pick_sender_for_delivery(by_sender) {
                Some(s) => s,
                None => {
                    return RecvOutcome {
                        allowed: true,
                        reason_code: BUS_REASON_EMPTY,
                        message: None,
                    };
                }
            }
        };

        let by_sender = match self.queues_by_sender.get_mut(&receiver) {
            Some(v) => v,
            None => {
                return RecvOutcome {
                    allowed: true,
                    reason_code: BUS_REASON_EMPTY,
                    message: None,
                };
            }
        };

        let queue = match by_sender.get_mut(&sender) {
            Some(v) => v,
            None => {
                return RecvOutcome {
                    allowed: true,
                    reason_code: BUS_REASON_EMPTY,
                    message: None,
                };
            }
        };

        let message = queue.pop_front();

        if queue.is_empty() {
            by_sender.remove(&sender);
        }
        if by_sender.is_empty() {
            self.queues_by_sender.remove(&receiver);
        }

        RecvOutcome {
            allowed: true,
            reason_code: BUS_REASON_ALLOWED,
            message,
        }
    }

    pub fn reset_channel_rate_windows(&mut self) {
        for channel in self.channels.values_mut() {
            channel.sends_in_window = 0;
        }
    }

    fn receiver_depth(&self, receiver: AgentId) -> usize {
        self.queues_by_sender
            .get(&receiver)
            .map(|by_sender| by_sender.values().map(VecDeque::len).sum())
            .unwrap_or(0)
    }

    fn pick_sender_for_delivery(
        by_sender: &BTreeMap<AgentId, VecDeque<Message>>,
    ) -> Option<AgentId> {
        let mut best: Option<(u64, AgentId)> = None;

        for (sender, queue) in by_sender {
            let head = queue.front()?;
            let candidate = (head.req_id, *sender);
            if best.map(|b| candidate < b).unwrap_or(true) {
                best = Some(candidate);
            }
        }

        best.map(|(_, sender)| sender)
    }

    fn pick_sender_for_channel(
        channel_id: ChannelId,
        by_sender: &BTreeMap<AgentId, VecDeque<Message>>,
    ) -> Option<AgentId> {
        let mut best: Option<(AgentId, u64, ChannelId)> = None;

        for (sender, queue) in by_sender {
            let head = queue.front()?;
            let candidate = (*sender, head.sender_seq, channel_id);
            if best.map(|b| candidate < b).unwrap_or(true) {
                best = Some(candidate);
            }
        }

        best.map(|(sender, _, _)| sender)
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{
        ChannelLimits, Mailbox, Message, BUS_REASON_CAP_RECV_DENIED, BUS_REASON_CAP_SEND_DENIED,
        BUS_REASON_FUEL_EXHAUSTED, BUS_REASON_MSG_TOO_LARGE, BUS_REASON_QUEUE_FULL,
        BUS_REASON_RATE_LIMIT, BUS_REASON_SCHEMA_MISMATCH,
    };
    use crate::runtime::event_reader::{
        EventReader, KIND_CHANNEL_CLOSED, KIND_CHANNEL_CREATED, KIND_MESSAGE_BLOCKED,
        KIND_MESSAGE_DELIVERED, KIND_MESSAGE_SENT, KIND_TASK_STARTED, LOG_HEADER_LEN,
        RECORD_HEADER_LEN,
    };
    use crate::runtime::event_recorder::EventRecorder;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::io::BufReader;

    fn msg(seq: u64, kind: u16, schema_id: u64, payload: Vec<u8>) -> Message {
        Message {
            req_id: 0,
            channel_id: 0,
            sender: 0,
            sender_seq: seq,
            seq,
            kind,
            schema_id,
            payload,
        }
    }

    #[test]
    fn req_id_increments_deterministically_across_sends() {
        let mut mailbox = Mailbox::new();

        let r1 = mailbox.send(1, 9, msg(1, 10, 1, vec![]));
        let r2 = mailbox.send(2, 9, msg(2, 11, 2, vec![]));
        let r3 = mailbox.send(3, 8, msg(3, 12, 3, vec![]));

        assert_eq!(r1.req_id, 1);
        assert_eq!(r2.req_id, 2);
        assert_eq!(r3.req_id, 3);

        let m1 = mailbox.recv(9).message.expect("receiver 9 first");
        let m2 = mailbox.recv(9).message.expect("receiver 9 second");
        let m3 = mailbox.recv(8).message.expect("receiver 8 first");

        assert_eq!((m1.req_id, m1.sender, m1.seq, m1.kind), (1, 1, 1, 10));
        assert_eq!((m2.req_id, m2.sender, m2.seq, m2.kind), (2, 2, 2, 11));
        assert_eq!((m3.req_id, m3.sender, m3.seq, m3.kind), (3, 3, 3, 12));
    }

    #[test]
    fn canonical_merge_ordering() {
        let mut mailbox = Mailbox::new();

        let r1 = mailbox.send(2, 42, msg(200, 1, 10, vec![]));
        let r2 = mailbox.send(1, 42, msg(100, 2, 11, vec![]));
        let r3 = mailbox.send(2, 42, msg(201, 3, 12, vec![]));

        let m1 = mailbox.recv(42).message.expect("first");
        let m2 = mailbox.recv(42).message.expect("second");
        let m3 = mailbox.recv(42).message.expect("third");

        assert_eq!((m1.req_id, m1.sender), (r1.req_id, 2));
        assert_eq!((m2.req_id, m2.sender), (r2.req_id, 1));
        assert_eq!((m3.req_id, m3.sender), (r3.req_id, 2));
    }

    #[test]
    fn canonical_merge_tie_breaks_by_sender() {
        let mut mailbox = Mailbox::new();
        let receiver = 7u32;

        let mut by_sender: BTreeMap<u32, VecDeque<Message>> = BTreeMap::new();
        by_sender.insert(2, VecDeque::from([msg(1, 1, 1, vec![])]));
        by_sender.insert(1, VecDeque::from([msg(2, 2, 2, vec![])]));

        if let Some(q) = by_sender.get_mut(&2) {
            q[0].req_id = 11;
            q[0].sender = 2;
        }
        if let Some(q) = by_sender.get_mut(&1) {
            q[0].req_id = 11;
            q[0].sender = 1;
        }

        mailbox.queues_by_sender.insert(receiver, by_sender);

        let first = mailbox
            .recv(receiver)
            .message
            .expect("first tie-break recv");
        let second = mailbox
            .recv(receiver)
            .message
            .expect("second tie-break recv");

        assert_eq!(first.sender, 1);
        assert_eq!(second.sender, 2);
    }

    #[test]
    fn send_without_capability_denied() {
        let mut mailbox = Mailbox::new();
        mailbox.set_capabilities(false, true);

        let out = mailbox.send(1, 42, msg(1, 1, 1, vec![1, 2, 3]));
        assert!(!out.allowed);
        assert!(!out.ok);
        assert_eq!(out.reason_code, BUS_REASON_CAP_SEND_DENIED);
        assert!(mailbox.recv(42).message.is_none());
    }

    #[test]
    fn recv_without_capability_denied() {
        let mut mailbox = Mailbox::new();
        let _ = mailbox.send(1, 42, msg(1, 1, 1, vec![]));
        mailbox.set_capabilities(true, false);

        let out = mailbox.recv(42);
        assert!(!out.allowed);
        assert_eq!(out.reason_code, BUS_REASON_CAP_RECV_DENIED);
        assert!(out.message.is_none());
    }

    #[test]
    fn msg_too_large_denied() {
        let mut mailbox = Mailbox::new();
        mailbox.set_limits(3, 1024);

        let out = mailbox.send(1, 42, msg(1, 1, 1, vec![0, 1, 2, 3]));
        assert!(!out.allowed);
        assert_eq!(out.reason_code, BUS_REASON_MSG_TOO_LARGE);
    }

    #[test]
    fn queue_full_backpressure_denied() {
        let mut mailbox = Mailbox::new();
        mailbox.set_limits(64, 1);

        let first = mailbox.send(1, 42, msg(1, 1, 1, vec![7]));
        assert!(first.ok);

        let second = mailbox.send(2, 42, msg(2, 1, 1, vec![8]));
        assert!(!second.ok);
        assert_eq!(second.reason_code, BUS_REASON_QUEUE_FULL);
    }

    #[test]
    fn fuel_exhausted_send_denied() {
        let mut mailbox = Mailbox::new();
        mailbox.set_fuel(5, 4, 1);

        let out = mailbox.send(1, 42, msg(1, 1, 1, vec![0, 1, 2]));
        assert!(!out.ok);
        assert_eq!(out.reason_code, BUS_REASON_FUEL_EXHAUSTED);
    }

    #[test]
    fn typed_schema_validation_channel_send_denied() {
        let mut mailbox = Mailbox::new();
        let schema_a = Mailbox::schema_id_from_type("Msg<A>");
        let schema_b = Mailbox::schema_id_from_type("Msg<B>");
        let channel = mailbox.channel_create(schema_a, ChannelLimits::default());

        let out = mailbox.channel_send(1, channel, schema_b, b"payload".to_vec());
        assert!(!out.ok);
        assert_eq!(out.reason_code, BUS_REASON_SCHEMA_MISMATCH);
    }

    #[test]
    fn channel_merge_order_sender_then_sender_seq_then_channel() {
        let mut mailbox = Mailbox::new();
        let schema = Mailbox::schema_id_from_type("Msg<Test>");
        let channel = mailbox.channel_create(schema, ChannelLimits::default());

        let s2_a = mailbox.channel_send(2, channel, schema, b"s2-a".to_vec());
        assert!(s2_a.ok);
        let s1_a = mailbox.channel_send(1, channel, schema, b"s1-a".to_vec());
        assert!(s1_a.ok);
        let s1_b = mailbox.channel_send(1, channel, schema, b"s1-b".to_vec());
        assert!(s1_b.ok);

        let m1 = mailbox.channel_recv(99, channel).message.expect("m1");
        let m2 = mailbox.channel_recv(99, channel).message.expect("m2");
        let m3 = mailbox.channel_recv(99, channel).message.expect("m3");

        assert_eq!((m1.sender, m1.sender_seq), (1, 1));
        assert_eq!((m2.sender, m2.sender_seq), (1, 2));
        assert_eq!((m3.sender, m3.sender_seq), (2, 1));
    }

    #[test]
    fn channel_rate_limit_denied_deterministically() {
        let mut mailbox = Mailbox::new();
        let schema = Mailbox::schema_id_from_type("Msg<R>");
        let limits = ChannelLimits {
            max_message_size: 1024,
            max_queue_depth: 1024,
            max_sends_per_window: 1,
        };
        let channel = mailbox.channel_create(schema, limits);

        let ok = mailbox.channel_send(1, channel, schema, b"first".to_vec());
        assert!(ok.ok);
        let denied = mailbox.channel_send(1, channel, schema, b"second".to_vec());
        assert!(!denied.ok);
        assert_eq!(denied.reason_code, BUS_REASON_RATE_LIMIT);

        mailbox.reset_channel_rate_windows();
        let ok2 = mailbox.channel_send(1, channel, schema, b"third".to_vec());
        assert!(ok2.ok);
    }

    #[test]
    fn required_message_events_roundtrip() {
        let base = std::env::temp_dir().join("nex_agent_bus_v075_required_events");
        let out_dir = base.join("out");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");

        let path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open recorder");
        rec.record_task_started(0).expect("task started");
        rec.record_channel_created(0, 1, 10, 20, 0xAA55)
            .expect("channel created");
        rec.record_message_sent(0, 2, 10, 7, 1, 20, 0x11, 5)
            .expect("message sent");
        rec.record_message_blocked(0, 3, 10, 42)
            .expect("message blocked");
        rec.record_message_delivered(0, 4, 10, 42, 7, 1, 0x11, 5)
            .expect("message delivered");
        rec.record_channel_closed(0, 5, 10).expect("channel closed");
        rec.record_task_finished(0, 0).expect("task finished");
        rec.record_run_finished(0, 0).expect("run finished");
        drop(rec);

        let file = fs::File::open(&path).expect("open events");
        let mut reader = EventReader::new(BufReader::new(file));
        reader.read_log_header().expect("read header");

        let mut bus_kinds = Vec::new();
        while let Some(ev) = reader.read_next().expect("read event") {
            match ev.kind {
                KIND_CHANNEL_CREATED
                | KIND_MESSAGE_SENT
                | KIND_MESSAGE_BLOCKED
                | KIND_MESSAGE_DELIVERED
                | KIND_CHANNEL_CLOSED => bus_kinds.push(ev.kind),
                _ => {}
            }
        }

        assert_eq!(
            bus_kinds,
            vec![
                KIND_CHANNEL_CREATED,
                KIND_MESSAGE_SENT,
                KIND_MESSAGE_BLOCKED,
                KIND_MESSAGE_DELIVERED,
                KIND_CHANNEL_CLOSED
            ]
        );
        assert_eq!(LOG_HEADER_LEN, 76);
        assert_eq!(RECORD_HEADER_LEN, 22);
        assert_eq!(KIND_TASK_STARTED, 6);
    }
}
