#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};

pub type AgentId = u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub req_id: u64,
    pub sender: AgentId,
    pub seq: u64,
    pub kind: u16,
}

#[derive(Debug)]
pub struct Mailbox {
    pub queues: BTreeMap<AgentId, VecDeque<Message>>,
    pub next_req_id: u64,
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
            queues: BTreeMap::new(),
            next_req_id: 1,
        }
    }

    pub fn send(&mut self, sender: AgentId, receiver: AgentId, mut msg: Message) -> u64 {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.saturating_add(1);

        msg.req_id = req_id;
        msg.sender = sender;
        self.queues.entry(receiver).or_default().push_back(msg);
        req_id
    }

    pub fn recv(&mut self, receiver: AgentId) -> Option<Message> {
        let queue = self.queues.get_mut(&receiver)?;
        let msg = queue.pop_front();
        if queue.is_empty() {
            self.queues.remove(&receiver);
        }
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message};
    use crate::runtime::event_reader::{
        EventReader, KIND_BUS_RECV, KIND_BUS_SEND, KIND_TASK_STARTED, LOG_HEADER_LEN,
        RECORD_HEADER_LEN,
    };
    use crate::runtime::event_recorder::EventRecorder;
    use std::fs;
    use std::io::BufReader;

    #[test]
    fn req_id_increments_deterministically_across_sends() {
        let mut mailbox = Mailbox::new();

        let r1 = mailbox.send(
            1,
            9,
            Message {
                req_id: 0,
                sender: 999,
                seq: 1,
                kind: 10,
            },
        );
        let r2 = mailbox.send(
            2,
            9,
            Message {
                req_id: 0,
                sender: 999,
                seq: 2,
                kind: 11,
            },
        );
        let r3 = mailbox.send(
            3,
            8,
            Message {
                req_id: 0,
                sender: 999,
                seq: 3,
                kind: 12,
            },
        );

        assert_eq!(r1, 1);
        assert_eq!(r2, 2);
        assert_eq!(r3, 3);

        let m1 = mailbox.recv(9).expect("receiver 9 first");
        let m2 = mailbox.recv(9).expect("receiver 9 second");
        let m3 = mailbox.recv(8).expect("receiver 8 first");

        assert_eq!((m1.req_id, m1.sender, m1.seq, m1.kind), (1, 1, 1, 10));
        assert_eq!((m2.req_id, m2.sender, m2.seq, m2.kind), (2, 2, 2, 11));
        assert_eq!((m3.req_id, m3.sender, m3.seq, m3.kind), (3, 3, 3, 12));
    }

    #[test]
    fn bus_send_recv_events_are_emitted_in_deterministic_order() {
        let base = std::env::temp_dir().join("nex_agent_bus_step2_event_order");
        let out_dir = base.join("out");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");

        let path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open recorder");
        rec.record_task_started(0).expect("task started");

        let mut mailbox = Mailbox::new();

        let req1 = mailbox.send(
            7,
            42,
            Message {
                req_id: 0,
                sender: 0,
                seq: 100,
                kind: 1,
            },
        );
        rec.record_bus_send(0, req1, 7, 42, 1, 0, 0)
            .expect("record bus send #1");

        let req2 = mailbox.send(
            8,
            42,
            Message {
                req_id: 0,
                sender: 0,
                seq: 101,
                kind: 2,
            },
        );
        rec.record_bus_send(0, req2, 8, 42, 2, 0, 0)
            .expect("record bus send #2");

        let first = mailbox.recv(42).expect("first recv");
        rec.record_bus_recv(0, first.req_id, 42)
            .expect("record bus recv #1");

        let second = mailbox.recv(42).expect("second recv");
        rec.record_bus_recv(0, second.req_id, 42)
            .expect("record bus recv #2");

        rec.record_task_finished(0, 0).expect("task finished");
        rec.record_run_finished(0, 0).expect("run finished");
        drop(rec);

        let file = fs::File::open(&path).expect("open events");
        let mut reader = EventReader::new(BufReader::new(file));
        reader.read_log_header().expect("read header");

        let mut kinds = Vec::new();
        let mut req_ids = Vec::new();
        while let Some(ev) = reader.read_next().expect("read event") {
            kinds.push(ev.kind);
            if ev.kind == KIND_BUS_SEND {
                req_ids.push(u64::from_le_bytes(
                    ev.payload[0..8].try_into().expect("req id"),
                ));
            }
            if ev.kind == KIND_BUS_RECV {
                req_ids.push(u64::from_le_bytes(
                    ev.payload[0..8].try_into().expect("req id"),
                ));
            }
        }

        let bus_kinds: Vec<u16> = kinds
            .into_iter()
            .filter(|k| *k == KIND_BUS_SEND || *k == KIND_BUS_RECV)
            .collect();
        assert_eq!(
            bus_kinds,
            vec![KIND_BUS_SEND, KIND_BUS_SEND, KIND_BUS_RECV, KIND_BUS_RECV]
        );
        assert_eq!(req_ids, vec![1, 2, 1, 2]);
    }

    #[test]
    fn recv_returns_correct_order_per_receiver() {
        let mut mailbox = Mailbox::new();

        mailbox.send(
            1,
            10,
            Message {
                req_id: 0,
                sender: 0,
                seq: 1,
                kind: 1,
            },
        );
        mailbox.send(
            2,
            11,
            Message {
                req_id: 0,
                sender: 0,
                seq: 2,
                kind: 2,
            },
        );
        mailbox.send(
            3,
            10,
            Message {
                req_id: 0,
                sender: 0,
                seq: 3,
                kind: 3,
            },
        );

        let r10_first = mailbox.recv(10).expect("receiver 10 first");
        let r11_first = mailbox.recv(11).expect("receiver 11 first");
        let r10_second = mailbox.recv(10).expect("receiver 10 second");

        assert_eq!((r10_first.sender, r10_first.seq), (1, 1));
        assert_eq!((r11_first.sender, r11_first.seq), (2, 2));
        assert_eq!((r10_second.sender, r10_second.seq), (3, 3));
        assert!(mailbox.recv(11).is_none());
        assert!(mailbox.recv(10).is_none());
    }

    #[test]
    fn event_layout_lengths_are_stable() {
        assert_eq!(LOG_HEADER_LEN, 76);
        assert_eq!(RECORD_HEADER_LEN, 22);
        assert_eq!(KIND_TASK_STARTED, 6);
    }
}
