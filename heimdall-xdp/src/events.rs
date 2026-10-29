//! Ring Buffer Event Handling

use aya::maps::{RingBuf, Map, MapData};
use crate::types::DetectionEvent;
use anyhow::Result;

pub struct EventReader<'a> {
    ring_buf: RingBuf<&'a mut MapData>,
}

impl<'a> EventReader<'a> {
    /// Create EventReader from a Map reference (use ebpf.map_mut("EVENTS"))
    pub fn new(map: &'a mut Map) -> Result<Self> {
        let ring_buf = RingBuf::try_from(map)?;
        Ok(Self { ring_buf })
    }

    /// Read next event from ring buffer (non-blocking)
    pub fn read(&mut self) -> Option<DetectionEvent> {
        if let Some(item) = self.ring_buf.next() {
            if item.len() >= std::mem::size_of::<DetectionEvent>() {
                return Some(unsafe {
                    std::ptr::read(item.as_ptr() as *const DetectionEvent)
                });
            }
        }
        None
    }
}
