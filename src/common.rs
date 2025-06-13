
use embedded_hal::delay::DelayNs;


pub struct DummyDelay;

impl embedded_hal::delay::DelayNs for DummyDelay {
    fn delay_ns(&mut self, ns: u32) {
        for _ in 0..(ns / 100) {
            cortex_m::asm::nop();
        }
    }
}

#[repr(align(32))]
#[link_section = ".ram_nc"] //non-cacheable memory
pub struct DmaBuffer<const N: usize> {
    pub buf: [u8; N],
}

impl<const N: usize> DmaBuffer<N> {
    pub const fn new() -> Self {
        Self { buf: [0; N] }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    pub fn len(&self) -> usize {
        N
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self, start:usize, end:usize) -> &mut [u8] {
        &mut self.buf[start..end]
    }
}

use core::ops::{Index, IndexMut};

impl<const N: usize> Index<usize> for DmaBuffer<N> {
    type Output = u8;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.buf[idx]
    }
}

impl<const N: usize> IndexMut<usize> for DmaBuffer<N> {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.buf[idx]
    }
}