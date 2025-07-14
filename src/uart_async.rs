// Licensed under the Apache-2.0 license

use ast1060_pac::Uart;

use crate::uart::UartController;

use core::future::poll_fn;
use core::task::{Context, Poll};
use embedded_io_async::{Read, Write};

/// Async implementation of embedded_io_async::Read for UartController.
///
/// Reads bytes asynchronously from the UART receiver buffer.
/// Waits until data is available before reading each byte.
impl embedded_io_async::Read for UartController<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut count = 0;
        for byte in buf.iter_mut() {
            poll_fn(|cx| {
                if self.is_data_ready() {
                    *byte = self.read_rbr();
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await?;
            count += 1;
        }
        Ok(count)
    }
}

/// Async implementation of embedded_io_async::Write for UartController.
///
/// Writes bytes asynchronously to the UART transmit holding register.
/// Waits until the transmitter is ready before sending each byte.
impl embedded_io_async::Write for UartController<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        for &byte in buf {
            poll_fn(|cx| {
                if self.is_thr_empty() {
                    self.write_thr(byte);
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await?;
        }
        Ok(buf.len())
    }
}
