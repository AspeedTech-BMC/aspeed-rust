#![no_std]
#![no_main]

use ast1060_pac::Peripherals;
use aspeed_ddk::uart::{Config, UartController};

use panic_halt as _;

use cortex_m_rt::entry;
use embedded_hal::delay::DelayNs;

use embedded_io::Write;
pub struct DummyDelay;

impl DelayNs for DummyDelay {
    fn delay_ns(&mut self, _ns: u32) {
        for _ in 0..1000 {
            cortex_m::asm::nop();
        }
    }
}

#[entry]
fn main() -> ! {

    let _peripherals = unsafe { Peripherals::steal() };
    let uart = _peripherals.uart;
    let mut delay = DummyDelay {};

    let mut uart_controller = UartController::new(uart, &mut delay);
    unsafe {
        uart_controller.init(Config {
            baud_rate: 115200,
            word_length: 8,
            parity: aspeed_ddk::uart::Parity::None,
            stop_bits: aspeed_ddk::uart::StopBits::One,
            clock: 24_000_000,
        });
    }

    uart_controller.write_all(b"Hello, world!\n").unwrap();
    uart_controller.write_all(b"aspeed_ddk!\n").unwrap();

    // Initialize the peripherals here if needed
    loop {}
}

