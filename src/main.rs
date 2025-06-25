#![no_std]
#![no_main]

use core::sync::atomic::AtomicBool;
// use core::arch::asm;
use ast1060_pac::Peripherals;
use aspeed_ddk::uart::{Config, UartController};
use ast1060_pac::{Wdt, Wdt1};
use aspeed_ddk::watchdog::WdtController;

use fugit::MillisDurationU32 as MilliSeconds;
use aspeed_ddk::hash::Controller;
use aspeed_ddk::syscon::SysCon;
use aspeed_ddk::ecdsa::AspeedEcdsa;
use aspeed_ddk::rsa::AspeedRsa;

use aspeed_ddk::tests::functional::hash_test::run_hash_tests;
use aspeed_ddk::tests::functional::ecdsa_test::run_ecdsa_tests;
use aspeed_ddk::tests::functional::rsa_test::run_rsa_tests;
use panic_halt as _;

use cortex_m_rt::entry;
use embedded_hal::delay::DelayNs;

use embedded_io::Write;
use cortex_m_rt::pre_init;
use core::ptr::{read_volatile, write_volatile};




#[pre_init]
unsafe fn pre_init() {
    let jtag_pinmux_offset : u32 = 0x7e6e2000 + 0x41c;
    let mut reg : u32;
    reg = read_volatile(jtag_pinmux_offset as *const u32);
    reg |= 0x1f << 25;
    write_volatile(jtag_pinmux_offset as *mut u32, reg);

    // Disable Cache
    let cache_ctrl_offset: u32 = 0x7e6e2a58;
    write_volatile(cache_ctrl_offset as *mut u32, 0);

    // Configure Cache Area and Invalidation
    let cache_area_offset: u32 = 0x7e6e2a50;
    let cache_val = 0x000f_ffff;
    write_volatile(cache_area_offset as *mut u32, cache_val);

    let cache_inval_offset: u32 = 0x7e6e2a54;
    let cache_inval_val = 0x8660_0000;
    write_volatile(cache_inval_offset as *mut u32, cache_inval_val);

    // Enable Cache
    write_volatile(cache_ctrl_offset as *mut u32, 1);
}

#[derive(Clone, Default)]
struct DummyDelay;

impl DelayNs for DummyDelay {
    fn delay_ns(&mut self, _ns: u32) {
        for _ in 0.._ns {
            cortex_m::asm::nop();
        }
    }
}

fn test_wdt( uart:&mut UartController<'_>) {
    //instantiates the controller for the hardware watchdog Wdt and Wdt1
    let mut wdt0 = WdtController::<Wdt>::new();
    let mut wdt1 = WdtController::<Wdt1>::new();
    let mut delay = DummyDelay {};

    // Start watchdog with a timeout of 2000 milliseconds (2 seconds)
    uart.write_all(b"\r\nstart wdt\r\n").unwrap();
    wdt0.start(MilliSeconds::millis(5000));
    wdt1.start(MilliSeconds::millis(10000));
    let mut cnt = 0;

    loop {
        delay.delay_ns(2_000_000);
        uart.write_all(b"wdt feed\r\n").unwrap();
        wdt0.feed(); // petting to prevent reset
        wdt1.feed(); // petting to prevent reset
        cnt += 1;
        if cnt > 30 {
            wdt0.stop();
            wdt1.stop();
            uart.write_all(b"stop wdt\r\n").unwrap();
            break;
        }
    }
}

#[no_mangle]
pub static HALT: AtomicBool = AtomicBool::new(true);

#[macro_export]
macro_rules! debug_halt {
    () => {{
        use core::sync::atomic::{AtomicBool, Ordering};
        use core::arch::asm;

        static HALT: AtomicBool = AtomicBool::new(true);

        while HALT.load(Ordering::SeqCst) {
            unsafe {
                asm!("nop");
            }
        }
    }};
}

#[entry]
fn main() -> ! {

    let _peripherals = unsafe { Peripherals::steal() };
    let uart = _peripherals.uart;
    let mut delay = DummyDelay::default();

    // For jlink attach
    // set aspeed_ddk::__cortex_m_rt_main::HALT.v.value = 0 in gdb
    // debug_halt!();
    let mut uart_controller = UartController::new(uart, &mut delay);
    unsafe {
        uart_controller.init(Config {
            baud_rate: 115200,
            word_length: aspeed_ddk::uart::WordLength::Eight as u8,
            parity: aspeed_ddk::uart::Parity::None,
            stop_bits: aspeed_ddk::uart::StopBits::One,
            clock: 24_000_000,
        });
    }

    let hace = _peripherals.hace;
    let scu = _peripherals.scu;
    let secure = _peripherals.secure;

    writeln!(uart_controller, "\r\nHello, world!!\r\n").unwrap();


    // Enable HACE (Hash and Crypto Engine)
    let delay = DummyDelay::default();
    let mut syscon = SysCon::new(delay.clone(), scu);
    syscon.enable_hace();

    let mut hace_controller = Controller::new(hace);

    run_hash_tests(&mut uart_controller, &mut hace_controller);

    // Enable RSA and ECC
    syscon.enable_rsa_ecc();

    let mut ecdsa = AspeedEcdsa::new(&secure, delay.clone());
    run_ecdsa_tests(&mut uart_controller, &mut ecdsa);

    let mut rsa = AspeedRsa::new(&secure, delay);
    run_rsa_tests(&mut uart_controller, &mut rsa);

    test_wdt(&mut uart_controller);
    // Initialize the peripherals here if needed
    loop {}
}

