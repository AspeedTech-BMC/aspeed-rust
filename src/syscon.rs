// Licensed under the Apache-2.0 license

use ast1060_pac::Scu;
use embedded_hal::delay::DelayNs;

pub struct SysCon<D: DelayNs> {
    delay: D,
    scu: Scu,
}

impl<D: DelayNs> SysCon<D> {
    pub fn new(delay: D, scu: Scu) -> Self {
        Self { delay, scu }
    }

    pub fn enable_hace(&mut self) {
        unsafe {
            self.scu
                .scu084()
                .write(|w| w.scu080clk_stop_ctrl_clear_reg().bits(1 << 13));

            self.delay.delay_ns(1_000_000);

            // Release the hace reset
            self.scu.scu044().write(|w| w.bits(0x10));
        }
    }
    pub fn enable_rsa_ecc(&mut self) {
        unsafe {
            // Enable RSA/ECC clock
            self.scu
                .scu094()
                .write(|w| w.scu090clk_stop_ctrl_clear_reg_set2().bits(1 << 6));
        }
    }
}
