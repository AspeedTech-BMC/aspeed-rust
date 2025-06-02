use embedded_hal::delay::DelayNs;
use ast1060_pac::Scu;

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

            self.delay.delay_ns(1000000);

            // Release the hace reset
            self.scu.scu044().write(|w| w.bits(0x10));
        }
    }
}
