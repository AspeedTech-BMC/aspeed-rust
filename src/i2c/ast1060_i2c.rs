use crate::common::{DmaBuffer, DummyDelay};
use crate::i2c::common::{I2cConfig, I2cSEvent, I2cXferMode};
use crate::i2c::i2c::HardwareInterface;
use crate::uart::UartController;
use ast1060_pac::{I2cglobal, Scu};
use core::cmp::min;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
use embedded_hal::delay::DelayNs;
use embedded_hal::i2c::{NoAcknowledgeSource, Operation, SevenBitAddress};
use embedded_io::Write;
use proposed_traits::i2c_target::I2CTarget;

static I2CGLOBAL_INIT: AtomicBool = AtomicBool::new(false);

pub trait Instance {
    fn ptr() -> *const ast1060_pac::i2c::RegisterBlock;
    fn buff_ptr() -> *const ast1060_pac::i2cbuff::RegisterBlock;
    const BUS_NUM: u8;
}

macro_rules! macro_i2c {
    ($I2cx: ident, $I2cbuffx: ident, $x: literal) => {
        impl Instance for ast1060_pac::$I2cx {
            fn ptr() -> *const ast1060_pac::i2c::RegisterBlock {
                ast1060_pac::$I2cx::ptr()
            }
            fn buff_ptr() -> *const ast1060_pac::i2cbuff::RegisterBlock {
                ast1060_pac::$I2cbuffx::ptr()
            }
            const BUS_NUM: u8 = $x;
        }
    };
}
macro_i2c!(I2c, I2cbuff, 0);
macro_i2c!(I2c1, I2cbuff1, 1);
macro_i2c!(I2c2, I2cbuff2, 2);
macro_i2c!(I2c3, I2cbuff3, 3);
macro_i2c!(I2c4, I2cbuff4, 4);
macro_i2c!(I2c5, I2cbuff5, 5);
macro_i2c!(I2c6, I2cbuff6, 6);
macro_i2c!(I2c7, I2cbuff7, 7);
macro_i2c!(I2c8, I2cbuff8, 8);
macro_i2c!(I2c9, I2cbuff9, 9);
macro_i2c!(I2c10, I2cbuff10, 10);
macro_i2c!(I2c11, I2cbuff11, 11);
macro_i2c!(I2c12, I2cbuff12, 12);
macro_i2c!(I2c13, I2cbuff13, 13);

const HPLL_FREQ: u32 = 1_000_000_000;

const AST_I2CC_SLAVE_EN: u32 = 1 << 1;

const AST_I2CM_PKT_EN: u32 = 1 << 16;
const AST_I2CM_SDA_OE_OUT_DIR: u32 = 1 << 15;
const AST_I2CM_SDA_O_OUT_DIR: u32 = 1 << 14;
const AST_I2CM_SCL_OE_OUT_DIR: u32 = 1 << 13;
const AST_I2CM_SCL_O_OUT_DIR: u32 = 1 << 12;
const AST_I2CM_RECOVER_CMD_EN: u32 = 1 << 11;

const AST_I2CM_RX_DMA_EN: u32 = 1 << 9;
const AST_I2CM_TX_DMA_EN: u32 = 1 << 8;

// Command Bit
const AST_I2CM_RX_BUFF_EN: u32 = 1 << 7;
const AST_I2CM_TX_BUFF_EN: u32 = 1 << 6;
const AST_I2CM_STOP_CMD: u32 = 1 << 5;
const AST_I2CM_RX_CMD_LAST: u32 = 1 << 4;
const AST_I2CM_RX_CMD: u32 = 1 << 3;
const AST_I2CM_TX_CMD: u32 = 1 << 1;
const AST_I2CM_START_CMD: u32 = 1 << 0;
//status bit
const AST_I2CM_SCL_LOW_TO: u32 = 1 << 6;
const AST_I2CM_ABNORMAL: u32 = 1 << 5;
const AST_I2CM_NORMAL_STOP: u32 = 1 << 4;
const AST_I2CM_ARBIT_LOSS: u32 = 1 << 3;
const AST_I2CM_RX_DONE: u32 = 1 << 2;
const AST_I2CM_TX_NAK: u32 = 1 << 1;
const AST_I2CM_TX_ACK: u32 = 1 << 0;

fn ast_i2cm_pkt_addr(x: u8) -> u32 {
    ((x & 0x7F) as u32) << 24
}

//0x08 : I2CC Master/Slave Transmit/Receive Byte Buffer Register
const AST_I2CC_STS_AND_BUFF: u32 = 0x08;
const AST_I2CC_TX_DIR_MASK: u32 = 0x7 << 29;
const AST_I2CC_SDA_OE: u32 = 1 << 28;
const AST_I2CC_SDA_O: u32 = 1 << 27;
const AST_I2CC_SCL_OE: u32 = 1 << 26;
const AST_I2CC_SCL_O: u32 = 1 << 25;

// 0x28 : I2CS Slave CMD/Status Register
const AST_I2CS_CMD_STS: u32 = 0x28;
const AST_I2CS_ACTIVE_ALL: u32 = 0x3 << 17;
const AST_I2CS_PKT_MODE_EN: u32 = 1 << 16;
const AST_I2CS_AUTO_NAK_NOADDR: u32 = 1 << 15;
const AST_I2CS_AUTO_NAK_EN: u32 = 1 << 14;
const AST_I2CM_PKT_TIMEOUT: u32 = 1 << 18;
const AST_I2CM_PKT_ERROR: u32 = 1 << 17;
const AST_I2CM_PKT_DONE: u32 = 1 << 16;
const AST_I2CM_BUS_RECOVER_FAIL: u32 = 1 << 15;
const AST_I2CM_SDA_DL_TO: u32 = 1 << 14;
const AST_I2CM_BUS_RECOVER: u32 = 1 << 13;
const AST_I2CM_SMBUS_ALT: u32 = 1 << 12;

const ASPEED_I2C_DMA_SIZE: usize = 4096;
const SLAVE_TRIGGER_CMD: u32 = AST_I2CS_ACTIVE_ALL | AST_I2CS_PKT_MODE_EN;
const I2C_SLAVE_BUF_SIZE: usize = 256;

const I2C_BUF_SIZE: u8 = 0x20;

//slave
const AST_I2CS_ALT_EN: u32 = 1 << 10;
const AST_I2CS_RX_DMA_EN: u32 = 1 << 9;
const AST_I2CS_TX_DMA_EN: u32 = 1 << 8;
const AST_I2CS_RX_BUFF_EN: u32 = 1 << 7;
const AST_I2CS_TX_BUFF_EN: u32 = 1 << 6;
const AST_I2CS_RX_CMD_LAST: u32 = 1 << 4;

const AST_I2CS_SLAVE_PENDING: u32 = 1 << 29;
const AST_I2CS_WAIT_TX_DMA: u32 = 1 << 25;
const AST_I2CS_WAIT_RX_DMA: u32 = 1 << 24;

const AST_I2CS_ADDR_INDICATE_MASK: u32 = 3 << 30;
const AST_I2CS_ADDR3_NAK: u32 = 1 << 22;
const AST_I2CS_ADDR2_NAK: u32 = 1 << 21;
const AST_I2CS_ADDR1_NAK: u32 = 1 << 20;

const AST_I2CS_ADDR_MASK: u32 = 3 << 18;
const AST_I2CS_PKT_ERROR: u32 = 1 << 17;
const AST_I2CS_PKT_DONE: u32 = 1 << 16;
const AST_I2CS_INACTIVE_TO: u32 = 1 << 15;
const AST_I2CS_SLAVE_MATCH: u32 = 1 << 7;
const AST_I2CS_ABNOR_STOP: u32 = 1 << 5;
const AST_I2CS_STOP: u32 = 1 << 4;
const AST_I2CS_RX_DONE_NAK: u32 = 1 << 3;
const AST_I2CS_RX_DONE: u32 = 1 << 2;
const AST_I2CS_TX_NAK: u32 = 1 << 1;
const AST_I2CS_TX_ACK: u32 = 1 << 0;

const AST_I2CS_TX_CMD: u32 = 1 << 2;

const AST_I2CC_AC_TIMING_MASK: u32 = 0x00ff_ffff;
const I2C_TIMEOUT_COUNT: u8 = 0x8; //~35ms

//message flag
//Write message to I2C bus.
const I2C_MSG_WRITE: u8 = 0;
//Read message from I2C bus. */
const I2C_MSG_READ: u8 = 1 << 0;
//Send STOP after this message. */
const I2C_MSG_STOP: u8 = 1 << 1;
//RESTART I2C transaction for this message.
const I2C_MSG_RESTART: u8 = 1 << 2;

const AST2600_I2CM_ISR_MASK: u32 = 0xFFE00000;

pub struct I2cMsg<'a> {
    pub buf: &'a mut [u8],
    pub flags: u8,
    pub length: u32,
}

impl<'a> I2cMsg<'a> {
    pub fn len(&mut self) -> u32 {
        self.buf.len() as u32
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[non_exhaustive]
pub enum Error {
    Overrun,
    NoAcknowledge(NoAcknowledgeSource),
    Timeout,
    BusRecoveryFailed,
    Bus,
    Busy,
    Invalid,
    Proto,
    Abnormal,
    ArbitrationLoss,
}

impl Error {
    pub(crate) fn nack_addr(self) -> Self {
        match self {
            Error::NoAcknowledge(NoAcknowledgeSource::Unknown) => {
                Error::NoAcknowledge(NoAcknowledgeSource::Address)
            }
            e => e,
        }
    }
    pub(crate) fn nack_data(self) -> Self {
        match self {
            Error::NoAcknowledge(NoAcknowledgeSource::Unknown) => {
                Error::NoAcknowledge(NoAcknowledgeSource::Data)
            }
            e => e,
        }
    }
}

use embedded_hal::i2c::ErrorKind;
impl embedded_hal::i2c::Error for Error {
    fn kind(&self) -> ErrorKind {
        match *self {
            Self::Overrun => ErrorKind::Overrun,
            Self::Bus => ErrorKind::Bus,
            Self::ArbitrationLoss => ErrorKind::ArbitrationLoss,
            Self::NoAcknowledge(nack) => ErrorKind::NoAcknowledge(nack),
            Self::Invalid | Self::Timeout | Self::Proto | Self::Abnormal | Self::Busy | Self::BusRecoveryFailed => ErrorKind::Other,
        }
    }
}


const I2C_TOTAL: usize = 4;
#[link_section = ".ram_nc"]
static mut MDMA_BUFFER: [DmaBuffer<ASPEED_I2C_DMA_SIZE>; I2C_TOTAL] = [
    DmaBuffer::new(),
    DmaBuffer::new(),
    DmaBuffer::new(),
    DmaBuffer::new(),
];
#[link_section = ".ram_nc"]
static mut SDMA_BUFFER: [DmaBuffer<I2C_SLAVE_BUF_SIZE>; I2C_TOTAL] = [
    DmaBuffer::new(),
    DmaBuffer::new(),
    DmaBuffer::new(),
    DmaBuffer::new(),
];

static mut I2C_BUF: [[u8; I2C_SLAVE_BUF_SIZE]; 4] = [[0; 256]; I2C_TOTAL];

pub struct I2cData<'a, I2CT: I2CTarget> {
    pub msg: I2cMsg<'a>,
    pub addr: u8,
    pub stop: bool,
    pub alert_enable: bool,
    pub bus_recover: u8,
    pub completion: bool,
    pub master_xfer_cnt: u32,
    pub slave_attached: bool,
    pub slave_operate: u8,
    pub slave_addr_last: u8,
    pub slave_target_addr: u8,
    pub slave_target: Option<&'a mut I2CT>,
}

impl<'a, I2CT: I2CTarget> I2cData<'a, I2CT> {
    pub fn new(buf_idx: usize) -> Self {
        assert!(buf_idx < I2C_TOTAL); // Prevent out-of-bounds access
        unsafe {
            let buf_ref: &'a mut [u8] = &mut I2C_BUF[buf_idx];
            Self {
                msg: I2cMsg {
                    buf: buf_ref,
                    flags: 0,
                    length: 0,
                },
                addr: 0,
                stop: false,
                alert_enable: false,
                bus_recover: 0,
                completion: false,
                master_xfer_cnt: 0,
                slave_attached: false,
                slave_operate: 0,
                slave_addr_last: 0,
                slave_target_addr: 0,
                slave_target: None,
            }
        }
    }
    pub fn set_target(&mut self, addr: u8, target: Option<&'a mut I2CT>) {
        self.slave_target_addr = addr;
        self.slave_target = target;
    }
}

/*impl<I2C: Instance, I2CT: I2CTarget> embedded_hal::i2c::ErrorType for Ast1060I2c<'_, I2C, I2CT> {
    type Error = Error;
}*/
/// I2C abstraction
pub struct Ast1060I2c<'a, I2C: Instance, I2CT: I2CTarget> {
    pub i2c: &'static ast1060_pac::i2c::RegisterBlock,
    pub i2c_buff: &'static ast1060_pac::i2cbuff::RegisterBlock,
    pub xfer_mode: I2cXferMode,
    pub multi_master: bool,
    pub mdma_buf: &'a mut DmaBuffer<ASPEED_I2C_DMA_SIZE>,
    pub sdma_buf: &'a mut DmaBuffer<I2C_SLAVE_BUF_SIZE>,
    pub i2c_data: I2cData<'a, I2CT>,
    _marker: PhantomData<I2C>,
    pub dbg_uart: Option<&'a mut UartController<'a>>,
}
impl<I2C: Instance, I2CT: I2CTarget> Drop for Ast1060I2c<'_, I2C, I2CT> {
    fn drop(&mut self) {
        // Disable i2c controller
        self.i2c.i2cc00().write(|w| unsafe {w.bits(0)});
        // Disable interrupt and clear interrupt status
        self.enable_interrupts(0);
        self.clear_interrupts(0xffff_ffff);
        #[cfg(feature = "i2c_target")]
        self.enable_slave_interrupts(0);
        #[cfg(feature = "i2c_target")]
        self.clear_slave_interrupts(0xffff_ffff);
    }
}
macro_rules! dbg {
    ($self:expr, $($arg:tt)*) => {
        if let Some(ref mut uart) = $self.dbg_uart {
            writeln!(uart, $($arg)*).unwrap();
            write!(uart, "\r").unwrap();
        }
    };
}

impl<'a, I2C: Instance, I2CT: I2CTarget> HardwareInterface for Ast1060I2c<'a, I2C, I2CT> {
    type Error = Error;

    fn init(&mut self, mut config: &mut I2cConfig) {
        dbg!(self, "i2c init");
        dbg!(
            self,
            "mdma_buf {:p}, sdma_buf {:p}",
            self.mdma_buf.as_ptr(),
            self.sdma_buf.as_ptr()
        );
        let scu = unsafe { &*Scu::ptr() };
        // global init
        if I2CGLOBAL_INIT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            dbg!(self, "i2c global init");
            scu.scu050().write(|w| w.rst_i2csmbus_ctrl().set_bit());
            let mut delay = DummyDelay {};
            delay.delay_ns(1_000_000); // 1ms delay
            scu.scu054().write(|w| unsafe { w.bits(0x4) });
            delay.delay_ns(1_000_000); // 1ms delay

            let i2cg = unsafe { &*I2cglobal::ptr() };
            i2cg.i2cg0c().write(|w| {
                w.clk_divider_mode_sel()
                    .set_bit()
                    .reg_definition_sel()
                    .set_bit()
                    .select_the_action_when_slave_pkt_mode_rxbuf_empty()
                    .set_bit()
            });
            /*
             * APB clk : 50Mhz
             * div  : scl       : baseclk [APB/((div/2) + 1)] : tBuf [1/bclk * 16]
             * I2CG10[31:24] base clk4 for i2c auto recovery timeout counter (0x62)
             * I2CG10[23:16] base clk3 for Standard-mode (100Khz) min tBuf 4.7us
             * 0x1d : 100.8Khz  : 3.225Mhz                    : 4.96us
             * 0x1e : 97.66Khz  : 3.125Mhz                    : 5.12us
             * 0x1f : 97.85Khz  : 3.03Mhz                     : 5.28us
             * 0x20 : 98.04Khz  : 2.94Mhz                     : 5.44us
             * 0x21 : 98.61Khz  : 2.857Mhz                    : 5.6us
             * 0x22 : 99.21Khz  : 2.77Mhz                     : 5.76us (default)
             * I2CG10[15:8] base clk2 for Fast-mode (400Khz) min tBuf 1.3us
             * 0x08 : 400Khz    : 10Mhz                       : 1.6us
             * I2CG10[7:0] base clk1 for Fast-mode Plus (1Mhz) min tBuf 0.5us
             * 0x03 : 1Mhz      : 20Mhz                       : 0.8us
             */
            i2cg.i2cg10().write(|w| unsafe { w.bits(0x62220803) });
        }

        // i2c reset
        self.i2c.i2cc00().write(|w| unsafe { w.bits(0) });
        if !config.multi_master {
            self.i2c
                .i2cc00()
                .write(|w| w.dis_multimaster_capability_for_master_fn_only().set_bit());
        }
        self.i2c.i2cc00().write(|w| {
            w.enbl_bus_autorelease_when_scllow_sdalow_or_slave_mode_inactive_timeout()
                .set_bit()
                .enbl_master_fn()
                .set_bit()
        });
        
        // set AC timing
        self.configure_timing(&mut config);
        // clear interrupts
        self.i2c.i2cm14().write(|w| unsafe { w.bits(0xffffffff) });
        // set interrupt
        self.i2c.i2cm10().write(|w| {
            w.enbl_pkt_cmd_done_int()
                .set_bit()
                .enbl_bus_recover_done_int()
                .set_bit()
        });
        dbg!(
            self,
            "i2c init after set interrupt: {:#x}",
            self.i2c.i2cm14().read().bits()
        );
        if config.smbus_alert {
            self.i2c
                .i2cm10()
                .write(|w| w.enbl_smbus_dev_alert_int().set_bit());
        }
        self.xfer_mode = config.xfer_mode;
        self.multi_master = config.multi_master;
        if cfg!(feature = "i2c_target") {
            dbg!(self, "i2c target enabled");
            // clear slave interrupts
            self.i2c.i2cs24().write(|w| unsafe { w.bits(0xffffffff) });
            if self.xfer_mode == I2cXferMode::ByteMode {
                self.i2c.i2cs20().write(|w| unsafe { w.bits(0xffff) });
            } else {
                self.i2c.i2cs20().write(|w| {
                    w.enbl_slave_mode_inactive_timeout_int()
                        .set_bit()
                        .enbl_pkt_cmd_done_int()
                        .set_bit()
                });
            }
        }
    }
    fn configure_timing(&mut self, config: &mut I2cConfig) {
        let scu = unsafe { &*Scu::ptr() };
        config.timing_config.clk_src =
            HPLL_FREQ / ((scu.scu310().read().apbbus_pclkdivider_sel().bits() as u32 + 1) * 2);
        
        let p = unsafe { &*I2cglobal::ptr() };
        let mut div: u32;
        let mut divider_ratio: u32;

        if p.i2cg0c().read().clk_divider_mode_sel().bit_is_set() {
            let base_clk = config.timing_config.clk_src;
            let base_clk1 = (config.timing_config.clk_src * 10)
                / ((p.i2cg10().read().base_clk1divisor_basedivider1().bits() as u32 + 2) * 10 / 2);
            let base_clk2 = (config.timing_config.clk_src * 10)
                / ((p.i2cg10().read().base_clk2divisor_basedivider2().bits() as u32 + 2) * 10 / 2);
            let base_clk3 = (config.timing_config.clk_src * 10)
                / ((p.i2cg10().read().base_clk3divisor_basedivider3().bits() as u32 + 2) * 10 / 2);
            let base_clk4 = (config.timing_config.clk_src * 10)
                / ((p.i2cg10().read().base_clk4divisor_basedivider4().bits() as u32 + 2) * 10 / 2);

            // rounding
            if config.timing_config.clk_src / (config.speed as u32) <= 32 {
                div = 0;
                divider_ratio = base_clk / config.speed as u32;
                if base_clk / divider_ratio > config.speed as u32 {
                    divider_ratio += 1;
                }
            } else if base_clk1 / (config.speed as u32) <= 32 {
                div = 1;
                divider_ratio = base_clk1 / config.speed as u32;
                if base_clk1 / divider_ratio > config.speed as u32 {
                    divider_ratio += 1;
                }
            } else if base_clk2 / (config.speed as u32) <= 32 {
                div = 2;
                divider_ratio = base_clk2 / config.speed as u32;
                if base_clk2 / divider_ratio > config.speed as u32 {
                    divider_ratio += 1;
                }
            } else if base_clk3 / (config.speed as u32) <= 32 {
                div = 3;
                divider_ratio = base_clk3 / config.speed as u32;
                if base_clk3 / divider_ratio > config.speed as u32 {
                    divider_ratio += 1;
                }
            } else {
                div = 4;
                divider_ratio = base_clk4 / config.speed as u32;
                let mut inc = 0;
                while divider_ratio + inc > 32 {
                    inc |= divider_ratio & 1u32;
                    divider_ratio >>= 1;
                    div += 1;
                }
                divider_ratio += inc;
                if base_clk4 / divider_ratio > config.speed as u32 {
                    divider_ratio += 1;
                }
                divider_ratio = min(divider_ratio, 32);
                div &= 0xf;
            }

            let mut scl_low: u8;
            let mut scl_high: u8;
            if (config.timing_config.manual_scl_low & config.timing_config.manual_scl_high) != 0 {
                scl_low = config.timing_config.manual_scl_low;
                scl_high = config.timing_config.manual_scl_high;
            } else if (config.timing_config.manual_scl_low | config.timing_config.manual_scl_high) != 0 {
                if config.timing_config.manual_scl_low != 0 {
                    scl_low = config.timing_config.manual_scl_low;
                    scl_high = divider_ratio as u8 - scl_low - 2;
                } else {
                    scl_high = config.timing_config.manual_scl_high;
                    scl_low = divider_ratio as u8 - scl_high - 2;
                }
            } else {
                scl_low = (divider_ratio * 9 / 16 - 1) as u8;
                scl_high = divider_ratio as u8 - scl_low - 2;
            }
            scl_low = min(scl_low, 0xf);
            scl_high = min(scl_high, 0xf);

            /*Divisor : Base Clock : tCKHighMin : tCK High : tCK Low*/
            self.i2c
                .i2cc04()
                .write(|w| unsafe { w.base_clk_divisor_tbase_clk().bits(div as u8) });
            self.i2c.i2cc04().write(|w| unsafe {
                w.cycles_of_master_sclclklow_pulse_width_tcklow()
                    .bits(scl_low)
            });
            self.i2c.i2cc04().write(|w| unsafe {
                w.cycles_of_master_sclclkhigh_pulse_width_tckhigh()
                    .bits(scl_high)
            });
            self.i2c.i2cc04().write(|w| unsafe {
                w.cycles_of_master_sclclkhigh_minimum_pulse_width_tckhigh_min()
                    .bits(scl_high - 1)
            });

            if config.smbus_timeout {
                self.i2c.i2cc04().write(|w| unsafe {
                    w.timeout_base_clk_divisor_tout_base_clk()
                        .bits(2)
                        .timeout_timer()
                        .bits(8)
                });
            }
            if config.timing_config.manual_sda_hold < 4 {
                self.i2c.i2cc04().write(|w| unsafe {
                    w.hold_time_of_masterslave_data_thddat()
                        .bits(config.timing_config.manual_sda_hold)
                });
            }
        }
    }
    fn enable_interrupts(&mut self, mask: u32) {
        self.i2c.i2cm10().write(|w| unsafe { w.bits(mask) });
    }
    fn clear_interrupts(&mut self, mask: u32) {
        self.i2c.i2cm14().write(|w| unsafe { w.bits(mask) });
    }
    #[cfg(feature = "i2c_target")]
    fn enable_slave_interrupts(&mut self, mask: u32) {
        self.i2c.i2cs20().write(|w| unsafe { w.bits(mask) });
    }
    #[cfg(feature = "i2c_target")]
    fn clear_slave_interrupts(&mut self, mask: u32) {
        self.i2c.i2cs24().write(|w| unsafe { w.bits(mask) });
    }
    fn handle_interrupt(&mut self) {
        //check slave mode first
        if self.i2c.i2cc00().read().enbl_slave_fn().bit() {
            if self.aspeed_i2c_slave_irq() != 0 {
                return;
            }
        }
        self.aspeed_i2c_master_irq();
    }

    fn write(&mut self, addr: SevenBitAddress, bytes: &[u8]) -> Result<(), Error> {
        self.prepare_write(addr, &bytes, true);
        self.i2c_aspeed_transfer()
    }
    fn read(&mut self, addr: SevenBitAddress, buffer: &mut [u8]) -> Result<(), Error> {
        self.prepare_read(addr, buffer.len() as u32);
        match self.i2c_aspeed_transfer() {
            Ok(_) => {
                self.read_processed(buffer);
                return Ok(());
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
    fn write_read(
        &mut self,
        addr: SevenBitAddress,
        bytes: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        self.prepare_write(addr, &bytes, false);

        match self.i2c_aspeed_transfer() {
            Err(e) => {
                return Err(e);
            },
            _ => {},
        }
        //read
        self.prepare_read(addr, buffer.len() as u32);
        match self.i2c_aspeed_transfer() {
            Ok(_) => {
                self.read_processed(buffer);
                return Ok(());
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
}

impl<'a, I2C: Instance, I2CT: I2CTarget> Ast1060I2c<'a, I2C, I2CT> {
    pub fn new(uart: Option<&'a mut UartController<'a>>) -> Self {
        let i2c = unsafe { &*I2C::ptr() };
        let i2c_buff = unsafe { &*I2C::buff_ptr() };
        let index: usize = I2C::BUS_NUM as usize;
        let mdma_buf: &'a mut DmaBuffer<ASPEED_I2C_DMA_SIZE> = unsafe { &mut MDMA_BUFFER[index] };
        let sdma_buf: &'a mut DmaBuffer<I2C_SLAVE_BUF_SIZE> = unsafe { &mut SDMA_BUFFER[index] };
        let i2c_data = I2cData::new(index);
        Self {
            i2c: i2c,
            i2c_buff: i2c_buff,
            xfer_mode: I2cXferMode::ByteMode,
            multi_master: false,
            mdma_buf: mdma_buf,
            sdma_buf: sdma_buf,
            i2c_data: i2c_data,
            _marker: PhantomData,
            dbg_uart: uart,
        }
    }
    pub fn dump_regs(&mut self) {
        let i2cg = unsafe { &*I2cglobal::ptr() };
        dbg!(self, "******* i2c registers ******");
        dbg!(self, "i2cg00 {:#x}", i2cg.i2cg00().read().bits());
        dbg!(self, "i2cg04 {:#x}", i2cg.i2cg04().read().bits());
        dbg!(self, "i2cg0c {:#x}", i2cg.i2cg0c().read().bits());
        dbg!(self, "i2cg10 {:#x}", i2cg.i2cg10().read().bits());

        dbg!(self, "i2cc00 {:#x}", self.i2c.i2cc00().read().bits());
        dbg!(self, "i2cc04 {:#x}", self.i2c.i2cc04().read().bits());
        dbg!(self, "i2cc08 {:#x}", self.i2c.i2cc08().read().bits());
        dbg!(self, "i2cc0c {:#x}", self.i2c.i2cc0c().read().bits());

        dbg!(self, "i2cm10 {:#x}", self.i2c.i2cm10().read().bits());
        dbg!(self, "i2cm14 {:#x}", self.i2c.i2cm14().read().bits());
        dbg!(self, "i2cm18 {:#x}", self.i2c.i2cm18().read().bits());
        dbg!(self, "i2cm1c {:#x}", self.i2c.i2cm1c().read().bits());

        dbg!(self, "i2cs20 {:#x}", self.i2c.i2cs20().read().bits());
        dbg!(self, "i2cs24 {:#x}", self.i2c.i2cs24().read().bits());
        dbg!(self, "i2cs28 {:#x}", self.i2c.i2cs28().read().bits());
        dbg!(self, "i2cs2c {:#x}", self.i2c.i2cs2c().read().bits());

        dbg!(self, "i2cm30 {:#x}", self.i2c.i2cm30().read().bits());
        dbg!(self, "i2cm34 {:#x}", self.i2c.i2cm34().read().bits());

        dbg!(self, "i2cs38 {:#x}", self.i2c.i2cs38().read().bits());
        dbg!(self, "i2cs3c {:#x}", self.i2c.i2cs3c().read().bits());

        dbg!(self, "i2cs40 {:#x}", self.i2c.i2cs40().read().bits());
        dbg!(self, "i2cm48 {:#x}", self.i2c.i2cm48().read().bits());
        dbg!(self, "i2cs4c {:#x}", self.i2c.i2cs4c().read().bits());
        dbg!(self, "i2cc50 {:#x}", self.i2c.i2cc50().read().bits());
        dbg!(self, "i2cc54 {:#x}", self.i2c.i2cc54().read().bits());
        dbg!(self, "**************************");
    }

    pub fn aspeed_i2c_is_irq_error(&mut self, irq_status: u32) -> Result<(), Error> {
        if irq_status & AST_I2CM_ARBIT_LOSS > 0 {
            return Err(Error::ArbitrationLoss);
        }
        if irq_status & (AST_I2CM_SDA_DL_TO | AST_I2CM_SCL_LOW_TO) > 0 {
            return Err(Error::Busy);
        }
        if irq_status & (AST_I2CM_ABNORMAL) > 0 {
            return Err(Error::Abnormal);
        }
        Ok(())
    }
    //Check if current message is completed
    //If not, continue TX
    //No start
    pub fn do_i2cm_tx(&mut self) {
        let mut cmd = AST_I2CM_PKT_EN;
        let xfer_len: u16;

        let msg_len = self.i2c_data.msg.length;
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                xfer_len = self.i2c.i2cm48().read().dmatx_actual_len_byte().bits() as u16;
            }
            I2cXferMode::BuffMode => {
                xfer_len = self.i2c.i2cc0c().read().tx_data_byte_count().bits() as u16;
            }
            I2cXferMode::ByteMode => {
                xfer_len = 1;
            }
        }
        dbg!(self, "do_i2cm_tx:: len {:#x}", xfer_len);
        self.i2c_data.master_xfer_cnt += xfer_len as u32;
        if self.i2c_data.master_xfer_cnt == msg_len {
            self.i2c_data.completion = true;
        } else {
            // continue current message
            cmd |= AST_I2CM_TX_CMD;
            self.aspeed_i2c_write(cmd);
        }
    }
    //move data from i2c mapped buff to message buffer
    pub fn copy_from_buff(&mut self, xfer_len: u16) {
        let count_dword = (xfer_len >> 2) as usize;
        let count_byte = (xfer_len & 0b11) as usize;
        let mut buf_index = self.i2c_data.master_xfer_cnt as usize;
        let mut data: u32 = 0;
        for i in 0..count_dword {
            data = self.i2c_buff.buff(i).read().bits();
            let bytes = data.to_le_bytes(); // ensures little-endian order
            for b in 0..4 {
                self.i2c_data.msg.buf[buf_index] = bytes[b];
                buf_index += 1;
            }
        }

        if count_byte > 0 {
            data = self.i2c_buff.buff(count_dword).read().bits();
            let bytes = data.to_le_bytes();
            for b in 0..count_byte {
                self.i2c_data.msg.buf[buf_index] = bytes[b];
                buf_index += 1;
            }
        }
    }
    pub fn copy_to_buff(&mut self, xfer_len: u16) {
        let mut buf_index = self.i2c_data.master_xfer_cnt as usize;
        let count_dword = (xfer_len >> 2) as usize;
        let count_byte = (xfer_len & 0b11) as usize;

        for i in 0..count_dword {
            let bytes: [u8; 4] = self.i2c_data.msg.buf[buf_index..buf_index + 4]
                .try_into()
                .expect("Not enough bytes for full DWORD");

            let data = u32::from_le_bytes(bytes); // assumes little-endian format
            self.i2c_buff.buff(i).write(|w| unsafe { w.bits(data) });

            buf_index += 4;
        }
        if count_byte > 0 {
            let mut data: u32 = 0;
            for i in 0..count_byte {
                data |= (self.i2c_data.msg.buf[buf_index + i] as u32) << (i * 8);
            }
            self.i2c_buff
                .buff(count_dword)
                .write(|w| unsafe { w.bits(data) });
        }
    }

    //Check if current message is completed
    //If not, continue RX
    pub fn do_i2cm_rx(&mut self) {
        let mut cmd = AST_I2CM_PKT_EN;
        let xfer_len: u16;
        let msg_len = self.i2c_data.msg.length;
        dbg!(self, "do_i2cm_rx");
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                xfer_len = self.i2c.i2cm48().read().dmarx_actual_len_byte().bits();
                dbg!(self, "dma data: {:#x}", unsafe { *self.mdma_buf.as_ptr() });
            }
            I2cXferMode::BuffMode => {
                xfer_len = self
                    .i2c
                    .i2cc0c()
                    .read()
                    .actual_rxd_pool_buffer_size()
                    .bits() as u16;
                //put data in msg buf
                self.copy_from_buff(xfer_len);
            }
            I2cXferMode::ByteMode => {
                xfer_len = 1;
                self.i2c_data.msg.buf[self.i2c_data.master_xfer_cnt as usize] =
                    self.i2c.i2cc08().read().rx_byte_buffer().bits();
            }
        }
        dbg!(self, "xfer_len {:#x}, msg_len {:#x}", xfer_len, msg_len);
        self.i2c_data.master_xfer_cnt += xfer_len as u32;
        if self.i2c_data.master_xfer_cnt == msg_len {
            self.i2c_data.completion = true;
        } else {
            // continue current message
            cmd |= AST_I2CM_RX_CMD;
            self.aspeed_i2c_read(cmd);
        }
    }

    pub fn aspeed_i2c_master_package_irq(&mut self, sts: u32) -> Result<(), Error> {
        dbg!(self, "aspeed_i2c_master_package_irq sts={:#x}", sts);
        if sts == AST_I2CM_PKT_ERROR | AST_I2CM_TX_NAK
            || sts == AST_I2CM_PKT_ERROR | AST_I2CM_TX_NAK | AST_I2CM_NORMAL_STOP
        {
            dbg!(self, "M: PKT ERR | TX NAK (STOP)");
            self.i2c_data.completion = true;
            return Err(Error::NoAcknowledge(NoAcknowledgeSource::Unknown));
        } else if sts == AST_I2CM_NORMAL_STOP {
            dbg!(self, "M: STOP");
            self.i2c_data.completion = true;
        } else if sts == AST_I2CM_TX_ACK || sts == AST_I2CM_TX_ACK | AST_I2CM_NORMAL_STOP {
            dbg!(self, "M: TX_ACK (STOP)");
            //slave mode
            if cfg!(feature = "i2c_target") {
                //Workaround for master/slave package mode
                //enable rx done stuck issue
                //When master go for first read (RX_DONE),
                //slave mode will also effect
                //Then controller will send nack,not operate anymore.
                if sts == AST_I2CM_TX_ACK {
                    if self.i2c.i2cs28().read().enbl_slave_pkt_op_mode().bit() {
                        let slave_cmd = self.i2c.i2cs28().read().bits();
                        self.i2c.i2cs28().write(|w| unsafe { w.bits(0) });
                        self.i2c.i2cs28().write(|w| unsafe { w.bits(slave_cmd) });
                    }
                }
            }
            self.do_i2cm_tx();
        } else if sts == AST_I2CM_RX_DONE || sts == AST_I2CM_RX_DONE | AST_I2CM_NORMAL_STOP {
            dbg!(self, "M: RX_DONE (STOP)");
            self.do_i2cm_rx();
        } else {
            dbg!(
                self,
                "aspeed_i2c_master_package_irq, not handled sts={:#x}",
                sts
            );
        }
        Ok(())
    }

    pub fn aspeed_i2c_master_irq(&mut self) -> Result<(), Error> {
        let mut sts = self.i2c.i2cm14().read().bits();
        //dbg!(self, "aspeed_i2c_master_irq: sts={:#x}",sts);
        if self.i2c_data.alert_enable {
            sts &= !AST_I2CM_SMBUS_ALT;
        }
        if AST_I2CM_BUS_RECOVER_FAIL == AST_I2CM_BUS_RECOVER_FAIL & sts {
            self.i2c.i2cm14().write(|w| unsafe { w.bits(sts) });
            if self.i2c_data.bus_recover > 0 {
                self.i2c_data.bus_recover = 0;
            }
            return Err(Error::BusRecoveryFailed);
        }
        if AST_I2CM_BUS_RECOVER == AST_I2CM_BUS_RECOVER & sts {
            self.i2c
                .i2cm14()
                .write(|w| w.wcbus_recover_fail_sts().set_bit());
            return Ok(());
        }
        if AST_I2CM_SMBUS_ALT == AST_I2CM_SMBUS_ALT & sts {
            sts &= !AST_I2CM_SMBUS_ALT;
            if self.i2c.i2cm10().read().enbl_smbus_dev_alert_int().bit() {
                //Disable ALT INT
                self.i2c
                    .i2cm10()
                    .modify(|_, w| w.enbl_smbus_dev_alert_int().clear_bit());
            }
            self.i2c
                .i2cm14()
                .modify(|_, w| w.wcsmbus_dev_alert_intsts().bit(true));
        }
        match self.aspeed_i2c_is_irq_error(sts) {
            Ok(v) => {},
            Err(e) => {
                self.i2c.i2cm14().modify(|_, w| {
                    w.wcpkt_cmd_done_intsts()
                        .bit(true)
                        .wcpkt_cmd_fail_intsts()
                        .bit(true)
                });
                self.i2c_data.completion = true;
                return Err(e);
            },
        }
        if AST_I2CM_PKT_DONE == AST_I2CM_PKT_DONE & sts {
            sts &= !AST_I2CM_PKT_DONE;
            self.i2c
                .i2cm14()
                .modify(|_, w| w.wcpkt_cmd_done_intsts().bit(true));
            return self.aspeed_i2c_master_package_irq(sts);
        }
        if sts > 0 {
            dbg!(self, "aspeed_i2c_master_irq left sts={:#x}", sts);
            self.i2c.i2cm14().write(|w| unsafe { w.bits(sts) });
        }
        Ok(())
    }

    pub fn aspeed_i2c_isr(&mut self) {
        //check slave mode first
        if self.i2c.i2cc00().read().enbl_slave_fn().bit() {
            if self.aspeed_i2c_slave_irq() != 0 {
                return;
            }
        }
        self.aspeed_i2c_master_irq();
    }

    pub fn i2c_wait_completion(&mut self) -> Result<(), Error>{
        let mut delay = DummyDelay {};
        let mut timeout = 1_000_000;
        while timeout > 0 && !self.i2c_data.completion {
            match self.aspeed_i2c_master_irq() {
                Ok(_v) => {},
                Err(e) => return Err(e),
            }
            delay.delay_ns(100_000);
            timeout -= 1;
        }
        if !self.i2c_data.completion {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    pub fn prepare_read(&mut self, addr: u8, len: u32) {
        //initialize xfer data
        self.i2c_data.addr = addr;
        self.i2c_data.alert_enable = false;
        //read
        self.i2c_data.msg.flags = I2C_MSG_READ;
        self.i2c_data.msg.length = len;
        self.i2c_data.stop = true;
        self.i2c_data.completion = false;
        self.i2c_data.master_xfer_cnt = 0;
    }
    //copy data
    pub fn read_processed(&mut self, buffer: &mut [u8]) {
        dbg!(self, "read_processed");
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                let src = self
                    .mdma_buf
                    .as_mut_slice(0, self.i2c_data.msg.length as usize);
                dbg!(self, "{:?}", src);
                buffer.copy_from_slice(src);
            }
            _ => {
                let src = &self.i2c_data.msg.buf[..self.i2c_data.msg.length as usize];
                dbg!(self, "{:?}", src);
                buffer.copy_from_slice(src);
            }
        }
    }
    pub fn prepare_write(&mut self, addr: u8, bytes: &[u8], stop: bool) {
        //initialize xfer data
        self.i2c_data.addr = addr;
        self.i2c_data.alert_enable = false;
        self.i2c_data.msg.flags = I2C_MSG_WRITE;
        self.i2c_data.msg.length = bytes.len() as u32;
        self.i2c_data.stop = stop;
        self.i2c_data.completion = false;
        self.i2c_data.master_xfer_cnt = 0;
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                let dest = &mut self.mdma_buf.as_mut_slice(0, bytes.len() as usize);
                dest.copy_from_slice(bytes);
            }
            _ => {
                //write
                let dest = &mut self.i2c_data.msg.buf[..bytes.len()];
                dest.copy_from_slice(bytes);
            }
        }
    }

    pub fn aspeed_i2c_read(&mut self, ctrl_cmd: u32) {
        let xfer_len: u16;
        let len_left: u32;
        let mut cmd: u32 = ctrl_cmd;
        let msg_len = self.i2c_data.msg.length;
        dbg!(self, "aspeed_i2c_read");
        cmd |= AST_I2CM_RX_CMD;
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                len_left = msg_len - self.i2c_data.master_xfer_cnt;
                if len_left > ASPEED_I2C_DMA_SIZE as u32 {
                    xfer_len = ASPEED_I2C_DMA_SIZE as u16;
                } else {
                    //last transaction
                    xfer_len = len_left as u16;
                    cmd |= AST_I2CM_RX_CMD_LAST | AST_I2CM_STOP_CMD;
                }
                if xfer_len > 0 {
                    dbg!(self, "rx_len {:#x}", xfer_len);
                    unsafe {
                        *self.mdma_buf.as_mut_ptr() = 0;
                    }
                    let phy_addr = self.mdma_buf.as_mut_ptr() as u32;
                    cmd |= AST_I2CM_RX_DMA_EN;
                    self.i2c.i2cm1c().modify(|_, w| unsafe {
                        w.dmarx_buf_len_byte()
                            .bits(xfer_len - 1)
                            .dmarx_buf_len_wr_enbl_for_cur_write_cmd()
                            .set_bit()
                    });
                    dbg!(self, "before rx data: {:#x}", unsafe {
                        *self.mdma_buf.as_ptr()
                    });
                    self.i2c
                        .i2cm34()
                        .modify(|_, w| unsafe { w.sdramdmabuffer_base_addr1().bits(phy_addr) });
                }
            }
            I2cXferMode::BuffMode => {
                len_left = msg_len - self.i2c_data.master_xfer_cnt;

                if len_left > I2C_BUF_SIZE as u32 {
                    xfer_len = I2C_BUF_SIZE as u16;
                } else {
                    //last transaction
                    xfer_len = len_left as u16;
                    cmd |= AST_I2CM_RX_CMD_LAST | AST_I2CM_STOP_CMD;
                }
                if xfer_len > 0 {
                    cmd |= AST_I2CM_RX_BUFF_EN;
                    self.i2c.i2cc0c().modify(|_, w| unsafe {
                        w.rx_pool_buffer_size().bits((xfer_len - 1) as u8)
                    });
                }
            }
            I2cXferMode::ByteMode => {
                //byte mode
                if msg_len == self.i2c_data.master_xfer_cnt + 1 {
                    //last transaction
                    cmd |= AST_I2CM_RX_CMD_LAST | AST_I2CM_STOP_CMD;
                    xfer_len = 1;
                }
            }
        }
        //triggering
        dbg!(self, "trigger cmd {:#x}", cmd);
        self.i2c.i2cm18().write(|w| unsafe { w.bits(cmd) });
    }

    pub fn aspeed_i2c_write(&mut self, ctrl_cmd: u32) {
        let xfer_len: u16;
        let len_left: u32;
        let mut cmd: u32 = ctrl_cmd;
        let msg_len = self.i2c_data.msg.length as u32;

        dbg!(self, "aspeed_i2c_write");
        cmd |= AST_I2CM_TX_CMD;
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                //dma mode
                len_left = msg_len - self.i2c_data.master_xfer_cnt;
                if len_left > ASPEED_I2C_DMA_SIZE as u32 {
                    xfer_len = ASPEED_I2C_DMA_SIZE as u16;
                } else {
                    //last transaction
                    xfer_len = len_left as u16;
                    if self.i2c_data.stop {
                        cmd |= AST_I2CM_STOP_CMD;
                    }
                }
                if xfer_len > 0 {
                    let phy_addr = self.mdma_buf.as_mut_ptr() as u32;
                    dbg!(self, "write len {:#x}, data {:#x}", xfer_len, unsafe {
                        *self.mdma_buf.as_ptr()
                    });
                    cmd |= AST_I2CM_TX_DMA_EN | AST_I2CM_TX_CMD;

                    self.i2c.i2cm1c().write(|w| unsafe {
                        w.dmatx_buf_len_byte()
                            .bits(xfer_len - 1)
                            .dmatx_buf_len_wr_enbl_for_cur_write_cmd()
                            .set_bit()
                    });
                    self.i2c
                        .i2cm30()
                        .write(|w| unsafe { w.sdramdmabuffer_base_addr().bits(phy_addr) });
                }
            }
            I2cXferMode::BuffMode => {
                len_left = msg_len - self.i2c_data.master_xfer_cnt;
                if len_left > I2C_BUF_SIZE as u32 {
                    xfer_len = I2C_BUF_SIZE as u16;
                } else {
                    //last transaction
                    xfer_len = len_left as u16;
                    if self.i2c_data.stop {
                        cmd |= AST_I2CM_STOP_CMD;
                    }
                }
                if xfer_len > 0 {
                    cmd |= AST_I2CM_TX_BUFF_EN | AST_I2CM_TX_CMD;
                    self.copy_to_buff(xfer_len);
                    self.i2c.i2cc0c().modify(|_, w| unsafe {
                        w.tx_data_byte_count().bits((xfer_len - 1) as u8)
                    });
                }
            }
            I2cXferMode::ByteMode => {
                if self.i2c_data.master_xfer_cnt + 1 == msg_len {
                    if self.i2c_data.stop {
                        cmd |= AST_I2CM_STOP_CMD;
                    }
                }
                let buf_index = self.i2c_data.master_xfer_cnt as usize;
                dbg!(
                    self,
                    "byte mode tx data: {:#x}",
                    self.i2c_data.msg.buf[buf_index]
                );
                self.i2c.i2cc08().modify(|_, w| unsafe {
                    w.tx_byte_buffer().bits(self.i2c_data.msg.buf[buf_index])
                });
            }
        }
        //triggering
        dbg!(self, "trigger cmd {:#x}", cmd);
        self.i2c.i2cm18().write(|w| unsafe { w.bits(cmd) });
    }

    //master recover bus
    pub fn aspeed_new_i2c_recover_bus(&mut self) -> Result<(), Error> {
        //disable master and slave functionality to put it in idle state
        self.i2c
            .i2cc00()
            .modify(|_, w| w.enbl_master_fn().bit(false).enbl_slave_fn().bit(false));
        //enable master functionality
        self.i2c
            .i2cc00()
            .modify(|_, w| w.enbl_master_fn().bit(true));
        self.i2c_data.bus_recover = 1;
        //Check SDA and SCL status
        if !self.i2c.i2cc08().read().sampled_sdaline_state().bit()
            && self.i2c.i2cc08().read().sampled_sclline_state().bit()
        {
            //stuck and recover
            self.i2c
                .i2cm18()
                .modify(|_, w| w.enbl_bus_recover_cmd().bit(true));
            return self.i2c_wait_completion();

        } else {
            //can't recover this situation
            return Err(Error::Proto);
        }
    }

    pub fn i2c_aspeed_transfer(&mut self) -> Result<(), Error> {
        let mut cmd: u32;

        //If bus is busy in a single master environment, attempt recovery
        if !self.multi_master && self.i2c.i2cc08().read().bus_busy_status().bit() {
            if self.aspeed_new_i2c_recover_bus().is_err() {
                return Err(Error::Bus);
            }
        }
        cmd = AST_I2CM_PKT_EN | ast_i2cm_pkt_addr(self.i2c_data.addr) | AST_I2CM_START_CMD;
        if self.i2c_data.msg.flags & I2C_MSG_READ > 0 {
            self.aspeed_i2c_read(cmd);
        } else {
            self.aspeed_i2c_write(cmd);
        }
        if self.i2c_wait_completion().is_err() {
            //timeout, do controller reset to recover
            let isr = self.i2c.i2cm14().read().bits();
            if isr > 0 || self.i2c.i2cc08().read().xfer_data_direction().bits() > 0 {
                let ctrl = self.i2c.i2cc00().read().bits();
                self.i2c.i2cc00().write(|w| unsafe { w.bits(0) });
                self.i2c.i2cc00().write(|w| unsafe { w.bits(ctrl) });
                if cfg!(feature = "i2c_target") {
                    cmd = AST_I2CS_ACTIVE_ALL | AST_I2CS_PKT_MODE_EN;
                    if ctrl & AST_I2CC_SLAVE_EN == AST_I2CC_SLAVE_EN {
                        match self.xfer_mode {
                            I2cXferMode::DmaMode => {
                                cmd |= AST_I2CS_RX_DMA_EN;
                                self.i2c.i2cs3c().write(|w| unsafe {
                                    w.sdramdmabuffer_base_addr3()
                                        .bits(self.sdma_buf.as_mut_ptr() as u32)
                                });
                                self.i2c.i2cs38().write(|w| unsafe {
                                    w.sdramdmabuffer_base_addr2()
                                        .bits(self.sdma_buf.as_mut_ptr() as u32)
                                });
                                self.i2c.i2cs2c().write(|w| unsafe {
                                    w.dmarx_buf_len_byte()
                                        .bits((I2C_SLAVE_BUF_SIZE - 1) as u16)
                                        .dmarx_buf_len_wr_enbl_for_cur_cmd()
                                        .set_bit()
                                });
                            }
                            I2cXferMode::BuffMode => {
                                cmd |= AST_I2CS_RX_BUFF_EN;
                                self.i2c.i2cc0c().write(|w| unsafe {
                                    w.rx_pool_buffer_size().bits(I2C_BUF_SIZE - 1)
                                });
                            }
                            I2cXferMode::ByteMode => {
                                cmd &= !AST_I2CS_PKT_MODE_EN;
                            }
                        }
                        self.i2c.i2cs28().write(|w| unsafe { w.bits(cmd) });
                    }
                }
                return Err(Error::Timeout);
            }
        }
        Ok(())
    }
    //slave
    pub fn i2c_aspeed_slave_register(
        &mut self,
        target_addr: u8,
        target: Option<&'a mut I2CT>,
    ) -> Result<(), Error> {
        let mut cmd = AST_I2CS_ACTIVE_ALL | AST_I2CS_PKT_MODE_EN;

        // check slave config exist or has attached ever
        if self.i2c_data.slave_attached || self.i2c.i2cc00().read().enbl_slave_fn().bit() {
            return Err(Error::Invalid);
        }

        if target_addr == self.i2c_data.slave_target_addr {
            return Err(Error::Invalid);
        }

        self.i2c_data.set_target(target_addr, target);

        dbg!(self, "set slave addr {:#x}", target_addr);
        //set slave addr
        self.i2c.i2cs40().modify(|_, w| unsafe {
            w.slave_dev_addr1()
                .bits(target_addr)
                .enbl_slave_dev_addr1only_for_new_reg_mode()
                .bit(true)
        });
        // trigger rx buffer
        match self.xfer_mode {
            I2cXferMode::DmaMode => {
                cmd |= AST_I2CS_RX_DMA_EN;
                let slave_dma_addr = self.sdma_buf.as_mut_ptr() as u32;
                self.i2c
                    .i2cs38()
                    .write(|w| unsafe { w.sdramdmabuffer_base_addr2().bits(slave_dma_addr) });
                self.i2c
                    .i2cs3c()
                    .write(|w| unsafe { w.sdramdmabuffer_base_addr3().bits(slave_dma_addr) });
                self.i2c.i2cs2c().write(|w| unsafe {
                    w.dmarx_buf_len_byte()
                        .bits((I2C_SLAVE_BUF_SIZE - 1) as u16)
                        .dmarx_buf_len_wr_enbl_for_cur_cmd()
                        .set_bit()
                });
            }
            I2cXferMode::BuffMode => {
                cmd |= AST_I2CS_RX_BUFF_EN;
                self.i2c
                    .i2cc0c()
                    .write(|w| unsafe { w.rx_pool_buffer_size().bits(I2C_BUF_SIZE - 1) });
            }
            I2cXferMode::ByteMode => {
                cmd &= !AST_I2CS_PKT_MODE_EN;
            }
        }
        //apply slave device setting and trigger
        self.i2c.i2cs28().write(|w| unsafe { w.bits(cmd) });

        // enable slave device
        self.i2c.i2cc00().modify(|_, w| w.enbl_slave_fn().bit(true));
        self.i2c_data.slave_attached = true;

        self.dump_regs();

        Ok(())
    }

    pub fn i2c_aspeed_slave_unregister(&mut self) -> Result<(), Error> {
        if !self.i2c_data.slave_attached {
            return Err(Error::Invalid);
        }

        self.i2c_data.slave_target = None;
        self.i2c_data.slave_target_addr = 0;
        //Turn off slave mode.
        self.i2c
            .i2cc00()
            .modify(|_, w| w.enbl_slave_fn().bit(false));
        //remove slave address
        self.i2c.i2cs40().modify(|_, w| unsafe {
            w.slave_dev_addr1()
                .bits(0)
                .enbl_slave_dev_addr1only_for_new_reg_mode()
                .bit(false)
        });
        self.i2c_data.slave_attached = false;
        Ok(())
    }

    pub fn aspeed_i2c_slave_timeout(&mut self, sts: u32, reset_slave: bool) {
        let cmd: u32;
        // Reset time out counter
        let mut ac_timing = self.i2c.i2cc04().read().bits();

        ac_timing &= AST_I2CC_AC_TIMING_MASK;
        self.i2c.i2cc04().write(|w| unsafe { w.bits(ac_timing) });
        self.i2c
            .i2cc04()
            .modify(|_, w| unsafe { w.timeout_timer().bits(I2C_TIMEOUT_COUNT) });
        if reset_slave {
            //Turn off slave mode
            self.i2c
                .i2cc00()
                .modify(|_, w| w.enbl_slave_fn().bit(false));
            //Turn on slave mode
            self.i2c.i2cc00().modify(|_, w| w.enbl_slave_fn().bit(true));
        }
        if self.xfer_mode == I2cXferMode::ByteMode {
            //Clear irq and re-send slave trigger command
            cmd = AST_I2CS_ACTIVE_ALL;
            self.i2c.i2cs28().write(|w| unsafe { w.bits(cmd) });
            self.i2c.i2cs24().write(|w| unsafe { w.bits(sts) });
            self.i2c.i2cs24().read().bits();
        } else {
            cmd = SLAVE_TRIGGER_CMD | AST_I2CS_RX_DMA_EN;
            self.i2c.i2cs2c().write(|w| unsafe {
                w.dmarx_buf_len_byte()
                    .bits((I2C_SLAVE_BUF_SIZE - 1) as u16)
                    .dmarx_buf_len_wr_enbl_for_cur_cmd()
                    .set_bit()
            });
            self.i2c.i2cs28().write(|w| unsafe { w.bits(cmd) });
            self.i2c
                .i2cs24()
                .modify(|_, w| w.wcpkt_cmd_done_intsts().bit(true));
        }
        self.i2c_slave_event_stop();
        self.i2c_data.slave_operate = 0;
    }

    pub fn aspeed_i2c_slave_irq(&mut self) -> u32 {
        let ier = self.i2c.i2cs20().read().bits();
        let mut sts = self.i2c.i2cs24().read().bits();
        //dbg!(self, "aspeed_i2c_slave_irq: ier {:#x}, sts {:#x}", ier, sts);
        //return without necessary slave interrupt
        if (sts & ier) == 0 {
            return 0;
        }
        dbg!(self, "Slave irq ier {:#x}, sts {:#x}", ier, sts);
        // remove unnessary status flags
        sts &= !(AST_I2CS_ADDR_INDICATE_MASK | AST_I2CS_SLAVE_PENDING);
        if AST_I2CS_ADDR1_NAK == AST_I2CS_ADDR1_NAK & sts {
            sts &= !AST_I2CS_ADDR1_NAK;
        }
        if AST_I2CS_ADDR2_NAK == AST_I2CS_ADDR2_NAK & sts {
            sts &= !AST_I2CS_ADDR2_NAK;
        }
        if AST_I2CS_ADDR3_NAK == AST_I2CS_ADDR3_NAK & sts {
            sts &= !AST_I2CS_ADDR3_NAK;
        }
        if AST_I2CS_ADDR_MASK == AST_I2CS_ADDR_MASK & sts {
            sts &= !AST_I2CS_ADDR_MASK;
        }
        if AST_I2CS_INACTIVE_TO == AST_I2CS_INACTIVE_TO & sts {
            self.aspeed_i2c_slave_timeout(sts, true);
            return 1;
        }
        if AST_I2CS_PKT_DONE & sts == AST_I2CS_PKT_DONE {
            self.aspeed_i2c_slave_packet_irq(sts);
        } else {
            self.aspeed_i2c_slave_byte_irq(sts);
        }
        1
    }

    //
    //I2C_SLAVE_WRITE_REQUESTED:
    //
    pub fn i2c_slave_event_stop(&mut self) {
        match self.i2c_data.slave_target.as_mut() {
            Some(target) => {
                target.on_stop();
            }
            None => {
                // Handle the case where config is not set
            }
        }
    }
    pub fn i2c_slave_pkt_read(&mut self, event: I2cSEvent) {
        if event == I2cSEvent::SlaveRdReq {
            dbg!(self, "read_requested");
            if let Some(target) = self.i2c_data.slave_target.as_mut() {
                target.on_transaction_start(false);
            }
        } else if event == I2cSEvent::SlaveRdProc {
            dbg!(self, "read_processed");
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    let tx_len = self.i2c.i2cs4c().read().dmatx_actual_len_byte().bits();
                    dbg!(self, "dma tx_len {:#x}", tx_len);
                    let mut slice = self.sdma_buf.as_mut_slice(0, 1);
                    if let Some(target) = self.i2c_data.slave_target.as_mut() {
                        target.on_read(&mut slice);
                    } else {
                        dbg!(self, "dma dummy read");
                        slice[0] = 0xde;
                    }
                    dbg!(self, "dma tx data {:#x}", slice[0]);
                }
                I2cXferMode::BuffMode => {
                    let tx_len = self.i2c.i2cc0c().read().tx_data_byte_count().bits();
                    dbg!(self, "buff tx_len {:#x}", tx_len);
                    if let Some(target) = self.i2c_data.slave_target.as_mut() {
                        target.on_read(&mut self.i2c_data.msg.buf[..1]);
                    } else {
                        dbg!(self, "buff dummy read");
                        self.i2c_data.msg.buf[0] = 0xdf;
                    }
                    dbg!(self, "buff tx data {:#x}", self.i2c_data.msg.buf[0]);
                }
                _ => {}
            }
        }
    }
    pub fn i2c_slave_pkt_write(&mut self, event: I2cSEvent) {
        if event == I2cSEvent::SlaveWrReq {
            //Another I2C master wants to write data to us.
            //This event should be sent once our own address and the write bit was detected
            //The data did not arrive yet
            //ack the address phase
            //if slave is ready to receive
            dbg!(self, "write_requested");
            if let Some(target) = self.i2c_data.slave_target.as_mut() {
                target.on_transaction_start(false);
            }
        } else if event == I2cSEvent::SlaveWrRecvd {
            //Another I2C master has sent a byte to us which needs to be set in ‘val’
            //bus driver delivers received byte
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    let slave_rx_len = self.i2c.i2cs4c().read().dmarx_actual_len_byte().bits();
                    dbg!(self, "dma write_received: len={:#x}", slave_rx_len);
                    let slice = self.sdma_buf.as_slice(0, slave_rx_len as usize);
                    if let Some(target) = self.i2c_data.slave_target.as_mut() {
                        target.on_write(slice);
                    }
                    dbg!(self, "write_received: data={:?}", slice);
                }
                I2cXferMode::BuffMode => {
                    let slave_rx_len = self
                        .i2c
                        .i2cc0c()
                        .read()
                        .actual_rxd_pool_buffer_size()
                        .bits() as u16;
                    dbg!(self, "buff write_received: len={:#x}", slave_rx_len);
                    if let Some(target) = self.i2c_data.slave_target.as_mut() {
                        target.on_write(&self.i2c_data.msg.buf[..(slave_rx_len as usize)]);
                    }
                    dbg!(
                        self,
                        "write_received data={:?}",
                        &self.i2c_data.msg.buf[0..(slave_rx_len as usize)]
                    );
                }
                _ => {}
            }
        }
    }
    pub fn i2c_slave_byte_write(&mut self, event: I2cSEvent, val: u8) {
        if event == I2cSEvent::SlaveWrReq {
            dbg!(self, "byte write_requested");
            if let Some(target) = self.i2c_data.slave_target.as_mut() {
                target.on_transaction_start(false);
            }
        } else if event == I2cSEvent::SlaveWrRecvd {
            dbg!(self, "byte write_received");
            if let Some(target) = self.i2c_data.slave_target.as_mut() {
                target.on_write(&[val]);
            }
        }
    }
    pub fn i2c_slave_byte_read(&mut self, event: I2cSEvent, val: &mut u8) {
        if event == I2cSEvent::SlaveRdReq {
            dbg!(self, "byte read_requested");
            if let Some(target) = self.i2c_data.slave_target.as_mut() {
                target.on_transaction_start(false);
            }
        } else if event == I2cSEvent::SlaveRdProc {
            dbg!(self, "byte read_processed");
            if let Some(target) = self.i2c_data.slave_target.as_mut() {
                target.on_read(core::slice::from_mut(val));
            } else {
                dbg!(self, "byte dummy read");
                *val = 0xdd;
            }
        }
    }
    pub fn aspeed_i2c_slave_packet_irq(&mut self, sts: u32) {
        let mut cmd: u32 = 0;
        let mut sts = sts;
        dbg!(self, "enter aspeed_i2c_slave_packet_irq");
        // clear irq first
        self.i2c
            .i2cs24()
            .modify(|_, w| w.wcpkt_cmd_done_intsts().bit(true));
        sts &= !(AST_I2CS_PKT_DONE | AST_I2CS_PKT_ERROR);

        if sts == AST_I2CS_SLAVE_MATCH || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE {
            dbg!(self, "S: Sw\n");
            self.i2c_slave_pkt_write(I2cSEvent::SlaveWrReq);
        } else if sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_WAIT_RX_DMA
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA
        {
            dbg!(self, "S: Sw|D - issue rx\n");
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrReq);
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrRecvd);
                    self.i2c.i2cs4c().write(|w| unsafe { w.bits(0) });
                    self.i2c.i2cs2c().write(|w| unsafe {
                        w.dmarx_buf_len_byte()
                            .bits((I2C_SLAVE_BUF_SIZE - 1) as u16)
                            .dmarx_buf_len_wr_enbl_for_cur_cmd()
                            .set_bit()
                    });
                    cmd |= AST_I2CS_RX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrReq);
                    cmd |= AST_I2CS_RX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
        } else if sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_STOP {
            dbg!(self, "S : Sw | P\n");
            self.i2c_slave_event_stop();
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    cmd |= AST_I2CS_RX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    cmd |= AST_I2CS_RX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
        } else if sts == AST_I2CS_RX_DONE | AST_I2CS_STOP
            || sts == AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA
            || sts == AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA | AST_I2CS_STOP
            || sts == AST_I2CS_RX_DONE_NAK | AST_I2CS_RX_DONE | AST_I2CS_STOP
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_STOP
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA | AST_I2CS_STOP
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE_NAK | AST_I2CS_RX_DONE | AST_I2CS_STOP
        {
            dbg!(self, "S: (Sw)|D|(P)\n");
            if AST_I2CS_SLAVE_MATCH == sts & AST_I2CS_SLAVE_MATCH {
                self.i2c_slave_pkt_write(I2cSEvent::SlaveWrReq);
            }
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrRecvd);
                    self.i2c.i2cs4c().write(|w| unsafe { w.bits(0) });
                    self.i2c.i2cs2c().write(|w| unsafe {
                        w.dmarx_buf_len_byte()
                            .bits((I2C_SLAVE_BUF_SIZE - 1) as u16)
                            .dmarx_buf_len_wr_enbl_for_cur_cmd()
                            .set_bit()
                    });
                    cmd |= AST_I2CS_RX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    self.copy_from_buff(I2C_BUF_SIZE as u16);
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrRecvd);
                    cmd |= AST_I2CS_RX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
            if AST_I2CS_STOP == sts & AST_I2CS_STOP {
                self.i2c_slave_event_stop();
            }
        } else if sts == AST_I2CS_RX_DONE | AST_I2CS_WAIT_TX_DMA
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_WAIT_TX_DMA
        {
            dbg!(self, "S: AST_I2CS_RX_DONE | AST_I2CS_WAIT_TX_DMA\n");
            //read bit from master, slave tx to master
            //finish write request if any
            if AST_I2CS_SLAVE_MATCH == sts & AST_I2CS_SLAVE_MATCH {
                self.i2c_slave_pkt_write(I2cSEvent::SlaveWrReq);
            }
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrRecvd);
                    //read request
                    self.i2c_slave_pkt_read(I2cSEvent::SlaveRdReq);
                    //LOG_DBG("tx [%02x]", data->slave_dma_buf[0]);
                    self.i2c.i2cs4c().write(|w| unsafe { w.bits(0) });
                    self.i2c.i2cs2c().modify(|_, w| unsafe {
                        w.dmatx_buf_len_byte()
                            .bits(0)
                            .dmatx_buf_len_wr_enbl_for_cur_cmd()
                            .set_bit()
                    });
                    cmd |= AST_I2CS_TX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    self.copy_from_buff(I2C_BUF_SIZE as u16);
                    self.i2c_slave_pkt_write(I2cSEvent::SlaveWrRecvd);
                    self.i2c_slave_pkt_read(I2cSEvent::SlaveRdReq);
                    self.i2c
                        .i2cc0c()
                        .write(|w| unsafe { w.tx_data_byte_count().bits(0) });
                    cmd |= AST_I2CS_TX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
        } else if sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_WAIT_TX_DMA {
            //First Start read
            dbg!(self, "S: Sw | AST_I2CS_Wait_TX_DMA\n");
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    self.i2c_slave_pkt_read(I2cSEvent::SlaveRdProc);

                    self.i2c.i2cs2c().modify(|_, w| unsafe {
                        w.dmatx_buf_len_byte()
                            .bits(0)
                            .dmatx_buf_len_wr_enbl_for_cur_cmd()
                            .set_bit()
                    });
                    cmd |= AST_I2CS_TX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    self.i2c_slave_pkt_read(I2cSEvent::SlaveRdProc);
                    self.copy_to_buff(I2C_BUF_SIZE as u16);
                    self.i2c
                        .i2cc0c()
                        .write(|w| unsafe { w.tx_data_byte_count().bits(0) });
                    cmd |= AST_I2CS_TX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
        } else if sts == AST_I2CS_WAIT_TX_DMA {
            dbg!(self, "S: AST_I2CS_Wait_TX_DMA\n");
            //it should be next start read
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    self.i2c_slave_pkt_read(I2cSEvent::SlaveRdProc);

                    self.i2c.i2cs2c().modify(|_, w| unsafe {
                        w.dmatx_buf_len_byte()
                            .bits(0)
                            .dmatx_buf_len_wr_enbl_for_cur_cmd()
                            .set_bit()
                    });
                    cmd |= AST_I2CS_TX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    self.i2c_slave_pkt_read(I2cSEvent::SlaveRdProc);
                    self.copy_to_buff(I2C_BUF_SIZE as u16);
                    cmd |= AST_I2CS_TX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
        } else if sts == AST_I2CS_TX_NAK | AST_I2CS_STOP || sts == AST_I2CS_STOP {
            if sts & AST_I2CS_TX_NAK == AST_I2CS_TX_NAK {
                dbg!(self, "S: TX_NAK | P\n");
            } else {
                dbg!(self, "S: P\n");
            }
            self.i2c_slave_event_stop();
            cmd = SLAVE_TRIGGER_CMD;
            match self.xfer_mode {
                I2cXferMode::DmaMode => {
                    self.i2c.i2cs2c().modify(|_, w| unsafe {
                        w.dmarx_buf_len_byte()
                            .bits((I2C_SLAVE_BUF_SIZE - 1) as u16)
                            .dmarx_buf_len_wr_enbl_for_cur_cmd()
                            .set_bit()
                    });
                    cmd |= AST_I2CS_RX_DMA_EN;
                }
                I2cXferMode::BuffMode => {
                    self.i2c
                        .i2cc0c()
                        .write(|w| unsafe { w.rx_pool_buffer_size().bits(I2C_BUF_SIZE - 1) });
                    cmd |= AST_I2CS_RX_BUFF_EN;
                }
                _ => {
                    cmd &= !AST_I2CS_PKT_MODE_EN;
                }
            }
        } else {
            dbg!(self, "TODO packet slave sts {:#x}\n", sts);
        }
        if cmd > 0 {
            self.i2c.i2cs28().write(|w| unsafe { w.bits(cmd) });
        }
    }

    pub fn aspeed_i2c_slave_byte_irq(&mut self, mut sts: u32) {
        let mut cmd = AST_I2CS_ACTIVE_ALL;
        let mut byte_data = 0;

        dbg!(self, "enter aspeed_i2c_slave_byte_irq");
        if sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA {
            dbg!(self, "S : Sw|D\n");
            // first address match is address
            byte_data = self.i2c.i2cc08().read().rx_byte_buffer().bits();
            dbg!(
                self,
                "rx: {:#x}, addr {:#x} , R: {}",
                byte_data,
                byte_data >> 1,
                byte_data & 0x1
            );
            // If the record address is still same, it is re-start case.
            if byte_data != self.i2c_data.slave_addr_last {
                self.i2c_slave_byte_write(I2cSEvent::SlaveWrReq, byte_data);
            }
            self.i2c_data.slave_addr_last = byte_data;
        } else if sts
            == AST_I2CS_SLAVE_MATCH
                | AST_I2CS_RX_DONE
                | AST_I2CS_WAIT_RX_DMA
                | AST_I2CS_STOP
                | AST_I2CS_TX_NAK
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA | AST_I2CS_STOP
        {
            dbg!(self, "S : Sw|D|P\n");
            self.i2c_slave_event_stop();
            self.i2c_data.slave_addr_last = 0;
            // first address match is address
            byte_data = self.i2c.i2cc08().read().rx_byte_buffer().bits();
            dbg!(self, "data: {:#x}", byte_data);
            self.i2c_slave_byte_write(I2cSEvent::SlaveWrReq, byte_data);
            self.i2c_data.slave_addr_last = byte_data;
        } else if sts == AST_I2CS_RX_DONE | AST_I2CS_WAIT_RX_DMA {
            dbg!(self, "S: rD\n");
            byte_data = self.i2c.i2cc08().read().rx_byte_buffer().bits();
            dbg!(self, "data: {:#x}", byte_data);
            self.i2c_slave_byte_write(I2cSEvent::SlaveWrRecvd, byte_data);
        }
        //pending stop and start address handle
        else if sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_RX_DONE | AST_I2CS_WAIT_TX_DMA {
            dbg!(self, "S : Sr|D\n");
            cmd |= AST_I2CS_TX_CMD;
            byte_data = self.i2c.i2cc08().read().rx_byte_buffer().bits();
            dbg!(
                self,
                "rx: {:#x}, addr {:#x} , R: {}",
                byte_data,
                byte_data >> 1,
                byte_data & 0x1
            );
            self.i2c_slave_byte_read(I2cSEvent::SlaveRdProc, &mut byte_data);
            dbg!(self, "data: {:#x}", byte_data);
            self.i2c
                .i2cc08()
                .modify(|_, w| unsafe { w.tx_byte_buffer().bits(byte_data) });
        } else if sts == AST_I2CS_TX_ACK | AST_I2CS_WAIT_TX_DMA {
            dbg!(self, "S: tD\n");
            cmd |= AST_I2CS_TX_CMD;
            self.i2c_slave_byte_read(I2cSEvent::SlaveRdProc, &mut byte_data);
            dbg!(self, "data: {:#x}", byte_data);
            self.i2c
                .i2cc08()
                .modify(|_, w| unsafe { w.tx_byte_buffer().bits(byte_data) });
        } else if sts == AST_I2CS_STOP
            || sts == AST_I2CS_STOP | AST_I2CS_TX_NAK
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_STOP | AST_I2CS_TX_NAK
            || sts == AST_I2CS_SLAVE_MATCH | AST_I2CS_WAIT_RX_DMA | AST_I2CS_STOP | AST_I2CS_TX_NAK
        {
            dbg!(self, "S : P\n");
            self.i2c_slave_event_stop();
            //clear recorded slave address
            self.i2c_data.slave_addr_last = 0;
            if AST_I2CS_SLAVE_MATCH == sts & AST_I2CS_SLAVE_MATCH {
                //Don't handle this match for current condition
                sts &= !AST_I2CS_SLAVE_MATCH;
            }
            if AST_I2CS_WAIT_RX_DMA == sts & AST_I2CS_WAIT_RX_DMA {
                //Don't handle this waiting for current condition
                sts &= !AST_I2CS_WAIT_RX_DMA;
            }
        } else {
            dbg!(self, "TODO byte slave sts {:#x}\n", sts);
        }
        self.i2c.i2cs28().write(|w| unsafe { w.bits(cmd) });
        self.i2c.i2cs24().write(|w| unsafe { w.bits(sts) });
        self.i2c.i2cs24().read().bits();
    }
    pub fn transaction<'b>(
        &mut self,
        addr: SevenBitAddress,
        mut ops: impl Iterator<Item = Operation<'a>>,
    ) -> Result<(), Error> {
        if let Some(mut prev_op) = ops.next() {
            // 1. Generate Start for operation
            match &prev_op {
                Operation::Read(_) => {}
                Operation::Write(_) => {}
            };

            for op in ops {
                // 2. Execute previous operations.
                match &mut prev_op {
                    Operation::Read(rb) => self.read(addr, rb),
                    Operation::Write(wb) => self.write(addr, &wb),
                };
                // 3. If operation changes type we must generate new start
                /*match (&prev_op, &op) {
                    (Operation::Read(_), Operation::Write(_)) => {
                        self.prepare_write(addr)?
                    }
                    (Operation::Write(_), Operation::Read(_)) => {
                        self.prepare_read(addr, false)?
                    }
                    _ => {} // No changes if operation have not changed
                }*/

                prev_op = op;
            }

            // 4. Now, prev_op is last command use methods variations that will generate stop
            /*match prev_op {
                Operation::Read(rb) => self.read_wo_prepare(rb)?,
                Operation::Write(wb) => self.write_wo_prepare(wb)?,
            };*/
        }

        // Fallthrough is success
        Ok(())
    }

    pub fn transaction_slice(
        &mut self,
        addr: SevenBitAddress,
        ops_slice: &mut [Operation<'_>],
    ) -> Result<(), Error> {
        let addr = addr.into();
        transaction_impl!(self, addr, ops_slice, Operation);
        // Fallthrough is success
        Ok(())
    }
}

macro_rules! transaction_impl {
    ($self:ident, $addr:ident, $ops_slice:ident, $Operation:ident) => {
        let i2c = $self;
        let addr = $addr;
        let mut ops = $ops_slice.iter_mut();

        if let Some(mut prev_op) = ops.next() {
            // 1. Generate Start for operation
            /*match &prev_op {
                $Operation::Read(_) => i2c.prepare_read(addr, true)?,
                $Operation::Write(_) => i2c.prepare_write(addr)?,
            };*/

            for op in ops {
                // 2. Execute previous operations.
                match &mut prev_op {
                    $Operation::Read(rb) => i2c.read(addr, rb),
                    $Operation::Write(wb) => i2c.write(addr, &wb),
                };
                // 3. If operation changes type we must generate new start
                /*match (&prev_op, &op) {
                    ($Operation::Read(_), $Operation::Write(_)) => i2c.prepare_write(addr)?,
                    ($Operation::Write(_), $Operation::Read(_)) => i2c.prepare_read(addr, false)?,
                    _ => {} // No changes if operation have not changed
                }*/

                prev_op = op;
            }

            // 4. Now, prev_op is last command use methods variations that will generate stop
            /*match prev_op {
                $Operation::Read(rb) => i2c.read_wo_prepare(rb)?,
                $Operation::Write(wb) => i2c.write_wo_prepare(wb)?,
            }*/
        }
    };
}
use transaction_impl;
