// Licensed under the Apache-2.0 license

//! spidmairqtest.rs - DMA irq read/write test harness using static buffers and chainable callbacks

use super::fmccontroller::FmcController;
use crate::common::{DmaBuffer, DummyDelay};
use crate::spi::device::ChipSelectDevice;
use crate::spi::norflash::{SpiNorData, SpiNorDevice};
use crate::spi::spicontroller::SpiController;
use crate::spi::spitest::{self, DeviceId, FMC_CONFIG};
use crate::spi::SpiData;
use crate::spimonitor::{RegionInfo, SpiMonitor, SpimExtMuxSel};
use crate::uart::UartController;
use crate::{astdebug, pinctrl};
use ast1060_pac::Spipf;
use core::ptr;
use cortex_m::peripheral::NVIC;
use embedded_hal::delay::DelayNs;
use embedded_io::Write;
use heapless::Deque;

static mut UART_PTR: Option<&'static mut UartController<'static>> = None;
static mut FMC_CONTROLLER: Option<FmcController<'static>> = None;
static mut SPI_CONTROLLER: Option<SpiController<'static>> = None;
//static mut SPI1_CONTROLLER: Option<SpiController<'static>> = None;

static mut FMC_DEVICE0: Option<ChipSelectDevice<'static, FmcController<'static>, Spipf>> = None;
static mut FMC_DEV0_PTR: *mut ChipSelectDevice<'_, FmcController<'_>, Spipf> =
    core::ptr::null_mut();
static mut FMC_DEVICE1: Option<ChipSelectDevice<'static, FmcController<'static>, Spipf>> = None;
static mut FMC_DEV1_PTR: *mut ChipSelectDevice<'_, FmcController<'_>, Spipf> =
    core::ptr::null_mut();

static mut SPI_DEVICE0: Option<ChipSelectDevice<'static, SpiController<'static>, Spipf>> = None;
static mut SPI_DEV0_PTR: *mut ChipSelectDevice<'_, SpiController<'_>, Spipf> =
    core::ptr::null_mut();

static mut SPI_MONITOR0: Option<SpiMonitor<Spipf>> = None;

// DMA operation type selector
#[derive(Debug, Copy, Clone)]
pub enum DmaOp {
    Read,
    ReadFast,
    Program,
    ProgramFast,
}

// DMA request struct with callback
#[derive(Debug)]
pub struct DmaRequest {
    pub src_addr: usize,
    pub dst_buf: &'static mut [u8],
    pub len: usize,
    pub op: DmaOp,
    pub verify: bool,   // for test
    pub buf_idx: usize, // for test
    pub on_complete: fn(bool, usize, &[u8]),
}

// Configuration
const MAX_DMA_CHAIN: usize = 4;
const DMA_BUF_SIZE: usize = 256;
// Static state for current DMA and queue
// use as FIFO

#[link_section = ".ram_nc"]
static mut READ_BUFFERS: [DmaBuffer<DMA_BUF_SIZE>; MAX_DMA_CHAIN] =
    [const { DmaBuffer::new() }; MAX_DMA_CHAIN];
#[link_section = ".ram_nc"]
static mut WRITE_BUFFERS: [DmaBuffer<DMA_BUF_SIZE>; MAX_DMA_CHAIN] =
    [const { DmaBuffer::new() }; MAX_DMA_CHAIN];

static mut CURRENT_DMA: Option<DmaRequest> = None;
static mut DMA_QUEUE: Deque<DmaRequest, MAX_DMA_CHAIN> = Deque::new();
static mut CURRENT_DEVID: DeviceId = DeviceId::FmcCs0Idx;

#[no_mangle]
pub extern "C" fn fmc() {
    unsafe {
        let fmc = FMC_CONTROLLER.as_mut().unwrap();
        let uart = UART_PTR.as_mut().unwrap();

        if let Err(e) = fmc.handle_interrupt() {
            // test done!. irq error
            writeln!(uart, "Failed: {e:?}").ok();
        } else {
            writeln!(uart, "fmc()").ok();
            if let Some(req) = CURRENT_DMA.take() {
                writeln!(uart, "completed").ok();
                (req.on_complete)(req.verify, req.buf_idx, req.dst_buf);
            } else {
                writeln!(uart, "Error... no CURRENT fmc DMA").ok();
            }
            start_next_dma();
        }
    }
}

#[no_mangle]
pub extern "C" fn spi() {
    unsafe {
        let spi = SPI_CONTROLLER.as_mut().unwrap();
        let uart = UART_PTR.as_mut().unwrap();

        if let Err(e) = spi.handle_interrupt() {
            // test done!. irq error
            writeln!(uart, "Failed: {e:?}").ok();
        } else {
            if let Some(req) = CURRENT_DMA.take() {
                writeln!(uart, "completed").ok();
                (req.on_complete)(req.verify, req.buf_idx, req.dst_buf);
            } else {
                writeln!(uart, "Error... no CURRENT spi DMA").ok();
            }

            start_next_dma();
        }
    }
}

#[macro_export]
macro_rules! log_uart {
    ($($arg:tt)*) => {{
        if let Some(uart) = $crate::spi::spidmairqtest::UART_PTR.as_mut() {
            writeln!(uart, $($arg)*).ok();
            write!(uart, "\r").ok();
        }
    }};
}

unsafe fn show_mmap_reg() {
    let (_, mmap_addr, _) = spitest::device_info(CURRENT_DEVID);

    let uart = UART_PTR.as_mut().unwrap();
    log_uart!("[{:08x}]", mmap_addr);
    astdebug::print_reg_u8(uart, mmap_addr, 0x400);
}
unsafe fn start_next_dma() {
    unsafe {
        log_uart!("start_next_dma()");
        if DMA_QUEUE.is_empty() {
            log_uart!("DMA queue is empty. All transfers are completed!!");
            show_mmap_reg();
            return;
        }
    }

    if let Some(req) = DMA_QUEUE.pop_front() {
        CURRENT_DMA = Some(req);
        match CURRENT_DEVID {
            DeviceId::FmcCs0Idx | DeviceId::FmcCs1Idx => {
                if let Err(e) = start_dma_fmc_transfer(CURRENT_DMA.as_mut().unwrap()) {
                    log_uart!("Failed to start DMA transfer: {:?}", e);
                }
            }
            DeviceId::Spi0Cs0Idx
            | DeviceId::Spi1Cs0Idx
            | DeviceId::Spi1Cs1Idx
            | DeviceId::Spi0Cs1Idx => {
                if let Err(e) = start_dma_spi_transfer(CURRENT_DMA.as_mut().unwrap()) {
                    log_uart!("Failed to start DMA transfer: {:?}", e);
                }
            }
        }
    }
}

pub fn on_complete_dma(verify: bool, idx: usize, buf: &[u8]) {
    unsafe {
        log_uart!("on_complete_dma");
        if verify {
            if verify_dma_buffer_match(idx) {
                log_uart!("DMA test passed!!");
            } else {
                log_uart!("DMA test failed!!");
            }
        } else if let Some(uart) = UART_PTR.as_mut() {
            astdebug::print_array_u8(uart, buf);
        }
    }
}

// Start DMA transfer using the device
fn start_dma_spi_transfer(req: &mut DmaRequest) -> Result<(), ()> {
    unsafe {
        log_uart!("spi start_dma_transfer");
        let dev = match CURRENT_DEVID {
            DeviceId::Spi0Cs0Idx => SPI_DEV0_PTR.as_mut().unwrap(),
            _ => todo!(),
        };

        let result = match req.op {
            DmaOp::Read => dev.nor_read_data(u32::try_from(req.src_addr).unwrap(), req.dst_buf),
            DmaOp::ReadFast => {
                dev.nor_read_fast_4b_data(u32::try_from(req.src_addr).unwrap(), req.dst_buf)
            }
            DmaOp::Program => {
                dev.nor_page_program(u32::try_from(req.src_addr).unwrap(), req.dst_buf)
            }
            DmaOp::ProgramFast => {
                dev.nor_page_program_4b(u32::try_from(req.src_addr).unwrap(), req.dst_buf)
            }
        };

        result.map_err(|e| {
            log_uart!("start_dma_transfer failed at {:#x}: {:?}", req.src_addr, e);
        })
    }
}

// Start DMA transfer using the device
fn start_dma_fmc_transfer(req: &mut DmaRequest) -> Result<(), ()> {
    unsafe {
        log_uart!("fmc start_dma_transfer");
        let dev = match CURRENT_DEVID {
            DeviceId::FmcCs0Idx => FMC_DEV0_PTR.as_mut().unwrap(),
            DeviceId::FmcCs1Idx => FMC_DEV1_PTR.as_mut().unwrap(),
            _ => todo!(),
        };

        let result = match req.op {
            DmaOp::Read => dev.nor_read_data(u32::try_from(req.src_addr).unwrap(), req.dst_buf),
            DmaOp::ReadFast => {
                dev.nor_read_fast_4b_data(u32::try_from(req.src_addr).unwrap(), req.dst_buf)
            }
            DmaOp::Program => {
                dev.nor_page_program(u32::try_from(req.src_addr).unwrap(), req.dst_buf)
            }
            DmaOp::ProgramFast => {
                dev.nor_page_program_4b(u32::try_from(req.src_addr).unwrap(), req.dst_buf)
            }
        };

        result.map_err(|e| {
            log_uart!("start_dma_transfer failed at {:#x}: {:?}", req.src_addr, e);
        })
    }
}

#[must_use]
pub fn verify_dma_buffer_match(i: usize) -> bool {
    unsafe {
        let read = READ_BUFFERS[i].as_mut_slice(0, DMA_BUF_SIZE);
        let write = WRITE_BUFFERS[i].as_mut_slice(0, DMA_BUF_SIZE);

        if read != write {
            // Fast path failed. now scan for first mismatch for debug
            for (j, (&r, &w)) in read.iter().zip(write.iter()).enumerate() {
                if r != w {
                    log_uart!(
                        "Mismatch at buffer {}, index {}: read={:02x}, expected={:02x}",
                        i,
                        j,
                        r,
                        w
                    );
                    break;
                }
            }
            if let Some(uart) = UART_PTR.as_mut() {
                astdebug::print_array_u8(uart, read);
                astdebug::print_array_u8(uart, write);
            }
            return false;
        }
    }

    unsafe {
        log_uart!("All DMA buffers matched successfully!");
    }
    true
}

pub fn fill_random(buf: &mut [u8], seed: &mut u32) {
    for b in buf.iter_mut() {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 17;
        *seed ^= *seed << 5;
        *b = (*seed & 0xFF) as u8;
    }
}

pub fn fill_dma_buffer(op_req: DmaOp, random: bool) {
    let mut seed = 0xDEAD_FBEE;

    unsafe {
        for i in 0..MAX_DMA_CHAIN {
            let buf: &'static mut [u8] = match op_req {
                DmaOp::Read | DmaOp::ReadFast => READ_BUFFERS[i].as_mut_slice(0, DMA_BUF_SIZE),
                DmaOp::Program | DmaOp::ProgramFast => {
                    WRITE_BUFFERS[i].as_mut_slice(0, DMA_BUF_SIZE)
                }
            };

            buf.fill(0x0);

            if random {
                fill_random(buf, &mut seed);
            }
        }
    }
}
// Example use
#[allow(clippy::missing_safety_doc)]
pub unsafe fn dma_irq_chain_test(start_addrs: &[u32], op_req: DmaOp, verify: bool) {
    DMA_QUEUE.clear();

    log_uart!("irq_chain_test");
    for (i, &addr) in start_addrs.iter().enumerate() {
        if i >= MAX_DMA_CHAIN {
            log_uart!("Too many DMA addresses; max is {}", MAX_DMA_CHAIN);
            break;
        }

        // Select buffer based on operation type
        let buf: &'static mut [u8] = match op_req {
            DmaOp::Read | DmaOp::ReadFast => READ_BUFFERS[i].as_mut_slice(0, DMA_BUF_SIZE),
            DmaOp::Program | DmaOp::ProgramFast => WRITE_BUFFERS[i].as_mut_slice(0, DMA_BUF_SIZE),
        };
        let request = DmaRequest {
            src_addr: addr as usize,
            dst_buf: buf,
            len: DMA_BUF_SIZE,
            op: op_req,
            buf_idx: i,
            verify,
            on_complete: on_complete_dma,
        };
        DMA_QUEUE.push_back(request).unwrap();
        log_uart!("chaining {}", i);
    } //for
    start_next_dma();
}

pub fn test_fmc_dma_irq(uart: &mut UartController<'_>) {
    let fmc_spi = unsafe { &*ast1060_pac::Fmc::ptr() };
    let mut delay = DummyDelay {};

    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_FMC_QUAD);
    let fmc_data = SpiData::new();

    unsafe {
        // register interrupt
        /* irq init */
        UART_PTR = Some(core::mem::transmute::<
            &mut UartController<'_>,
            &'static mut UartController<'static>,
        >(uart));
        NVIC::unmask(ast1060_pac::Interrupt::fmc);

        FMC_CONTROLLER = Some(FmcController::new(
            fmc_spi,
            0,
            FMC_CONFIG,
            fmc_data,
            Some(UART_PTR.as_mut().unwrap()),
        ));

        log_uart!("==== FMC DEV0 DMA read Test====");
        let controller = FMC_CONTROLLER.as_mut().unwrap();
        let _ = controller.init();

        // You can now pass `fmc_ptr` into ChipSelectDevice or use it directly
        let nor_read_data: SpiNorData<'_> =
            spitest::nor_device_read_data(spitest::FMC_CS0_CAPACITY);
        let nor_write_data = spitest::nor_device_write_data(spitest::FMC_CS0_CAPACITY);

        let flash_device0 = ChipSelectDevice {
            bus: controller,
            cs: 0,
            spi_monitor: None,
        };
        FMC_DEVICE0 = Some(flash_device0);

        let dev0 = FMC_DEVICE0.as_mut().unwrap();
        //FMC_DEV0_PTR = dev0 as *mut _;
        FMC_DEV0_PTR = ptr::from_mut(dev0);

        // Wrap controller in a CS device (CS0)
        let _ = dev0.nor_read_init(&nor_read_data);
        let _ = dev0.nor_write_init(&nor_write_data);
        let start_addrs = [0x0000_0000, 0x0000_0100, 0x0000_0200, 0x0000_0300];

        CURRENT_DEVID = DeviceId::FmcCs0Idx;
        fill_dma_buffer(DmaOp::Read, true);
        dma_irq_chain_test(&start_addrs, DmaOp::Read, false);

        delay.delay_ns(8_000_000);

        log_uart!("==== FMC DEV1 DMA read & write Test====");
        let controller1 = FMC_CONTROLLER.as_mut().unwrap();
        let flash_device1 = ChipSelectDevice {
            bus: controller1, // reuse same ref
            cs: 1,
            spi_monitor: None,
        };

        FMC_DEVICE1 = Some(flash_device1);

        let dev1 = FMC_DEVICE1.as_mut().unwrap();
        let _ = dev1.nor_read_init(&nor_read_data);
        let _ = dev1.nor_write_init(&nor_write_data);

        FMC_DEV1_PTR = ptr::from_mut(dev1);

        //let start_addrs = [0x0000_0000, 0x0000_0100, 0x0000_0200, 0x0000_0300];
        //let start_addrs = [0x0000_0100];
        let read_only = true;
        CURRENT_DEVID = DeviceId::FmcCs1Idx;
        if read_only {
            fill_dma_buffer(DmaOp::Read, false);
            dma_irq_chain_test(&start_addrs, DmaOp::Read, false);
        } else {
            fill_dma_buffer(DmaOp::Program, true);
            let _ = dev1.nor_sector_erase(0x0000_0000);
            delay.delay_ns(8_000_000);
            // NOTE: DMA write has an issue in AST2600-Errata-11
            // DMA write ends before finish transfering data
            // work-around: add delay
            dma_irq_chain_test(&start_addrs, DmaOp::Program, false);
            dma_irq_chain_test(&start_addrs, DmaOp::Read, true);
        }
    } //unsafe

    delay.delay_ns(8_000_000);
}

pub fn test_spi_dma_irq(uart: &mut UartController<'_>) {
    let spi0 = unsafe { &*ast1060_pac::Spi::ptr() };
    let current_cs = 0;

    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_SPIM0_QUAD_DEFAULT);
    pinctrl::Pinctrl::apply_pinctrl_group(pinctrl::PINCTRL_SPI1_QUAD);
    let scu_qspi_mux: &mut [u32] =
        unsafe { core::slice::from_raw_parts_mut((spitest::SCU_BASE + 0xf0) as *mut u32, 4) };
    scu_qspi_mux[0] = 0x0000_fff0;

    let spi_data = SpiData::new();

    unsafe {
        // register interrupt
        // irq init
        UART_PTR = Some(core::mem::transmute::<
            &mut UartController<'_>,
            &'static mut UartController<'static>,
        >(uart));
        NVIC::unmask(ast1060_pac::Interrupt::spi);

        SPI_CONTROLLER = Some(SpiController::new(
            spi0,
            current_cs,
            spitest::SPI0_CONFIG,
            spi_data,
            Some(UART_PTR.as_mut().unwrap()),
        ));

        let controller = SPI_CONTROLLER.as_mut().unwrap();
        let _ = controller.init();
        log_uart!("==== SPI0 DEV0 DMA read Test====");
        // You can now pass `fmc_ptr` into ChipSelectDevice or use it directly
        let nor_read_data: SpiNorData<'_> =
            spitest::nor_device_read_4b_data(spitest::SPI_CS0_CAPACITY);
        let nor_write_data = spitest::nor_device_write_4b_data(spitest::SPI_CS0_CAPACITY);
        let spi_monitor0 = start_static_spim0();

        let flash_device0 = ChipSelectDevice {
            bus: controller,
            cs: 0,
            spi_monitor: Some(spi_monitor0),
        };

        SPI_DEVICE0 = Some(flash_device0);
        let dev0 = SPI_DEVICE0.as_mut().unwrap();
        SPI_DEV0_PTR = ptr::from_mut(dev0);

        // Wrap controller in a CS device (CS0)
        let _ = dev0.nor_read_init(&nor_read_data);
        let _ = dev0.nor_write_init(&nor_write_data);

        let start_addrs = [0x0000_0000, 0x0000_0100, 0x0000_0200, 0x0000_0300];
        //let start_addrs = [0x0000_0100];
        CURRENT_DEVID = DeviceId::Spi0Cs0Idx;
        fill_dma_buffer(DmaOp::ReadFast, false);
        dma_irq_chain_test(&start_addrs, DmaOp::ReadFast, false);
    } //unsafe
}

static ALLOW_CMDS: [u8; 27] = [
    0x03, 0x13, 0x0b, 0x0c, 0x6b, 0x6c, 0x01, 0x05, 0x35, 0x06, 0x04, 0x20, 0x21, 0x9f, 0x5a, 0xb7,
    0xe9, 0x32, 0x34, 0xd8, 0xdc, 0x02, 0x12, 0x15, 0x31, 0x3b, 0x3c,
];

static READ_BLOCKED_REGIONS: [RegionInfo; 1] = [RegionInfo {
    start: 0x0400_0000,
    length: 0x0002_0000,
}];

static WRITE_BLOCKED_REGIONS: [RegionInfo; 1] = [RegionInfo {
    start: 0x0000_0000,
    length: 0x0800_0000,
}];

pub fn start_static_spim0() -> &'static mut SpiMonitor<Spipf> {
    unsafe {
        SPI_MONITOR0 = Some(SpiMonitor::new(
            true,
            SpimExtMuxSel::SpimExtMuxSel1,
            &ALLOW_CMDS,
            u8::try_from(ALLOW_CMDS.len()).unwrap(),
            &READ_BLOCKED_REGIONS,
            u8::try_from(READ_BLOCKED_REGIONS.len()).unwrap(),
            &WRITE_BLOCKED_REGIONS,
            u8::try_from(WRITE_BLOCKED_REGIONS.len()).unwrap(),
        ));

        let monitor = SPI_MONITOR0.as_mut().unwrap();
        monitor.spim_sw_rst();
        monitor.aspeed_spi_monitor_init();

        monitor
    }
}
