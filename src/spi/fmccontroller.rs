use super::*;
use crate::{common::DummyDelay, spi::norflash::SpiNorData, uart::UartController};
use crate::{dbg};
use embedded_hal::{
    delay::DelayNs,
    spi::{ErrorKind, ErrorType, SpiBus},
};

pub struct FmcController<'a> {
    regs: &'static ast1060_pac::fmc::RegisterBlock,
    current_cs: usize,
    spi_config: SpiConfig,
    spi_data: SpiData,
    pub dbg_uart: Option<&'a mut UartController<'a>>,
}

macro_rules! cs_ctrlreg_w {
    ($this:expr, $cs:expr, $value:expr) => {{
        if $cs == 0 {
            $this.regs.fmc010().write(|w| unsafe { w.bits($value) });
        } else if $cs == 1 {
            $this.regs.fmc014().write(|w| unsafe { w.bits($value) });
        }
    }};
}

macro_rules! cs_ctrlreg_r {
    ($this:expr, $cs:expr) => {{
        if $cs == 0 {
            $this.regs.fmc010().read().bits()
        } else if $cs == 1 {
            $this.regs.fmc014().read().bits()
        } else {
            0
        }
    }};
}

impl<'a> FmcController<'a> {
    pub fn new(
        regs: &'static ast1060_pac::fmc::RegisterBlock,
        current_cs: usize,
        spi_config: SpiConfig,
        spi_data: SpiData,
        dbg_uart: Option<&'a mut UartController<'a>>,
    ) -> Self {
        FmcController {
            regs,
            current_cs,
            spi_config,
            spi_data,
            dbg_uart,
        }
    }

    pub fn init(&mut self) -> Result<(), i32> {
        dbg!(self, "fmcController: init()");

        for cs in 0..self.spi_config.max_cs {
            self.regs.fmc000().modify(|r, w| unsafe {
                let current = r.bits();
                w.bits(current | (1 << (16 + cs)))
            });

            self.spi_data.cmd_mode[cs].user = ASPEED_SPI_USER;
        }

        self.spi_data.hclk = get_hclock_rate()?;

        self.decode_range_pre_init();

        if self.spi_config.mux_ctrl.master_idx != 0
            && (self.spi_config.mux_ctrl.spim_output_base == 0
                || !self.spi_config.mux_ctrl.spi_monitor_common_ctrl)
        {
            return Err(-1); // replace with EINVAL
        }

        Ok(())
    }
    fn decode_range_pre_init(&mut self) {
        let mut max_cs = self.spi_config.max_cs;
        let mut unit_sz = ASPEED_SPI_SZ_2M;
        dbg!(self, "rang pre - init()");
        if self.spi_config.mux_ctrl.master_idx != 0 {
            max_cs = 1;
            unit_sz = ASPEED_SPI_SZ_256M;
        }

        if self.spi_config.pure_spi_mode_only {
            unit_sz = ASPEED_SPI_SZ_256M / self.spi_config.max_cs as u32;
            unit_sz &= !(ASPEED_SPI_SZ_2M - 1);
        }

        let mut pre_end_addr = 0;
        for cs in 0..max_cs {
            let start_addr = if cs == 0 {
                self.spi_config.mmap_base
            } else {
                pre_end_addr
            };
            let end_addr = start_addr + unit_sz - 1;

            if self.spi_config.mmap_base + ASPEED_SPI_SZ_256M <= end_addr {
                if cs == 0 {
                    self.regs.fmc030().write(|w| unsafe { w.bits(0) });
                } else if cs == 1 {
                    self.regs.fmc034().write(|w| unsafe { w.bits(0) });
                }
                continue;
            }

            let seg_val = self.segment_compose(start_addr, end_addr);
            if cs == 0 {
                self.regs.fmc030().write(|w| unsafe { w.bits(seg_val) });
            } else if cs == 1 {
                self.regs.fmc034().write(|w| unsafe { w.bits(seg_val) });
            }

            self.spi_data.decode_addr[cs].start = start_addr;
            self.spi_data.decode_addr[cs].len = unit_sz;
            pre_end_addr = end_addr + 1;
        }
    }

    fn segment_start(&self, reg_val: u32) -> u32 {
        (reg_val & 0x0ff8) << 16
    }
    fn segment_end(&self, reg_val: u32) -> u32 {
        (reg_val & 0x0ff80000) | 0x0007_ffff
    }
    fn segment_compose(&self, start: u32, end: u32) -> u32 {
        ((((start >> 19) << 19) >> 16) & 0xfff8) | (((end >> 19) << 19) & 0xfff80000)
    }

    fn decode_range_reinit(&mut self, flash_sz: u32) {
        let mut decode_sz_arr = [0u32; ASPEED_MAX_CS];
        let mut total_decode_range = 0;
        let mut pre_end_addr = 0;
        dbg!(self, "rang reinit() flash size: {}", flash_sz);
        for cs in 0..self.spi_config.max_cs as usize {
            let tmp = if cs == 0 {
                self.regs.fmc030().read().bits()
            } else if cs == 1 {
                self.regs.fmc034().read().bits()
            } else {
                0
            };

            decode_sz_arr[cs] = if tmp == 0 {
                0
            } else {
                self.segment_end(tmp) - self.segment_start(tmp) + 1
            };
            total_decode_range += decode_sz_arr[cs];
            dbg!(self, "decode_sz_arr[{}]: {}", cs, decode_sz_arr[cs]);
        } //for

        dbg!(self, "total range: {}", total_decode_range);

        // prepare new decode sz array
        if total_decode_range - decode_sz_arr[self.current_cs] + flash_sz <= ASPEED_SPI_SZ_256M {
            decode_sz_arr[self.current_cs] = flash_sz;
        } else {
            return;
        }

        // 3. Apply new decode config
        for cs in 0..self.spi_config.max_cs as usize {
            if decode_sz_arr[cs] == 0 {
                continue;
            }

            let start_addr = if cs == 0 {
                self.spi_config.mmap_base
            } else {
                pre_end_addr
            };

            let end_addr = start_addr + decode_sz_arr[cs] - 1;

            let value = self.segment_compose(start_addr, end_addr);
            if cs == 0 {
                self.regs.fmc030().write(|w| unsafe { w.bits(value) });
            } else if cs == 1 {
                self.regs.fmc034().write(|w| unsafe { w.bits(value) });
            }

            self.spi_data.decode_addr[cs].start = start_addr;

            if cs == self.current_cs {
                self.spi_data.decode_addr[cs].len = flash_sz;
            }

            pre_end_addr = end_addr + 1;
        }
    }

    fn spi_nor_read_init(&mut self, cs: usize, op_info: &SpiNorData) {
        dbg!(
            self,
            "spi_nor_read_init() cs:{}  master_idx: {}",
            cs,
            self.spi_config.mux_ctrl.master_idx
        );

        if self.spi_config.mux_ctrl.master_idx == 0 && self.spi_config.pure_spi_mode_only == false {
            self.decode_range_reinit(op_info.data_len);
        }
        let io_mode = spi_io_mode(op_info.mode);
        let dummy = spi_cal_dummy_cycle(
            get_addr_buswidth(op_info.mode as u32) as u32,
            op_info.dummy_cycle,
        );
        let read_cmd = (io_mode | (((op_info.opcode as u32) & 0xff) << 16) | (dummy as u32))
            | ASPEED_SPI_NORMAL_READ;
        self.spi_data.cmd_mode[cs].normal_read = read_cmd;
        dbg!(
            self,
            "cs: {:08x}, io_mode: {:08x}, dummy: {:08x}, op: {:08x}, normal read: {:08x}",
            cs,
            io_mode,
            dummy,
            op_info.opcode,
            read_cmd
        );

        cs_ctrlreg_w!(self, cs, read_cmd);
        if op_info.addr_len == 4 {
            self.regs.fmc004().modify(|r, w| unsafe {
                let current = r.bits();
                w.bits(current | (0x11 << cs))
            });
        }
        if matches!(self.spi_config.ctrl_type, CtrlType::HostSpi) {
            self.regs.fmc06c().modify(|r, w| unsafe {
                let mut current = r.bits();
                if op_info.addr_len == 4 {
                    current = (current & 0xffff_00ff) | (op_info.opcode << 8);
                } else {
                    current = (current & 0xffff_ff00) | op_info.opcode;
                }

                w.bits((current & 0x0fff_ffff) | spi_io_mode(op_info.mode))
            });
        }
        self.timing_calibration(cs);
    }

    fn spi_nor_write_init(&mut self, cs: usize, op_info: &SpiNorData) {
        let io_mode = spi_io_mode(op_info.mode);
        let dummy = 0;
        let write_cmd =
            (io_mode | (((op_info.opcode as u32) & 0xff) << 16) | dummy) | ASPEED_SPI_NORMAL_WRITE;
        self.spi_data.cmd_mode[cs].normal_write = write_cmd;
    }

    pub fn timing_calibration(&mut self, cs: usize) {
        let max_freq = self.spi_config.frequency;
        if self.spi_config.timing_calibration_disabled {
            dbg!(self, "Timing calibration disabled by config");
            self.apply_clock_settings(cs, max_freq);
            return;
        }

        // Read current timing control register for CS, skip if non-zero (already calibrated)
        let reg_val = if cs == 0 {
            self.regs.fmc094().read().bits()
        } else if cs == 1 {
            self.regs.fmc098().read().bits()
        } else {
            return;
        };

        if reg_val != 0 {
            dbg!(self, "Calibration already executed for cs {}", cs);
            self.apply_clock_settings(cs, max_freq);
            return;
        }

        // Skip if mux master_idx != 0 and cs != 0 (as per original logic)
        if self.spi_config.mux_ctrl.master_idx != 0 && cs != 0 {
            self.apply_clock_settings(cs, max_freq);
            return;
        }

        // SPI Monitor MUX config (conditional)
        #[cfg(feature = "spi_monitor")]
        {
            if self.spi_config.mux_ctrl.master_idx != 0 {
                // Setup monitor mux here - you will need to define spim_scu_ctrl_set
                spim_scu_ctrl_set(
                    self.spi_config.mux_ctrl.spi_monitor_common_ctrl,
                    1 << 3,
                    (self.spi_config.mux_ctrl.master_idx - 1) << 3,
                );
                spim_scu_ctrl_set(
                    self.spi_config.mux_ctrl.spi_monitor_common_ctrl,
                    0x7,
                    self.spi_config.mux_ctrl.spim_output_base + cs as u32,
                );
            }

            if let Some(pre_config) = &self.spi_data.aspeed_spim_proprietary_pre_config {
                pre_config();
            }
        }

        // Read ctrl register to clear frequency bits
        let mut reg_val = cs_ctrlreg_r!(self, cs);

        reg_val &= !SPI_CTRL_FREQ_MASK;

        cs_ctrlreg_w!(self, cs, reg_val);

        // Allocate buffers (replace with static buffers or heap allocator)
        const SPI_CALIB_LEN: usize = 256; // Use actual length needed
        let mut check_buf = [0u8; SPI_CALIB_LEN];
        let mut calib_res = [0u8; 6 * 17];

        // Copy flash calibration data from mapped address + offset
        unsafe {
            let flash_ptr = self.spi_data.decode_addr[cs].start as *const u8;
            core::ptr::copy_nonoverlapping(
                flash_ptr.add(self.spi_config.timing_calibration_start_off as usize),
                check_buf.as_mut_ptr(),
                SPI_CALIB_LEN,
            );
        }

        // Skip if flash data is monotonous (implement spi_calibration_enable equivalent)
        if !spi_calibration_enable(&check_buf) {
            dbg!(self, "Flash data is monotonous, skip calibration");
            self.apply_clock_settings(cs, max_freq);
            return;
        }

        // Get golden checksum for reference
        let gold_checksum = self.aspeed_spi_dma_checksum(0, 0);

        let hclk_masks = [7u32, 14, 6, 13];

        let mut final_delay: u32 = 0;
        let mut freq_to_use = max_freq;

        'outer: for (i, &mask) in hclk_masks.iter().enumerate() {
            if freq_to_use < self.spi_data.hclk / (i as u32 + 2) {
                //log::debug!("Skipping frequency {}", self.spi_data.hclk / (i as u32 + 2));
                continue;
            }
            freq_to_use = self.spi_data.hclk / (i as u32 + 2);

            let checksum = self.aspeed_spi_dma_checksum(mask, 0);
            let pass = checksum == gold_checksum;
            dbg!(
                self,
                "HCLK/{}, no timing compensation: {}",
                i + 2,
                if pass { "PASS" } else { "FAIL" }
            );

            // Clear calibration results buffer
            calib_res.fill(0);

            for hcycle in 0..=5 {
                dbg!(self, "Delay Enable : hcycle {}", hcycle);
                for delay_ns in 0..=0xf {
                    let reg_val = mask | (1 << 3) | hcycle | (delay_ns << 4);
                    let checksum = self.aspeed_spi_dma_checksum(mask, reg_val);
                    let pass = checksum == gold_checksum;
                    let index = (hcycle * 17 + delay_ns) as usize;
                    calib_res[index] = pass as u8;
                    dbg!(
                        self,
                        "HCLK/{}, {} HCLK cycle, {} delay_ns : {}",
                        i + 2,
                        hcycle,
                        delay_ns,
                        if pass { "PASS" } else { "FAIL" }
                    );
                }
            }

            let calib_point = get_mid_point_of_longest_one(&calib_res);
            if calib_point < 0 {
                dbg!(self, "Cannot get good calibration point.");
                continue;
            }
            let hcycle: u32 = (calib_point / 17) as u32;
            let delay_ns: u32 = (calib_point % 17) as u32;

            dbg!(self, "Final hcycle: {}, delay_ns: {}", hcycle, delay_ns);
            final_delay = ((1 << 3) | hcycle | (delay_ns << 4)) << (i * 8);
            self.regs.fmc084().write(|w| unsafe { w.bits(final_delay) });
            break 'outer;
        }

        // Apply clock division and set SPI clock frequency
        self.apply_clock_settings(cs, freq_to_use);

        #[cfg(feature = "spi_monitor")]
        {
            if let Some(post_config) = &self.spi_data.aspeed_spim_proprietary_post_config {
                post_config();
            }
            if self.spi_config.mux_ctrl.master_idx != 0 {
                spim_scu_ctrl_clear(self.spi_config.mux_ctrl.spi_monitor_common_ctrl, 0xf);
            }
        }
    }

    fn apply_clock_settings(&mut self, cs: usize, max_freq: u32) {
        let hclk_div = aspeed_get_spi_freq_div(self.spi_data.hclk, max_freq);

        let mut reg_val = cs_ctrlreg_r!(self, cs);
        reg_val = (reg_val & !SPI_CTRL_FREQ_MASK) | hclk_div;
        cs_ctrlreg_w!(self, cs, reg_val);

        self.spi_data.cmd_mode[cs].normal_read =
            (self.spi_data.cmd_mode[cs].normal_read & !SPI_CTRL_FREQ_MASK) | hclk_div;

        self.spi_data.cmd_mode[cs].normal_write =
            (self.spi_data.cmd_mode[cs].normal_write & !SPI_CTRL_FREQ_MASK) | hclk_div;

        self.spi_data.cmd_mode[cs].user =
            (self.spi_data.cmd_mode[cs].user & !SPI_CTRL_FREQ_MASK) | hclk_div;

        dbg!(
            self,
            "Configured SPI frequency to {} MHz",
            max_freq / 1_000_000
        );
    }

    pub fn aspeed_spi_dma_checksum(&mut self, div: u32, delay: u32) -> u32 {
        let data = &self.spi_data;
        let config = &self.spi_config;

        let cs = self.current_cs as usize;
        // Request DMA access

        self.regs
            .fmc080()
            .write(|w| unsafe { w.bits(SPI_DMA_GET_REQ_MAGIC) });
        if self.regs.fmc080().read().bits() & SPI_DMA_REQUEST != 0 {
            while self.regs.fmc080().read().bits() & &SPI_DMA_GRANT == 0 {}
        }

        // Set DMA flash start address
        let flash_addr = data.decode_addr[cs as usize].start + config.timing_calibration_start_off;
        self.regs.fmc084().write(|w| unsafe { w.bits(flash_addr) });
        // Set DMA length
        self.regs
            .fmc08c()
            .write(|w| unsafe { w.bits(SPI_CALIB_LEN) });
        // Configure DMA control register
        let ctrl_val = SPI_DMA_ENABLE
            | SPI_DMA_CALC_CKSUM
            | SPI_DMA_CALIB_MODE
            | (delay << 8)
            | ((div & 0xf) << 16);

        self.regs.fmc080().write(|w| unsafe { w.bits(ctrl_val) });
        // Wait until DMA done
        while self.regs.fmc008().read().bits() & SPI_DMA_STATUS == 0 {}

        // Read checksum result
        let checksum = self.regs.fmc090().read().bits();
        // Clear DMA control and discard request
        self.dma_disable();

        checksum
    }
    fn spi_nor_transceive_user(&mut self, op_info: &mut SpiNorData) {
        let cs: usize = self.current_cs as usize;
        let dummy = [0u8; 12];
        let start_ptr = self.spi_data.decode_addr[cs].start as *mut u32;
        dbg!(
            self,
            "nor_transceive_user cs: {}, ahb start: {:08x}",
            cs as u32,
            self.spi_data.decode_addr[cs].start
        );

        // Handle SPI monitor setup (if enabled)
        #[cfg(feature = "spi_monitor")]
        {
            if config.mux_ctrl.master_idx != 0 {
                cs = 0;
                spim_scu_ctrl_set(
                    config.mux_ctrl.spi_monitor_common_ctrl,
                    1 << 3,
                    (config.mux_ctrl.master_idx - 1) << 3,
                );
                spim_scu_ctrl_set(
                    config.mux_ctrl.spi_monitor_common_ctrl,
                    0x7,
                    config.mux_ctrl.spim_output_base + ctx.config.slave,
                );
            }

            if let Some(pre_config) = &data.aspeed_spim_proprietary_pre_config {
                pre_config();
            }
        }

        // Send command
        let cmd_mode = self.spi_data.cmd_mode[cs].user
            | super::spi_io_mode_user(super::get_cmd_buswidth(op_info.mode as u32) as u32);
        cs_ctrlreg_w!(self, cs, cmd_mode);
        dbg!(self, "write opcode/cmd: 0x{:08x}", op_info.opcode);
        unsafe { super::spi_write_data(start_ptr, &[op_info.opcode.try_into().unwrap()]) };

        // Send address
        let addr_mode = self.spi_data.cmd_mode[cs].user
            | super::spi_io_mode_user(super::get_addr_buswidth(op_info.mode as u32) as u32);
        cs_ctrlreg_w!(self, cs, addr_mode);

        let mut addr = op_info.addr;
        if op_info.addr_len == 3 {
            addr <<= 8;
        }

        let addr_bytes = addr.to_be_bytes();
        unsafe { super::spi_write_data(start_ptr, &addr_bytes[..op_info.addr_len as usize]) };

        // Dummy cycles
        let bus_width: u8 = super::get_addr_buswidth(op_info.mode as u32);
        let dummy_len: u8 = (op_info.dummy_cycle / (8 / bus_width as u32))
            .try_into()
            .unwrap();
        dbg!(self, "write dummy len: 0x{:08x}", dummy_len);
        unsafe { super::spi_write_data(start_ptr, &dummy[..dummy_len as usize]) };

        // Data transfer
        let data_mode = self.spi_data.cmd_mode[cs].user
            | spi_io_mode_user(super::get_data_buswidth(op_info.mode as u32) as u32);
        cs_ctrlreg_w!(self, cs, data_mode);

        if op_info.data_direct == super::SPI_NOR_DATA_DIRECT_READ {
            unsafe { spi_read_data(start_ptr, op_info.rx_buf) };
        } else {
            unsafe { spi_write_data(start_ptr, op_info.tx_buf) };
        }

        #[cfg(feature = "spi_monitor")]
        {
            if let Some(post_config) = &self.spi_data.aspeed_spim_proprietary_post_config {
                post_config();
            }
            if self.spi_config.mux_ctrl.master_idx != 0 {
                spim_scu_ctrl_clear(self.spi_config.mux_ctrl.spi_monitor_common_ctrl, 0xf);
            }
        }
    }

    // Helper wrappers would be defined for spi_write_data, spi_read_data, io_mode_user, etc.

    pub fn spi_nor_transceive(&mut self, op_info: &mut SpiNorData) {
        dbg!(self, "spi_nor_transceive()...");

        #[cfg(feature = "spi_dma")]
        {
            dbg!(self, "spi dma enabled rx_len:{}", op_info.rx_buf.len());
            let addr_aligned = op_info.addr % 4 == 0;

            if op_info.data_direct == SPI_NOR_DATA_DIRECT_READ {
                let buf_aligned = (op_info.rx_buf.as_ptr() as usize) % 4 == 0;
                let use_dma = !self.spi_config.pure_spi_mode_only
                    && op_info.rx_buf.len() > SPI_DMA_TRIGGER_LEN as usize
                    && addr_aligned
                    && buf_aligned;
                dbg!(self, "read dma");
                dbg!(
                    self,
                    "use_dma{} rx len: {}, addr_aligned: {}, buf_aligned: {}",
                    use_dma,
                    op_info.rx_buf.len(),
                    addr_aligned,
                    buf_aligned
                );
                if use_dma {
                    if let Err(e) = self.read_dma(op_info) {
                        dbg!(self, "DMA read Timeout");
                    }
                } else {
                    self.spi_nor_transceive_user(op_info);
                }
            } else if op_info.data_direct == SPI_NOR_DATA_DIRECT_WRITE {
                dbg!(self, "write dma");
                #[cfg(feature = "spi_dma_write")]
                {
                    let buf_aligned = (op_info.tx_buf.as_ptr() as usize) % 4 == 0;
                    let use_dma = !self.spi_config.pure_spi_mode_only
                        && op_info.tx_buf.len() > SPI_DMA_TRIGGER_LEN as usize
                        && addr_aligned
                        && buf_aligned;
                    if use_dma {
                        if let Err(e) = self.write_dma(op_info) {
                            dbg!(self, "DMA write Timeout");
                        }
                    } else {
                        self.spi_nor_transceive_user(op_info);
                    }
                } //spi dma write
                #[cfg(not(feature = "spi_dma_write"))]
                self.spi_nor_transceive_user(op_info);
            } //write
        } // dma

        #[cfg(not(feature = "spi_dma"))]
        {
            dbg!(self, "no dma transceive user");
            self.spi_nor_transceive_user(op_info);
        }
    }

    fn dma_disable(&mut self) {
        self.regs.fmc080().write(|w| unsafe { w.bits(0x0) });

        self.regs
            .fmc080()
            .write(|w| unsafe { w.bits(SPI_DMA_DISCARD_REQ_MAGIC) });
    }

    fn wait_for_dma_completion(&mut self, timeout: u32) -> Result<(), &'static str> {
        let mut delay = DummyDelay {};
        let mut to = timeout;
        //wait for_dma done
        while self.regs.fmc008().read().dmastatus().is_dma_finish() == false {
            delay.delay_ns(500);
            to -= 1;

            if to == 0 {
                self.dma_disable();
                return Err("ERROR::SPI DMA wait timeout");
            }
        }
        self.dma_disable();
        Ok(())
    }
    fn dma_irq_disable(&mut self) {
        // Enable the DMA interrupt bit (bit 3)
        self.regs.fmc008().modify(|_, w| w.dmaintenbl().clear_bit());
    }

    fn dma_irq_enable(&mut self) {
        // Enable the DMA interrupt bit (bit 3)
        self.regs.fmc008().modify(|_, w| w.dmaintenbl().set_bit());
    }
    fn dbg_fmc_dma(&mut self){
        dbg!(self, "reg 0x80: {:08x}", self.regs.fmc080().read().bits());
        dbg!(self, "reg 0x84: {:08x}", self.regs.fmc084().read().bits());
        dbg!(self, "reg 0x88: {:08x}", self.regs.fmc088().read().bits());
        dbg!(self, "reg 0x8c: {:08x}", self.regs.fmc08c().read().bits());
    }
    pub fn read_dma(&mut self, op: &mut SpiNorData) -> Result<(), &'static str> {
        let cs = self.current_cs;
        dbg!(self, "##### read dma ####");
        dbg!(self, "device size: 0x{:08x} dv start: 0x{:08x}, read len: 0x{:08x}, rx_buf:0x{:08x} op addr: 0x{:08x}",
         self.spi_data.decode_addr[cs].len,
         self.spi_data.decode_addr[cs].start,
        op.rx_buf.len(),
        (op.rx_buf.as_ptr() as u32),
        op.addr);

        // Length check
        if op.rx_buf.len() > self.spi_data.decode_addr[cs].len.try_into().unwrap() {
            return Err("Invalid read length");
        }

        // Alignment check
        if (op.addr % 4 != 0) || ((op.rx_buf.as_ptr() as u32) % 4 != 0) {
            return Err("Address or buffer not 4-byte aligned");
        }
        // Construct control value
        let mut ctrl = self.spi_data.cmd_mode[cs].normal_read & SPI_CTRL_FREQ_MASK;
        ctrl |= spi_io_mode(op.mode);
        ctrl |= (op.opcode as u32) << 16;

        // Calculate dummy cycle bits
        let bus_width = get_addr_buswidth(op.mode as u32);
        let dummy = (op.dummy_cycle / (8 / bus_width) as u32) << 6;
        ctrl |= dummy;
        ctrl |= ASPEED_SPI_NORMAL_READ;

        // Write to CSx control
        cs_ctrlreg_w!(self, cs, ctrl);

        self.regs
            .fmc080()
            .write(|w| unsafe { w.bits(SPI_DMA_GET_REQ_MAGIC) });
        // Wait for grant (busy wait)
        if self.regs.fmc080().read().bits() & SPI_DMA_REQUEST == SPI_DMA_REQUEST {
            while self.regs.fmc080().read().bits() & SPI_DMA_GRANT != SPI_DMA_GRANT {}
        }
     
        let flash_start = self.spi_data.decode_addr[cs].start + op.addr - SPI_DMA_FLASH_MAP_BASE;
        dbg!(self, "flash start: 0x{:08x}", flash_start);
        // DMA flash and RAM address
        self.regs.fmc084().write(|w| unsafe { w.bits(flash_start) });
        let ram_addr = (op.rx_buf.as_ptr() as usize) + SPI_DMA_RAM_MAP_BASE as usize;
        dbg!(self, "ram start: 0x{:08x}", ram_addr);
        self.regs
            .fmc088()
            .write(|w| unsafe { w.bits(ram_addr as u32) });
        let read_length = op.rx_buf.len() - 1;
        self.regs
            .fmc08c()
            .write(|w| unsafe { w.bits(read_length as u32) });

        // Enable IRQ
        //self.dma_irq_enable();

        // Start DMA
        self.regs.fmc080().modify(|_, w| {
            w.dmaenbl().enable_dma_operation();
            w.dmadirection()
                .read_flash_move_from_flash_to_external_memory()
        });

        dbg!(self, "start wait for dma");
        self.wait_for_dma_completion(SPI_DMA_TIMEOUT)
    }

    fn write_dma(&mut self, op: &mut SpiNorData) -> Result<(), &'static str> {
        let cs = self.current_cs;
        dbg!(self, "##### write_dma ####");
        // Check alignment and bounds
        if op.addr % 4 != 0 || (op.tx_buf.as_ptr() as usize) % 4 != 0 {
            return Err("Address or buffer is not 4-byte aligned");
        }
        if op.tx_buf.len() > self.spi_data.decode_addr[cs].len.try_into().unwrap() {
            return Err("Write length exceeds decode region");
        }

        // Set command register
        let mut ctrl_reg = self.spi_data.cmd_mode[cs].normal_write & SPI_CTRL_FREQ_MASK;
        let bus_width = get_addr_buswidth(op.mode as u32);
        ctrl_reg |= spi_io_mode(op.mode); // you must implement this
        ctrl_reg |= (op.opcode as u32) << 16;
        ctrl_reg |= (op.dummy_cycle / (8 / bus_width) as u32) << 6;
        ctrl_reg |= ASPEED_SPI_NORMAL_WRITE;

        cs_ctrlreg_w!(self, cs, ctrl_reg);

        // Write DMA control (REQ magic)
        self.regs
            .fmc080()
            .write(|w| unsafe { w.bits(SPI_DMA_GET_REQ_MAGIC) });
        if self.regs.fmc080().read().bits() & SPI_DMA_REQUEST == SPI_DMA_REQUEST {
            while self.regs.fmc080().read().bits() & SPI_DMA_GRANT != SPI_DMA_GRANT {}
        }

        // Program addresses
        self.regs.fmc084().write(|w| unsafe {
            w.bits(self.spi_data.decode_addr[cs].start + op.addr - SPI_DMA_FLASH_MAP_BASE)
        });
        self.regs.fmc088().write(|w| unsafe {
            w.bits((op.tx_buf.as_ptr() as usize as u32) + SPI_DMA_RAM_MAP_BASE)
        });
        self.regs
            .fmc08c()
            .write(|w| unsafe { w.bits(op.tx_buf.len() as u32 - 1) });

        // Enable DMA IRQ if needed
        // self.enable_dma_irq(); // implement if necessary
        // Start DMA with write direction
        self.regs.fmc080().modify(|_, w| {
            w.dmaenbl().enable_dma_operation();
            w.dmadirection()
                .write_flash_move_from_external_memory_to_flash()
        });

        self.wait_for_dma_completion(SPI_DMA_TIMEOUT)
    }
}

impl<'a> ErrorType for FmcController<'a> {
    type Error = ErrorKind;
}

impl<'a> SpiBus<u8> for FmcController<'a> {
    // we only use mmap for all transaction
    fn read(&mut self, mut buffer: &mut [u8]) -> Result<(), Self::Error> {
        let ahb_addr = self.spi_data.decode_addr[self.current_cs].start as usize as *const u32;
        unsafe { spi_read_data(ahb_addr, &mut buffer) };
        Ok(())
    }

    fn write(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
        let ahb_addr = self.spi_data.decode_addr[self.current_cs].start as usize as *mut u32;
        unsafe { spi_write_data(ahb_addr, &buffer) };
        Ok(())
    }

    fn transfer(&mut self, rd_buffer: &mut [u8], wr_buffer: &[u8]) -> Result<(), Self::Error> {
        let cs = self.current_cs;
        if !wr_buffer.is_empty() {
            let ahb_addr = self.spi_data.decode_addr[cs].start as usize as *mut u32;
            unsafe { spi_write_data(ahb_addr, &wr_buffer) };
        }
        cortex_m::asm::delay(2);
        if !rd_buffer.is_empty() {
            let ahb_addr = self.spi_data.decode_addr[cs].start as usize as *const u32;
            // Read RX buffer
            unsafe { super::spi_read_data(ahb_addr, rd_buffer) };
        }
        Ok(())
    }

    fn transfer_in_place(&mut self, buffer: &mut [u8]) -> Result<(), Self::Error> {
        todo!()
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        todo!()
    }
}

impl<'a> SpiBusWithCs for FmcController<'a> {
    fn select_cs(&mut self, cs: usize) {
        let user_reg = self.spi_data.cmd_mode[cs].user;

        self.current_cs = cs;
        cs_ctrlreg_w!(self, cs, user_reg | ASPEED_SPI_USER_INACTIVE);
        cs_ctrlreg_w!(self, cs, user_reg);
        dbg!(self, "activate cs:{}", cs as u32);
    }

    fn deselect_cs(&mut self, cs: usize) {
        let user_reg = self.spi_data.cmd_mode[cs].user;

        cs_ctrlreg_w!(self, cs, user_reg | ASPEED_SPI_USER_INACTIVE);
        cs_ctrlreg_w!(self, cs, self.spi_data.cmd_mode[cs].normal_read);
        dbg!(self, "deactivate cs:{}", cs as u32);
        dbg!(
            self,
            "normal read:{:08x}",
            self.spi_data.cmd_mode[cs].normal_read
        );
    }

    fn nor_transfer(&mut self, op_info: &mut SpiNorData) {
        self.spi_nor_transceive(op_info);
    }

    fn nor_read_init(&mut self, cs: usize, op_info: &SpiNorData) {
        self.spi_nor_read_init(cs, op_info);
    }

    fn nor_write_init(&mut self, cs: usize, op_info: &SpiNorData) {
        self.spi_nor_write_init(cs, op_info);
    }

    fn get_device_info(&mut self, cs: usize) -> (u32, u32) {
        (
            self.spi_data.decode_addr[cs].len,
            self.spi_config.write_block_size,
        )
    }
}
