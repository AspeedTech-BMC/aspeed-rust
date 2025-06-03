//! GPIO pins

use core::marker::PhantomData;
use ast1060_pac::{Gpio, Scu};
use embedded_hal::digital::{InputPin, OutputPin, StatefulOutputPin};

/// All input modes implement this
pub trait InputMode {}

/// All output modes implement this
pub trait OutputMode {}

/// OpenDrain modes implement this
pub trait OpenDrainMode {
    /// Is pull-up enabled
    fn pup() -> bool;
}

/// Input mode (type state)
pub struct Input<MODE>
where
    MODE: InputMode,
{
    _mode: PhantomData<MODE>,
}

/// Sub-mode of Input: Floating input (type state)
pub struct Floating;
impl InputMode for Floating {}
impl OpenDrainMode for Floating {
    /// Pull-up is not enabled
    fn pup() -> bool {
        false
    }
}

/// Sub-mode of Input: Pulled down input (type state)
pub struct PullDown;
impl InputMode for PullDown {}

/// Sub-mode of Input: Pulled up input (type state)
pub struct PullUp;
impl InputMode for PullUp {}
impl OpenDrainMode for PullUp {
    /// Pull-up is enabled
    fn pup() -> bool {
        true
    }
}

/// Tri-state
pub struct Tristate;

/// Output mode (type state)
pub struct Output<MODE>
where
    MODE: OutputMode,
{
    _mode: PhantomData<MODE>,
}

/// Sub-mode of Output: Push pull output (type state for Output)
pub struct PushPull;
impl OutputMode for PushPull {}
impl OutputMode for PullDown {}
impl OutputMode for PullUp {}

/// Sub-mode of Output: Open drain output (type state for Output)
pub struct OpenDrain<ODM>
where
    ODM: OpenDrainMode,
{
    _pull: PhantomData<ODM>,
}
impl<ODM> OutputMode for OpenDrain<ODM> where ODM: OpenDrainMode {}

/// Sets when a GPIO pin triggers an interrupt.
pub enum InterruptMode {
    /// Interrupt when level is low
    LevelLow,
    /// Interrupt when level is high
    LevelHigh,
    /// Interrupt on rising edge
    EdgeRising,
    /// Interrupt on falling edge
    EdgeFalling,
    /// Interrupt on both rising and falling edges
    EdgeBoth,
    /// Disable interrupts on this pin
    Disabled,
}

/// Extension trait to split a GPIO peripheral in independent pins and registers
pub trait GpioExt {
    /// The to split the GPIO into
    type Parts;

    /// Splits the GPIO block into independent pins and registers
    fn split(self) -> Self::Parts;
}

#[derive(Debug)]
pub enum GPIOError {
    Unknown,
}

// implementing the Error trait from the embedded_hal::digital crate
impl embedded_hal::digital::Error for GPIOError {
    fn kind(&self) -> embedded_hal::digital::ErrorKind {
        match self {
            GPIOError::Unknown => embedded_hal::digital::ErrorKind::Other,
        }
    }
}

/*
Acquire the GPIOA peripheral
NOTE: `dp` is the device peripherals from the `PAC` crate
let mut gpioa = dp.GPIOA.split();
gpioa.pa5.set_high();
*/

// GPIO
macro_rules! gpio_macro {
    ($GPIOX:ident, $gpiox:ident, $x:literal, $pos:literal, $data_val_reg:ident, 
        $dir_reg:ident, $int_en_reg:ident, $int_sen_t0:ident,
        $int_sen_t1:ident, $int_sen_t2:ident, $int_sts_reg:ident,
        $rst_tolerant_reg:ident, $deb1_reg:ident, $deb2_reg:ident,
        $cmd_src0_reg:ident, $cmd_src1_reg:ident, $data_read_reg:ident,
        $intput_mask_reg:ident, [
            $($PXi:ident: ($pxi:ident, $i:literal, $MODE:ty),)+
        ]) => {

        // GPIO
        pub mod $gpiox {
            use super::*;

            pub struct $GPIOX {
                gpio: Gpio,
            }

            impl $GPIOX {
                pub fn new(gpio: Gpio) -> Self {
                    Self {gpio}
                }

                pub fn init(&self) {
                    // command source 0
                    self.gpio.$cmd_src0_reg().modify(|r, w| unsafe {
                        w.bits(r.bits() & !(0xff << $pos))
                    });
                    // command source 1
                    self.gpio.$cmd_src1_reg().modify(|r, w| unsafe {
                        w.bits(r.bits() & !(0xff << $pos))
                    });
    
                    // debounce setting 1
                    self.gpio.$deb1_reg().modify(|r, w| unsafe {
                        w.bits(r.bits() & !(0xff << $pos))
                    });
                    // debounce setting 2
                    self.gpio.$deb2_reg().modify(|r, w| unsafe {
                        w.bits(r.bits() & !(0xff << $pos))
                    });
                }
            }

            // GPIO parts
            pub struct Parts {
                $(
                    pub $pxi: $PXi<$MODE>,
                )+
            }

            impl GpioExt for $GPIOX {
                type Parts = Parts;
    
                fn split(self) -> Self::Parts {
                    Parts {
                        $(
                            $pxi: $PXi {
                                _mode: PhantomData
                            },
                        )+
                    }
                }
            }


            $(
                // Pin
                pub struct $PXi<MODE> {
                    _mode: PhantomData<MODE>,
                }
    
                impl<MODE> $PXi<MODE> {
                    pub fn set_up_multifunc_pin_ctrl(self) {
                        let p = unsafe{ &*Scu::ptr() };
                        match $x {
                            'a' | 'b' | 'c' | 'd' => {
                                p.scu410().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                p.scu4b0().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                p.scu690().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                            },
                            'e' | 'f' | 'g' | 'h' => {
                                p.scu414().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                if $x != 'h' || $i < 6 {
                                    p.scu4b4().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                    p.scu694().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                }
                            },
                            'i' | 'j' | 'k' | 'l' => {
                                p.scu418().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                if $x == 'j' || $x == 'k' || ($x == 'l' && $i > 3) {
                                    p.scu4b8().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                }
                                if $x == 'l' && $i > 3 {
                                    p.scu698().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                }
                            },
                            'm' | 'n' | 'o' | 'p' => {
                                p.scu41c().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                if ($x == 'n' && $i != 2) || $x == 'o' || $x == 'p' {
                                    p.scu4bc().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                }
                                if ($x == 'o' && $i > 3) || ($x == 'p' && ($i == 0 || $i > 5)) {
                                    p.scu69c().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                }
                            },
                            'q' | 'r' | 's' => {
                                p.scu430().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                if $x == 'q' && $i < 5 {
                                    p.scu6b0().modify(|r, w| unsafe {
                                        w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                    });
                                }
                            },
                            't' => {
                                p.scu430().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                            },
                            'u' => {
                                p.scu434().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                            },
                            _ => {},
                        }
                    }

                    /// Configures the pin to operate as a pulled down input pin
                    pub fn into_pull_down_input(self) -> $PXi<Input<PullDown>> {
                        self.set_up_multifunc_pin_ctrl();
                        let p = unsafe{ &*Gpio::ptr() };
                        //dir
                        p.$dir_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() & !(1u32 << ($pos + $i)))
                        });
                        //data
                        p.$data_val_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() & !(1u32 << ($pos + $i)))
                        });
                        $PXi { _mode: PhantomData }
                    }
    
                    /// Configures the pin to operate as a pulled up input pin
                    pub fn into_pull_up_input(self) -> $PXi<Input<PullUp>> {
                        self.set_up_multifunc_pin_ctrl();
                        let p = unsafe{ &*Gpio::ptr() };
                        //dir
                        p.$dir_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() & !(1u32 << ($pos + $i)))
                        });
                        //data
                        p.$data_val_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() | (1u32 << ($pos + $i)))
                        });
                        $PXi { _mode: PhantomData }
                    }

                    /// Configures the pin to operate as an open drain output pin
                    pub fn into_open_drain_output<ODM>(self) -> $PXi<Output<OpenDrain<ODM>>> where ODM:OpenDrainMode {
                        self.set_up_multifunc_pin_ctrl();
                        let p = unsafe { &*Gpio::ptr()};
                        //data 
                        // 0 for active low; 1 for active high??
                        p.$data_val_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() | (1u32 << ($pos + $i)))
                        });
                        //dir
                        p.$dir_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() | (1u32 << ($pos + $i)))
                        });
                        $PXi { _mode: PhantomData}
                    }

                    /// Configures the pin to operate as an push pull output pin
                    pub fn into_push_pull_output(self) -> $PXi<Output<PushPull>> {
                        self.set_up_multifunc_pin_ctrl();
                        let p = unsafe { &*Gpio::ptr()};
                        //dir
                        p.$dir_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() | (1u32 << ($pos + $i)))
                        });
                        //data 
                        // 0/1 to drive low/high output??
                        p.$data_val_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() | (1u32 << ($pos + $i)))
                        });
                        $PXi { _mode: PhantomData}
                    }
                }
    
                impl<MODE> StatefulOutputPin for $PXi<Output<MODE>> where MODE: OutputMode {
                    fn is_set_high(&mut self) -> Result<bool, Self::Error> {
                        let p = unsafe { &*Gpio::ptr() };
                        Ok((p.$data_read_reg().read().bits() & (1u32 << ($pos + $i))) == (1u32 << ($pos + $i)))
                    }
                
                    fn is_set_low(&mut self) -> Result<bool, Self::Error> {
                        match self.is_set_high() {
                            Ok(v) => Ok(!v),
                            Err(e) => Err(e),
                        }
                    }
                }
    
                impl<MODE> OutputPin for $PXi<Output<MODE>> where MODE: OutputMode {
                    fn set_high(&mut self) -> Result<(), Self::Error> {
                        let p = unsafe { &*Gpio::ptr() };
                
                        p.$data_val_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() | (1u32 << ($pos + $i)))
                        });
                        Ok(())
                    }
                
                    fn set_low(&mut self) -> Result<(), Self::Error> {
                        let p = unsafe { &*Gpio::ptr() };
                
                        p.$data_val_reg().modify(|r, w| unsafe {
                            w.bits(r.bits() & !(1u32 << ($pos + $i)))
                        });
                        Ok(())
                    }
                }
    
                impl<MODE> InputPin for $PXi<Input<MODE>> where MODE: InputMode {
                    fn is_high(&mut self) -> Result<bool, Self::Error> {
                        let p = unsafe { &*Gpio::ptr() };
                
                        Ok((p.$data_read_reg().read().bits() & (1u32 << ($pos + $i))) == (1u32 << ($pos + $i)))
                    }
                
                    fn is_low(&mut self) -> Result<bool, Self::Error> {
                        match self.is_high() {
                            Ok(v) => Ok(!v),
                            Err(e) => Err(e),
                        }
                    }
                }
    
                impl<MODE> $PXi<Input<MODE>> where MODE: InputMode {
                    // Enables or disables interrupts on this GPIO pin.
                    pub fn set_interrupt_mode(&mut self, mode: InterruptMode) {
                        let p = unsafe { &*Gpio::ptr()};
                        match mode {
                            InterruptMode::LevelHigh => {
                                // sensitivity type 0
                                p.$int_sen_t0().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                                // sensitivity type 1
                                p.$int_sen_t1().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                                // sensitivity type 2
                                p.$int_sen_t2().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // interrupt enable
                                p.$int_en_reg().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                            },
                            InterruptMode::LevelLow => {
                                // sensitivity type 0
                                p.$int_sen_t0().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // sensitivity type 1
                                p.$int_sen_t1().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                                // sensitivity type 2
                                p.$int_sen_t2().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // interrupt enable
                                p.$int_en_reg().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                            },
                            InterruptMode::EdgeRising => {
                                // sensitivity type 0
                                p.$int_sen_t0().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                                // sensitivity type 1
                                p.$int_sen_t1().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // sensitivity type 2
                                p.$int_sen_t2().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // interrupt enable
                                p.$int_en_reg().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                            },
                            InterruptMode::EdgeFalling => {
                                // sensitivity type 0
                                p.$int_sen_t0().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // sensitivity type 1
                                p.$int_sen_t1().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // sensitivity type 2
                                p.$int_sen_t2().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                                // interrupt enable
                                p.$int_en_reg().modify(|r, w| unsafe {
                                    w.bits(r.bits() | !(1u32 << ($pos + $i)))
                                });
                            },
                            InterruptMode::EdgeBoth => {
                                // sensitivity type 2
                                p.$int_sen_t2().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                                // interrupt enable
                                p.$int_en_reg().modify(|r, w| unsafe {
                                    w.bits(r.bits() | (1u32 << ($pos + $i)))
                                });
                            },
                            InterruptMode::Disabled => {
                                // interrupt disable
                                p.$int_en_reg().modify(|r, w| unsafe {
                                    w.bits(r.bits() & !(1u32 << ($pos + $i)))
                                });
                            }
                        }
                    }   
                
                    // returns the current interrupt status for this pin
                    pub fn get_interrupt_status(&self) -> bool {
                        let p = unsafe {&*Gpio::ptr()};
                        (p.$int_sts_reg().read().bits() & (1u32 << ($pos + $i))) == (1u32 << ($pos + $i))
                    }
                
                    pub fn clear_interrupt(&self) {
                        let p = unsafe {&*Gpio::ptr()};
                        p.$int_sts_reg().write(|w| unsafe {
                            w.bits((1u32 << ($pos + $i)))
                        });
                    }
                
                    pub fn set_cmd_src(&self, cmd_src0: u32, cmd_src1: u32) {
                        let p = unsafe { &*Gpio::ptr()};
                        p.$cmd_src0_reg().modify(|r, w| unsafe {
                            w.bits((r.bits() & !(1u32 << ($pos + $i))) | (cmd_src0 << ($pos + $i)))
                        });
                        p.$cmd_src1_reg().modify(|r, w| unsafe {
                            w.bits((r.bits() & !(1u32 << ($pos + $i))) | (cmd_src1 << ($pos + $i)))
                        });
                    }
                
                    pub fn select_debounce_timer(&self, deb_setting1: u32, deb_setting2: u32) {
                        let p = unsafe {&*Gpio::ptr()};
                        p.$deb1_reg().modify(|r, w| unsafe {
                            w.bits((r.bits() & !(1u32 << ($pos + $i))) | (deb_setting1 << ($pos + $i)))
                        });
                        p.$deb2_reg().modify(|r, w| unsafe {
                            w.bits((r.bits() & !(1u32 << ($pos + $i))) | (deb_setting2 << ($pos + $i)))
                        });
                    }
                
                }
    
                impl<MODE> embedded_hal::digital::ErrorType for $PXi<MODE> {
                    type Error = GPIOError;
                }
    
            )+
        } 
    };
}

// GPIO ABCD
gpio_macro!( GPIOA, gpioa, 'a', 0, gpio000, gpio004, gpio008, 
    gpio00c, gpio010, gpio014, gpio018, gpio01c, gpio040,
    gpio044, gpio060, gpio064, gpio0c0, gpio1d0, [
    PA0: (pa0, 0, Tristate),
    PA1: (pa1, 1, Tristate),
    PA2: (pa2, 2, Tristate),
    PA3: (pa3, 3, Tristate),
    PA4: (pa4, 4, Tristate),
    PA5: (pa5, 5, Tristate),
    PA6: (pa6, 6, Tristate),
    PA7: (pa7, 7, Tristate),
]);

gpio_macro!( GPIOB, gpiob, 'b', 8, gpio000, gpio004, gpio008, 
    gpio00c, gpio010, gpio014, gpio018, gpio01c, gpio040,
    gpio044, gpio060, gpio064, gpio0c0, gpio1d0, [
    PB0: (pb0, 0, Tristate),
    PB1: (pb1, 1, Tristate),
    PB2: (pb2, 2, Tristate),
    PB3: (pb3, 3, Tristate),
    PB4: (pb4, 4, Tristate),
    PB5: (pb5, 5, Tristate),
    PB6: (pb6, 6, Tristate),
    PB7: (pb7, 7, Tristate),
]);

gpio_macro!( GPIOC, gpioc, 'c', 16, gpio000, gpio004, gpio008, 
    gpio00c, gpio010, gpio014, gpio018, gpio01c, gpio040,
    gpio044, gpio060, gpio064, gpio0c0, gpio1d0, [
    PC0: (pc0, 0, Tristate),
    PC1: (pc1, 1, Tristate),
    PC2: (pc2, 2, Tristate),
    PC3: (pc3, 3, Tristate),
    PC4: (pc4, 4, Tristate),
    PC5: (pc5, 5, Tristate),
    PC6: (pc6, 6, Tristate),
    PC7: (pc7, 7, Tristate),
]);

gpio_macro!( GPIOD, gpiod, 'd', 24, gpio000, gpio004, gpio008, 
    gpio00c, gpio010, gpio014, gpio018, gpio01c, gpio040,
    gpio044, gpio060, gpio064, gpio0c0, gpio1d0, [
    PD0: (pd0, 0, Tristate),
    PD1: (pd1, 1, Tristate),
    PD2: (pd2, 2, Tristate),
    PD3: (pd3, 3, Tristate),
    PD4: (pd4, 4, Tristate),
    PD5: (pd5, 5, Tristate),
    PD6: (pd6, 6, Tristate),
    PD7: (pd7, 7, Tristate),
]);

// GPIO EFGH
gpio_macro!( GPIOE, gpioe, 'e', 0, gpio020, gpio024, gpio028, 
    gpio02c, gpio030, gpio034, gpio038, gpio03c, gpio048,
    gpio04c, gpio068, gpio06c, gpio0c4, gpio1d4, [
    PE0: (pe0, 0, Tristate),
    PE1: (pe1, 1, Tristate),
    PE2: (pe2, 2, Tristate),
    PE3: (pe3, 3, Tristate),
    PE4: (pe4, 4, Tristate),
    PE5: (pe5, 5, Tristate),
    PE6: (pe6, 6, Tristate),
    PE7: (pe7, 7, Tristate),
]);

gpio_macro!( GPIOF, gpiof, 'f', 8, gpio020, gpio024, gpio028, 
    gpio02c, gpio030, gpio034, gpio038, gpio03c, gpio048,
    gpio04c, gpio068, gpio06c, gpio0c4, gpio1d4, [
    PF0: (pf0, 0, Tristate),
    PF1: (pf1, 1, Tristate),
    PF2: (pf2, 2, Tristate),
    PF3: (pf3, 3, Tristate),
    PF4: (pf4, 4, Tristate),
    PF5: (pf5, 5, Tristate),
    PF6: (pf6, 6, Tristate),
    PF7: (pf7, 7, Tristate),
]);

gpio_macro!( GPIOG, gpiog, 'g', 16, gpio020, gpio024, gpio028, 
    gpio02c, gpio030, gpio034, gpio038, gpio03c, gpio048,
    gpio04c, gpio068, gpio06c, gpio0c4, gpio1d4, [
    PG0: (pg0, 0, Tristate),
    PG1: (pg1, 1, Tristate),
    PG2: (pg2, 2, Tristate),
    PG3: (pg3, 3, Tristate),
    PG4: (pg4, 4, Tristate),
    PG5: (pg5, 5, Tristate),
    PG6: (pg6, 6, Tristate),
    PG7: (pg7, 7, Tristate),
]);

gpio_macro!( GPIOH, gpioh, 'h', 24, gpio020, gpio024, gpio028, 
    gpio02c, gpio030, gpio034, gpio038, gpio03c, gpio048,
    gpio04c, gpio068, gpio06c, gpio0c4, gpio1d4, [
    PH0: (ph0, 0, Tristate),
    PH1: (ph1, 1, Tristate),
    PH2: (ph2, 2, Tristate),
    PH3: (ph3, 3, Tristate),
    PH4: (ph4, 4, Tristate),
    PH5: (ph5, 5, Tristate),
    PH6: (ph6, 6, Tristate),
    PH7: (ph7, 7, Tristate),
]);

// GPIO IJKL
gpio_macro!( GPIOI, gpioi, 'i', 0, gpio070, gpio074, gpio098, 
    gpio09c, gpio0a0, gpio0a4, gpio0a8, gpio0ac, gpio0b0,
    gpio0b4, gpio090, gpio094, gpio0b8, gpio0c8, [
    PI0: (pi0, 0, Tristate),
    PI1: (pi1, 1, Tristate),
    PI2: (pi2, 2, Tristate),
    PI3: (pi3, 3, Tristate),
    PI4: (pi4, 4, Tristate),
    PI5: (pi5, 5, Tristate),
    PI6: (pi6, 6, Tristate),
    PI7: (pi7, 7, Tristate),
]);

gpio_macro!( GPIOJ, gpioj, 'j', 8, gpio070, gpio074, gpio098, 
    gpio09c, gpio0a0, gpio0a4, gpio0a8, gpio0ac, gpio0b0,
    gpio0b4, gpio090, gpio094, gpio0b8, gpio0c8, [
    PJ0: (pj0, 0, Tristate),
    PJ1: (pj1, 1, Tristate),
    PJ2: (pj2, 2, Tristate),
    PJ3: (pj3, 3, Tristate),
    PJ4: (pj4, 4, Tristate),
    PJ5: (pj5, 5, Tristate),
    PJ6: (pj6, 6, Tristate),
    PJ7: (pj7, 7, Tristate),
]);

gpio_macro!( GPIOK, gpiok, 'k', 16, gpio070, gpio074, gpio098, 
    gpio09c, gpio0a0, gpio0a4, gpio0a8, gpio0ac, gpio0b0,
    gpio0b4, gpio090, gpio094, gpio0b8, gpio0c8, [
    PK0: (pk0, 0, Tristate),
    PK1: (pk1, 1, Tristate),
    PK2: (pk2, 2, Tristate),
    PK3: (pk3, 3, Tristate),
    PK4: (pk4, 4, Tristate),
    PK5: (pk5, 5, Tristate),
    PK6: (pk6, 6, Tristate),
    PK7: (pk7, 7, Tristate),
]);

gpio_macro!( GPIOL, gpiol, 'l', 24, gpio070, gpio074, gpio098, 
    gpio09c, gpio0a0, gpio0a4, gpio0a8, gpio0ac, gpio0b0,
    gpio0b4, gpio090, gpio094, gpio0b8, gpio0c8, [
    PL0: (pl0, 0, Tristate),
    PL1: (pl1, 1, Tristate),
    PL2: (pl2, 2, Tristate),
    PL3: (pl3, 3, Tristate),
    PL4: (pl4, 4, Tristate),
    PL5: (pl5, 5, Tristate),
    PL6: (pl6, 6, Tristate),
    PL7: (pl7, 7, Tristate),
]);

// GPIO MNOP
gpio_macro!( GPIOM, gpiom, 'm', 0, gpio078, gpio07c, gpio0e8, 
    gpio0ec, gpio0f0, gpio0f4, gpio0f8, gpio0fc, gpio100,
    gpio104, gpio0e0, gpio0e4, gpio0cc, gpio108, [
    PM0: (pm0, 0, Tristate),
    PM1: (pm1, 1, Tristate),
    PM2: (pm2, 2, Tristate),
    PM3: (pm3, 3, Tristate),
    PM4: (pm4, 4, Tristate),
    PM5: (pm5, 5, Tristate),
    PM6: (pm6, 6, Tristate),
    PM7: (pm7, 7, Tristate),
]);

gpio_macro!( GPION, gpion, 'n', 8, gpio078, gpio07c, gpio0e8, 
    gpio0ec, gpio0f0, gpio0f4, gpio0f8, gpio0fc, gpio100,
    gpio104, gpio0e0, gpio0e4, gpio0cc, gpio108, [
    PN0: (pn0, 0, Tristate),
    PN1: (pn1, 1, Tristate),
    PN2: (pn2, 2, Tristate),
    PN3: (pn3, 3, Tristate),
    PN4: (pn4, 4, Tristate),
    PN5: (pn5, 5, Tristate),
    PN6: (pn6, 6, Tristate),
    PN7: (pn7, 7, Tristate),
]);

gpio_macro!( GPIOO, gpioo, 'o', 16, gpio078, gpio07c, gpio0e8, 
    gpio0ec, gpio0f0, gpio0f4, gpio0f8, gpio0fc, gpio100,
    gpio104, gpio0e0, gpio0e4, gpio0cc, gpio108, [
    PO0: (po0, 0, Tristate),
    PO1: (po1, 1, Tristate),
    PO2: (po2, 2, Tristate),
    PO3: (po3, 3, Tristate),
    PO4: (po4, 4, Tristate),
    PO5: (po5, 5, Tristate),
    PO6: (po6, 6, Tristate),
    PO7: (po7, 7, Tristate),
]);

gpio_macro!( GPIOP, gpiop, 'p', 24, gpio078, gpio07c, gpio0e8, 
    gpio0ec, gpio0f0, gpio0f4, gpio0f8, gpio0fc, gpio100,
    gpio104, gpio0e0, gpio0e4, gpio0cc, gpio108, [
    PP0: (pp0, 0, Tristate),
    PP1: (pp1, 1, Tristate),
    PP2: (pp2, 2, Tristate),
    PP3: (pp3, 3, Tristate),
    PP4: (pp4, 4, Tristate),
    PP5: (pp5, 5, Tristate),
    PP6: (pp6, 6, Tristate),
    PP7: (pp7, 7, Tristate),
]);

// GPIO QRST
gpio_macro!( GPIOQ, gpioq, 'q', 0, gpio080, gpio084, gpio118, 
    gpio11c, gpio120, gpio124, gpio128, gpio12c, gpio130,
    gpio134, gpio110, gpio114, gpio0d0, gpio138, [
    PQ0: (pq0, 0, Tristate),
    PQ1: (pq1, 1, Tristate),
    PQ2: (pq2, 2, Tristate),
    PQ3: (pq3, 3, Tristate),
    PQ4: (pq4, 4, Tristate),
    PQ5: (pq5, 5, Tristate),
    PQ6: (pq6, 6, Tristate),
    PQ7: (pq7, 7, Tristate),
]);

gpio_macro!( GPIOR, gpior, 'r', 8, gpio080, gpio084, gpio118, 
    gpio11c, gpio120, gpio124, gpio128, gpio12c, gpio130,
    gpio134, gpio110, gpio114, gpio0d0, gpio138, [
    PR0: (pr0, 0, Tristate),
    PR1: (pr1, 1, Tristate),
    PR2: (pr2, 2, Tristate),
    PR3: (pr3, 3, Tristate),
    PR4: (pr4, 4, Tristate),
    PR5: (pr5, 5, Tristate),
    PR6: (pr6, 6, Tristate),
    PR7: (pr7, 7, Tristate),
]);

gpio_macro!( GPIOS, gpios, 's', 16, gpio080, gpio084, gpio118, 
    gpio11c, gpio120, gpio124, gpio128, gpio12c, gpio130,
    gpio134, gpio110, gpio114, gpio0d0, gpio138, [
    PS0: (ps0, 0, Tristate),
    PS1: (ps1, 1, Tristate),
    PS2: (ps2, 2, Tristate),
    PS3: (ps3, 3, Tristate),
    PS4: (ps4, 4, Tristate),
    PS5: (ps5, 5, Tristate),
    PS6: (ps6, 6, Tristate),
    PS7: (ps7, 7, Tristate),
]);

gpio_macro!( GPIOT, gpiot, 't', 24, gpio080, gpio084, gpio118, 
    gpio11c, gpio120, gpio124, gpio128, gpio12c, gpio130,
    gpio134, gpio110, gpio114, gpio0d0, gpio138, [
    PT0: (pt0, 0, Tristate),
    PT1: (pt1, 1, Tristate),
    PT2: (pt2, 2, Tristate),
    PT3: (pt3, 3, Tristate),
    PT4: (pt4, 4, Tristate),
    PT5: (pt5, 5, Tristate),
    PT6: (pt6, 6, Tristate),
    PT7: (pt7, 7, Tristate),
]);

// GPIO U
gpio_macro!( GPIOU, gpiou, 'u', 0, gpio088, gpio08c, gpio148, 
    gpio14c, gpio150, gpio154, gpio158, gpio15c, gpio160,
    gpio164, gpio140, gpio144, gpio0d4, gpio168, [
    PU0: (pu0, 0, Tristate),
    PU1: (pu1, 1, Tristate),
    PU2: (pu2, 2, Tristate),
    PU3: (pu3, 3, Tristate),
    PU4: (pu4, 4, Tristate),
    PU5: (pu5, 5, Tristate),
    PU6: (pu6, 6, Tristate),
    PU7: (pu7, 7, Tristate),
]);