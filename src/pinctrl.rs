pub struct Pinctrl;

pub struct PinctrlPin {
    pub offset: u32,
    pub bit: u32,
    pub clear: bool,
}

// Pin to be cleared or set
pub const PIN_SCL0: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 28,
    clear: false,
};
pub const PIN_SDA0: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 29,
    clear: false,
};
pub const PIN_SCL1: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 30,
    clear: false,
};
pub const PIN_SDA1: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 31,
    clear: false,
};

pub const PIN_SCL2: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 0,
    clear: false,
};
pub const PIN_SDA2: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 1,
    clear: false,
};
pub const PIN_SCL3: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 2,
    clear: false,
};
pub const PIN_SDA3: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 3,
    clear: false,
};
pub const PIN_SCL4: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 4,
    clear: false,
};
pub const PIN_SDA4: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 5,
    clear: false,
};
pub const PIN_SCL5: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 6,
    clear: false,
};
pub const PIN_SDA5: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 7,
    clear: false,
};
pub const PIN_SCL6: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 8,
    clear: false,
};
pub const PIN_SDA6: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 9,
    clear: false,
};
pub const PIN_SCL7: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 10,
    clear: false,
};
pub const PIN_SDA7: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 11,
    clear: false,
};
pub const PIN_SCL8: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 12,
    clear: false,
};
pub const PIN_SDA8: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 13,
    clear: false,
};
pub const PIN_SCL9: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 14,
    clear: false,
};
pub const PIN_SDA9: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 15,
    clear: false,
};
pub const CLR_PIN_I3C_SCL0: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 16,
    clear: true,
};
pub const CLR_PIN_I3C_SDA0: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 17,
    clear: true,
};
pub const CLR_PIN_I3C_SCL1: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 18,
    clear: true,
};
pub const CLR_PIN_I3C_SDA1: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 19,
    clear: true,
};
pub const CLR_PIN_I3C_SCL2: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 20,
    clear: true,
};
pub const CLR_PIN_I3C_SDA2: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 21,
    clear: true,
};
pub const CLR_PIN_I3C_SCL3: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 22,
    clear: true,
};
pub const CLR_PIN_I3C_SDA3: PinctrlPin = PinctrlPin {
    offset: 0x418,
    bit: 23,
    clear: true,
};

pub const PIN_SPI2CS0: PinctrlPin = PinctrlPin {
    offset: 0x41C,
    bit: 30,
    clear: false,
};
pub const PIN_SPI2CS1: PinctrlPin = PinctrlPin {
    offset: 0x41C,
    bit: 31,
    clear: false,
};

pub const PIN_SPI2CK: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 0,
    clear: false,
};
pub const PIN_SPI2DQ0: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 1,
    clear: false,
};
pub const PIN_SPI2DQ1: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 2,
    clear: false,
};
pub const PIN_SPI2DQ2: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 3,
    clear: false,
};
pub const PIN_SPI2DQ3: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 4,
    clear: false,
};
pub const PIN_FWSPIDQ2: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 10,
    clear: false,
};
pub const PIN_FWSPIDQ3: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 11,
    clear: false,
};
pub const PIN_SPI1DQ2: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 17,
    clear: false,
};
pub const PIN_SPI1DQ3: PinctrlPin = PinctrlPin {
    offset: 0x430,
    bit: 18,
    clear: false,
};

pub const PIN_SCL10: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 16,
    clear: false,
};
pub const PIN_SDA10: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 17,
    clear: false,
};
pub const PIN_SCL11: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 18,
    clear: false,
};
pub const PIN_SDA11: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 19,
    clear: false,
};
pub const PIN_SCL12: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 20,
    clear: false,
};
pub const PIN_SDA12: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 21,
    clear: false,
};
pub const PIN_SCL13: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 22,
    clear: false,
};
pub const PIN_SDA13: PinctrlPin = PinctrlPin {
    offset: 0x4b8,
    bit: 23,
    clear: false,
};

pub const PIN_SPIM1_CSIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 0,
    clear: true,
};  
pub const PIN_SPIM1_CSIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 0,
    clear: true,
}; 
pub const PIN_SPIM1_CSIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 0,
    clear: false,
}; 
pub const PIN_SPIM1_CLKIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 1,
    clear: true,
};  
pub const PIN_SPIM1_CLKIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 1,
    clear: true,
}; 
pub const PIN_SPIM1_CLKIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 1,
    clear: false,
}; 
pub const PIN_SPIM1_MOSIIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 2,
    clear: true,
};  
pub const PIN_SPIM1_MOSIIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 2,
    clear: true,
}; 
pub const PIN_SPIM1_MOSIIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 2,
    clear: false,
};
pub const PIN_SPIM1_MISOIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 3,
    clear: true,
};  
pub const PIN_SPIM1_MISOIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 3,
    clear: true,
}; 
pub const PIN_SPIM1_MISOIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 3,
    clear: false,
};
pub const PIN_SPIM1_IO2IN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 4,
    clear: true,
};  
pub const PIN_SPIM1_IO2IN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 4,
    clear: true,
}; 
pub const PIN_SPIM1_IO2IN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 4,
    clear: false,
}; 
pub const PIN_SPIM1_IO3IN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 5,
    clear: true,
};  
pub const PIN_SPIM1_IO3IN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 5,
    clear: true,
}; 
pub const PIN_SPIM1_IO3IN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 5,
    clear: false,
};
pub const PIN_SPIM1_CSNOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 6,
    clear: true,
};  
pub const PIN_SPIM1_CSNOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 6,
    clear: true,
}; 
pub const PIN_SPIM1_CSNOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 6,
    clear: false,
};
pub const PIN_SPIM1_CLKOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 7,
    clear: true,
};  
pub const PIN_SPIM1_CLKOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 7,
    clear: true,
}; 
pub const PIN_SPIM1_CLKOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 7,
    clear: false,
};
pub const PIN_SPIM1_MOSIOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 8,
    clear: true,
};  
pub const PIN_SPIM1_MOSIOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 8,
    clear: true,
}; 
pub const PIN_SPIM1_MOSIOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 8,
    clear: false,
};
pub const PIN_SPIM1_MISOOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 9,
    clear: true,
};  
pub const PIN_SPIM1_MISOOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 9,
    clear: true,
}; 
pub const PIN_SPIM1_MISOOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 9,
    clear: false,
};
pub const PIN_SPIM1_IO2OUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 10,
    clear: true,
};  
pub const PIN_SPIM1_IO2OUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 10,
    clear: true,
}; 
pub const PIN_SPIM1_IO2OUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 10,
    clear: false,
};
pub const PIN_SPIM1_IO3OUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 11,
    clear: true,
};  
pub const PIN_SPIM1_IO3OUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 11,
    clear: true,
}; 
pub const PIN_SPIM1_IO3OUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 11,
    clear: false,
};
pub const PIN_SPIM1_MUX_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 12,
    clear: true,
};

pub const PIN_SPIM1_MUX_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 12,
    clear: true,
};

pub const PIN_SPIM1_MUX_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 12,
    clear: false,
};
pub const PIN_SPIM1_RSTOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 13,
    clear: true,
};

pub const PIN_SPIM1_RSTOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 13,
    clear: true,
};

pub const PIN_SPIM1_RSTOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 13,
    clear: false,
};
pub const PIN_SPIM1_RSTIN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 24,
    clear: true,
};

pub const PIN_SPIM1_RSTIN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 24,
    clear: true,
};

pub const PIN_SPIM1_RSTIN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 24,
    clear: false,
};
pub const PIN_SPIM2_CSIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 14,
    clear: true,
};  
pub const PIN_SPIM2_CSIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 14,
    clear: true,
}; 
pub const PIN_SPIM2_CSIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 14,
    clear: false,
}; 
pub const PIN_SPIM2_CLKIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 15,
    clear: true,
};  
pub const PIN_SPIM2_CLKIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 15,
    clear: true,
}; 
pub const PIN_SPIM2_CLKIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 15,
    clear: false,
}; 
pub const PIN_SPIM2_MOSIIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 16,
    clear: true,
};  
pub const PIN_SPIM2_MOSIIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 16,
    clear: true,
}; 
pub const PIN_SPIM2_MOSIIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 16,
    clear: false,
};
pub const PIN_SPIM2_MISOIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 17,
    clear: true,
};  
pub const PIN_SPIM2_MISOIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 17,
    clear: true,
}; 
pub const PIN_SPIM2_MISOIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 17,
    clear: false,
};
pub const PIN_SPIM2_IO2IN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 18,
    clear: true,
};  
pub const PIN_SPIM2_IO2IN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 18,
    clear: true,
}; 
pub const PIN_SPIM2_IO2IN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 18,
    clear: false,
}; 
pub const PIN_SPIM2_IO3IN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 19,
    clear: true,
};  
pub const PIN_SPIM2_IO3IN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 19,
    clear: true,
}; 
pub const PIN_SPIM2_IO3IN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 19,
    clear: false,
};
pub const PIN_SPIM2_CSNOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 20,
    clear: true,
};  
pub const PIN_SPIM2_CSNOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 20,
    clear: true,
}; 
pub const PIN_SPIM2_CSNOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 20,
    clear: false,
};
pub const PIN_SPIM2_CLKOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 21,
    clear: true,
};  
pub const PIN_SPIM2_CLKOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 21,
    clear: true,
}; 
pub const PIN_SPIM2_CLKOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 21,
    clear: false,
};
pub const PIN_SPIM2_MOSIOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 8,
    clear: true,
};  
pub const PIN_SPIM2_MOSIOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 8,
    clear: true,
}; 
pub const PIN_SPIM2_MOSIOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 8,
    clear: false,
};
pub const PIN_SPIM2_MISOOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 23,
    clear: true,
};  
pub const PIN_SPIM2_MISOOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 23,
    clear: true,
}; 
pub const PIN_SPIM2_MISOOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 23,
    clear: false,
};
pub const PIN_SPIM2_IO2OUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 24,
    clear: true,
};  
pub const PIN_SPIM2_IO2OUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 24,
    clear: true,
}; 
pub const PIN_SPIM2_IO2OUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 24,
    clear: false,
};
pub const PIN_SPIM2_IO3OUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 25,
    clear: true,
};  
pub const PIN_SPIM2_IO3OUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 25,
    clear: true,
}; 
pub const PIN_SPIM2_IO3OUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 25,
    clear: false,
};
pub const PIN_SPIM2_MUX_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 26,
    clear: true,
};

pub const PIN_SPIM2_MUX_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 26,
    clear: true,
};

pub const PIN_SPIM2_MUX_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 26,
    clear: false,
};
pub const PIN_SPIM2_RSTOUT_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 27,
    clear: true,
};

pub const PIN_SPIM2_RSTOUT_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 27,
    clear: true,
};

pub const PIN_SPIM2_RSTOUT_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 27,
    clear: false,
};

pub const PIN_SPIM3_CSIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 28,
    clear: true,
};  
pub const PIN_SPIM3_CSIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 28,
    clear: true,
}; 
pub const PIN_SPIM3_CSIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 28,
    clear: false,
}; 
pub const PIN_SPIM3_CLKIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 29,
    clear: true,
};  
pub const PIN_SPIM3_CLKIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 29,
    clear: true,
}; 
pub const PIN_SPIM3_CLKIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 29,
    clear: false,
}; 
pub const PIN_SPIM3_MOSIIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 30,
    clear: true,
};  
pub const PIN_SPIM3_MOSIIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 30,
    clear: true,
}; 
pub const PIN_SPIM3_MOSIIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 30,
    clear: false,
};
pub const PIN_SPIM3_MISOIN_CTRL1: PinctrlPin = PinctrlPin {
    offset: 0x410,
    bit: 31,
    clear: true,
};  
pub const PIN_SPIM3_MISOIN_CTRL13: PinctrlPin = PinctrlPin {
    offset: 0x4B0,
    bit: 31,
    clear: true,
}; 
pub const PIN_SPIM3_MISOIN_CTRL31: PinctrlPin = PinctrlPin {
    offset: 0x690,
    bit: 31,
    clear: false,
};
pub const PIN_SPIM3_IO2IN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 0,
    clear: true,
};  
pub const PIN_SPIM3_IO2IN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 0,
    clear: true,
}; 
pub const PIN_SPIM3_IO2IN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 0,
    clear: false,
}; 
pub const PIN_SPIM3_IO3IN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 1,
    clear: true,
};  
pub const PIN_SPIM3_IO3IN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 1,
    clear: true,
}; 
pub const PIN_SPIM3_IO3IN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 1,
    clear: false,
};
pub const PIN_SPIM3_CSNOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 2,
    clear: true,
};  
pub const PIN_SPIM3_CSNOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 2,
    clear: true,
}; 
pub const PIN_SPIM3_CSNOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 2,
    clear: false,
};
pub const PIN_SPIM3_CLKOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 3,
    clear: true,
};  
pub const PIN_SPIM3_CLKOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 3,
    clear: true,
}; 
pub const PIN_SPIM3_CLKOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 3,
    clear: false,
};
pub const PIN_SPIM3_MOSIOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 4,
    clear: true,
};  
pub const PIN_SPIM3_MOSIOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 4,
    clear: true,
}; 
pub const PIN_SPIM3_MOSIOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 4,
    clear: false,
};
pub const PIN_SPIM3_MISOOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 5,
    clear: true,
};  
pub const PIN_SPIM3_MISOOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 5,
    clear: true,
}; 
pub const PIN_SPIM3_MISOOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 5,
    clear: false,
};
pub const PIN_SPIM3_IO2OUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 6,
    clear: true,
};  
pub const PIN_SPIM3_IO2OUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 6,
    clear: true,
}; 
pub const PIN_SPIM3_IO2OUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 6,
    clear: false,
};
pub const PIN_SPIM3_IO3OUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 7,
    clear: true,
};  
pub const PIN_SPIM3_IO3OUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 7,
    clear: true,
}; 
pub const PIN_SPIM3_IO3OUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 7,
    clear: false,
};
pub const PIN_SPIM3_MUX_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 8,
    clear: true,
};

pub const PIN_SPIM3_MUX_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 8,
    clear: true,
};

pub const PIN_SPIM3_MUX_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 8,
    clear: false,
};
pub const PIN_SPIM3_RSTOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 9,
    clear: true,
};

pub const PIN_SPIM3_RSTOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 9,
    clear: true,
};

pub const PIN_SPIM3_RSTOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 9,
    clear: false,
};

pub const PIN_SPIM3_RSTIN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 25,
    clear: true,
};

pub const PIN_SPIM3_RSTIN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 25,
    clear: true,
};

pub const PIN_SPIM3_RSTIN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 25,
    clear: false,
};

pub const PIN_SPIM4_CSIN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 10,
    clear: true,
};  
pub const PIN_SPIM4_CSIN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 10,
    clear: true,
}; 
pub const PIN_SPIM4_CSIN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 10,
    clear: false,
}; 
pub const PIN_SPIM4_CLKIN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 11,
    clear: true,
};  
pub const PIN_SPIM4_CLKIN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 11,
    clear: true,
}; 
pub const PIN_SPIM4_CLKIN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 11,
    clear: false,
}; 
pub const PIN_SPIM4_MOSIIN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 12,
    clear: true,
};  
pub const PIN_SPIM4_MOSIIN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 12,
    clear: true,
}; 
pub const PIN_SPIM4_MOSIIN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 12,
    clear: false,
};
pub const PIN_SPIM4_MISOIN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 13,
    clear: true,
};  
pub const PIN_SPIM4_MISOIN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 13,
    clear: true,
}; 
pub const PIN_SPIM4_MISOIN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 13,
    clear: false,
};
pub const PIN_SPIM4_IO2IN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 14,
    clear: true,
};  
pub const PIN_SPIM4_IO2IN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 14,
    clear: true,
}; 
pub const PIN_SPIM4_IO2IN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 14,
    clear: false,
}; 
pub const PIN_SPIM4_IO3IN_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 15,
    clear: true,
};  
pub const PIN_SPIM4_IO3IN_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 15,
    clear: true,
}; 
pub const PIN_SPIM4_IO3IN_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 15,
    clear: false,
};
pub const PIN_SPIM4_CSNOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit:16,
    clear: true,
};  
pub const PIN_SPIM4_CSNOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 16,
    clear: true,
}; 
pub const PIN_SPIM4_CSNOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 16,
    clear: false,
};
pub const PIN_SPIM4_CLKOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 17,
    clear: true,
};  
pub const PIN_SPIM4_CLKOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 17,
    clear: true,
}; 
pub const PIN_SPIM4_CLKOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 17,
    clear: false,
};
pub const PIN_SPIM4_MOSIOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 18,
    clear: true,
};  
pub const PIN_SPIM4_MOSIOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 18,
    clear: true,
}; 
pub const PIN_SPIM4_MOSIOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 18,
    clear: false,
};
pub const PIN_SPIM4_MISOOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 19,
    clear: true,
};  
pub const PIN_SPIM4_MISOOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 19,
    clear: true,
}; 
pub const PIN_SPIM4_MISOOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 19,
    clear: false,
};
pub const PIN_SPIM4_IO2OUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 20,
    clear: true,
};  
pub const PIN_SPIM4_IO2OUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 20,
    clear: true,
}; 
pub const PIN_SPIM4_IO2OUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 20,
    clear: false,
};
pub const PIN_SPIM4_IO3OUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 21,
    clear: true,
};  
pub const PIN_SPIM4_IO3OUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 21,
    clear: true,
}; 
pub const PIN_SPIM4_IO3OUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 21,
    clear: false,
};
pub const PIN_SPIM4_MUX_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 22,
    clear: true,
};

pub const PIN_SPIM4_MUX_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 22,
    clear: true,
};

pub const PIN_SPIM4_MUX_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 22,
    clear: false,
};
pub const PIN_SPIM4_RSTOUT_CTRL2: PinctrlPin = PinctrlPin {
    offset: 0x414,
    bit: 23,
    clear: true,
};

pub const PIN_SPIM4_RSTOUT_CTRL14: PinctrlPin = PinctrlPin {
    offset: 0x4B4,
    bit: 23,
    clear: true,
};

pub const PIN_SPIM4_RSTOUT_CTRL32: PinctrlPin = PinctrlPin {
    offset: 0x694,
    bit: 23,
    clear: false,
};

//Pin Group Aliases
pub const PINCTRL_FMC_QUAD: &[PinctrlPin] = &[PIN_FWSPIDQ2, PIN_FWSPIDQ3];
pub const PINCTRL_SPI1_QUAD: &[PinctrlPin] = &[PIN_SPI1DQ2, PIN_SPI1DQ3];
pub const PINCTRL_SPI2_DEFAULT: &[PinctrlPin] = &[
    PIN_SPI2CS0,
    PIN_SPI2CK,
    PIN_SPI2DQ0,
    PIN_SPI2DQ1,
    PIN_SPI2CS1,
];
pub const PINCTRL_SPI2_QUAD: &[PinctrlPin] = &[
    PIN_SPI2CS0,
    PIN_SPI2CK,
    PIN_SPI2DQ0,
    PIN_SPI2DQ1,
    PIN_SPI2CS1,
    PIN_SPI2DQ2,
    PIN_SPI2DQ3,
];
pub const PINCTRL_SPIM1_MUXSEL: &[PinctrlPin] = & [
    PIN_SPIM1_MUX_CTRL1,
    PIN_SPIM1_MUX_CTRL13,
    PIN_SPIM1_MUX_CTRL31,
];
pub const PINCTRL_SPIM2_MUXSEL: &[PinctrlPin] = & [
    PIN_SPIM2_MUX_CTRL1,
    PIN_SPIM2_MUX_CTRL13,
    PIN_SPIM2_MUX_CTRL31,
];
pub const PINCTRL_SPIM3_MUXSEL: &[PinctrlPin] = & [
    PIN_SPIM3_MUX_CTRL2,
    PIN_SPIM3_MUX_CTRL14,
    PIN_SPIM3_MUX_CTRL32,
];
pub const PINCTRL_SPIM4_MUXSEL: &[PinctrlPin] = & [
    PIN_SPIM4_MUX_CTRL2,
    PIN_SPIM4_MUX_CTRL14,
    PIN_SPIM4_MUX_CTRL32,
];

pub const PINCTRL_SPIM1_QUAD_DEFAULT: &[PinctrlPin] = &[
    PIN_SPIM1_CSIN_CTRL1, PIN_SPIM1_CSIN_CTRL13, PIN_SPIM1_CSIN_CTRL31,
    PIN_SPIM1_CLKIN_CTRL1,PIN_SPIM1_CLKIN_CTRL13,PIN_SPIM1_CLKIN_CTRL31,
    PIN_SPIM1_MOSIIN_CTRL1,PIN_SPIM1_MOSIIN_CTRL13,PIN_SPIM1_MOSIIN_CTRL31,
    PIN_SPIM1_MISOIN_CTRL1,PIN_SPIM1_MISOIN_CTRL13,PIN_SPIM1_MISOIN_CTRL31,
    PIN_SPIM1_IO2IN_CTRL1,PIN_SPIM1_IO2IN_CTRL13,PIN_SPIM1_IO2IN_CTRL31,
    PIN_SPIM1_IO3IN_CTRL1,PIN_SPIM1_IO3IN_CTRL13,PIN_SPIM1_IO3IN_CTRL31,
    PIN_SPIM1_CSNOUT_CTRL1,PIN_SPIM1_CSNOUT_CTRL13,PIN_SPIM1_CSNOUT_CTRL31,
    PIN_SPIM1_CLKOUT_CTRL1,PIN_SPIM1_CLKOUT_CTRL13,PIN_SPIM1_CLKOUT_CTRL31,
    PIN_SPIM1_MOSIOUT_CTRL1,PIN_SPIM1_MOSIOUT_CTRL13,PIN_SPIM1_MOSIOUT_CTRL31,
    PIN_SPIM1_MISOOUT_CTRL1,PIN_SPIM1_MISOOUT_CTRL13,PIN_SPIM1_MISOOUT_CTRL31,
    PIN_SPIM1_IO2OUT_CTRL1,PIN_SPIM1_IO2OUT_CTRL13,PIN_SPIM1_IO2OUT_CTRL31,
    PIN_SPIM1_IO3OUT_CTRL1,PIN_SPIM1_IO3OUT_CTRL13,PIN_SPIM1_IO3OUT_CTRL31,
    PIN_SPIM1_MUX_CTRL1,PIN_SPIM1_MUX_CTRL13,PIN_SPIM1_MUX_CTRL31,
    PIN_SPIM1_RSTOUT_CTRL1,PIN_SPIM1_RSTOUT_CTRL13,PIN_SPIM1_RSTOUT_CTRL31,
    PIN_SPIM1_RSTIN_CTRL2,PIN_SPIM1_RSTIN_CTRL14,PIN_SPIM1_RSTIN_CTRL32,
];
pub const PINCTRL_SPIM3_QUAD_DEFAULT: &[PinctrlPin] = &[
    PIN_SPIM3_CSIN_CTRL1, PIN_SPIM3_CSIN_CTRL13, PIN_SPIM3_CSIN_CTRL31,
    PIN_SPIM3_CLKIN_CTRL1,PIN_SPIM3_CLKIN_CTRL13,PIN_SPIM3_CLKIN_CTRL31,
    PIN_SPIM3_MOSIIN_CTRL1,PIN_SPIM3_MOSIIN_CTRL13,PIN_SPIM3_MOSIIN_CTRL31,
    PIN_SPIM3_MISOIN_CTRL1,PIN_SPIM3_MISOIN_CTRL13,PIN_SPIM3_MISOIN_CTRL31,
    PIN_SPIM3_IO2IN_CTRL2,PIN_SPIM3_IO2IN_CTRL14,PIN_SPIM3_IO2IN_CTRL32,
    PIN_SPIM3_IO3IN_CTRL2,PIN_SPIM3_IO3IN_CTRL14,PIN_SPIM3_IO3IN_CTRL32,
    PIN_SPIM3_CSNOUT_CTRL2,PIN_SPIM3_CSNOUT_CTRL14,PIN_SPIM3_CSNOUT_CTRL32,
    PIN_SPIM3_CLKOUT_CTRL2,PIN_SPIM3_CLKOUT_CTRL14,PIN_SPIM3_CLKOUT_CTRL32,
    PIN_SPIM3_MOSIOUT_CTRL2,PIN_SPIM3_MOSIOUT_CTRL14,PIN_SPIM3_MOSIOUT_CTRL32,
    PIN_SPIM3_MISOOUT_CTRL2,PIN_SPIM3_MISOOUT_CTRL14,PIN_SPIM3_MISOOUT_CTRL32,
    PIN_SPIM3_IO2OUT_CTRL2,PIN_SPIM3_IO2OUT_CTRL14,PIN_SPIM3_IO2OUT_CTRL32,
    PIN_SPIM3_IO3OUT_CTRL2,PIN_SPIM3_IO3OUT_CTRL14,PIN_SPIM3_IO3OUT_CTRL32,
    PIN_SPIM3_MUX_CTRL2,PIN_SPIM3_MUX_CTRL14,PIN_SPIM3_MUX_CTRL32,
    PIN_SPIM3_RSTOUT_CTRL2,PIN_SPIM3_RSTOUT_CTRL14,PIN_SPIM3_RSTOUT_CTRL32,
    PIN_SPIM3_RSTIN_CTRL2,PIN_SPIM3_RSTIN_CTRL14,PIN_SPIM3_RSTIN_CTRL32,
];

pub const PINCTRL_SPIM3_PINCTRL0: &[PinctrlPin] = &[
    PIN_SPIM3_CSIN_CTRL1, PIN_SPIM3_CSIN_CTRL13, PIN_SPIM3_CSIN_CTRL31,
    PIN_SPIM3_CLKIN_CTRL1,PIN_SPIM3_CLKIN_CTRL13,PIN_SPIM3_CLKIN_CTRL31,
    PIN_SPIM3_MOSIIN_CTRL1,PIN_SPIM3_MOSIIN_CTRL13,PIN_SPIM3_MOSIIN_CTRL31,
    PIN_SPIM3_MISOIN_CTRL1,PIN_SPIM3_MISOIN_CTRL13,PIN_SPIM3_MISOIN_CTRL31,
    PIN_SPIM3_IO2IN_CTRL2,PIN_SPIM3_IO2IN_CTRL14,PIN_SPIM3_IO2IN_CTRL32,
    PIN_SPIM3_IO3IN_CTRL2,PIN_SPIM3_IO3IN_CTRL14,PIN_SPIM3_IO3IN_CTRL32,
    PIN_SPIM3_CSNOUT_CTRL2,PIN_SPIM3_CSNOUT_CTRL14,PIN_SPIM3_CSNOUT_CTRL32,
    PIN_SPIM3_CLKOUT_CTRL2,PIN_SPIM3_CLKOUT_CTRL14,PIN_SPIM3_CLKOUT_CTRL32,
    PIN_SPIM3_MOSIOUT_CTRL2,PIN_SPIM3_MOSIOUT_CTRL14,PIN_SPIM3_MOSIOUT_CTRL32,
    PIN_SPIM3_MISOOUT_CTRL2,PIN_SPIM3_MISOOUT_CTRL14,PIN_SPIM3_MISOOUT_CTRL32,
    PIN_SPIM3_IO2OUT_CTRL2,PIN_SPIM3_IO2OUT_CTRL14,PIN_SPIM3_IO2OUT_CTRL32,
    PIN_SPIM3_IO3OUT_CTRL2,PIN_SPIM3_IO3OUT_CTRL14,PIN_SPIM3_IO3OUT_CTRL32,
    PIN_SPIM3_MUX_CTRL2,PIN_SPIM3_MUX_CTRL14,PIN_SPIM3_MUX_CTRL32,
];


pub const PINCTRL_I2C0: &[PinctrlPin] = &[PIN_SCL0, PIN_SDA0];
pub const PINCTRL_I2C1: &[PinctrlPin] = &[PIN_SCL1, PIN_SDA1];
pub const PINCTRL_I2C2: &[PinctrlPin] = &[PIN_SCL2, PIN_SDA2];
pub const PINCTRL_I2C3: &[PinctrlPin] = &[PIN_SCL3, PIN_SDA3];
pub const PINCTRL_I2C4: &[PinctrlPin] = &[PIN_SCL4, PIN_SDA4];
pub const PINCTRL_I2C5: &[PinctrlPin] = &[PIN_SCL5, PIN_SDA5];
pub const PINCTRL_I2C6: &[PinctrlPin] = &[PIN_SCL6, PIN_SDA6];
pub const PINCTRL_I2C7: &[PinctrlPin] = &[PIN_SCL7, PIN_SDA7];
pub const PINCTRL_I2C8: &[PinctrlPin] = &[PIN_SCL8, PIN_SDA8];
pub const PINCTRL_I2C9: &[PinctrlPin] = &[PIN_SCL9, PIN_SDA9];
pub const PINCTRL_I2C10: &[PinctrlPin] = &[
    PIN_SCL10, 
    PIN_SDA10,
    CLR_PIN_I3C_SCL0,
    CLR_PIN_I3C_SDA0,
];
pub const PINCTRL_I2C11: &[PinctrlPin] = &[
    PIN_SCL11, 
    PIN_SDA11,
    CLR_PIN_I3C_SCL1,
    CLR_PIN_I3C_SDA1,
];
pub const PINCTRL_I2C12: &[PinctrlPin] = &[
    PIN_SCL12, 
    PIN_SDA12,
    CLR_PIN_I3C_SCL2,
    CLR_PIN_I3C_SDA2,
];
pub const PINCTRL_I2C13: &[PinctrlPin] = &[
    PIN_SCL13, 
    PIN_SDA13,
    CLR_PIN_I3C_SCL3,
    CLR_PIN_I3C_SDA3,
];
#[macro_export]
macro_rules! modify_reg {
    ($reg:expr, $bit:expr, $clear:expr) => {{
        $reg.modify(|r, w| unsafe {
            let current = r.bits();
            let new_val = if $clear {
                current & !(1 << $bit)
            } else {
                current | (1 << $bit)
            };
            w.bits(new_val)
        });
    }};
}

impl Pinctrl {
    /// Write pinmux configuration to SCU register
    pub fn apply_pinctrl_group(pins: &[PinctrlPin]) {
        let scu = unsafe { &*ast1060_pac::Scu::ptr() };
        for pin in pins {
            match pin.offset {
                0x410 => modify_reg!(scu.scu410(), pin.bit, pin.clear),
                0x414 => modify_reg!(scu.scu414(), pin.bit, pin.clear),
                0x418 => modify_reg!(scu.scu418(), pin.bit, pin.clear),
                0x41C => modify_reg!(scu.scu41c(), pin.bit, pin.clear),
                0x430 => modify_reg!(scu.scu430(), pin.bit, pin.clear),
                0x434 => modify_reg!(scu.scu434(), pin.bit, pin.clear),
                0x4b0 => modify_reg!(scu.scu4b0(), pin.bit, pin.clear),
                0x4b4 => modify_reg!(scu.scu4b4(), pin.bit, pin.clear),
                0x4b8 => modify_reg!(scu.scu4b8(), pin.bit, pin.clear),
                0x690 => modify_reg!(scu.scu690(), pin.bit, pin.clear),
                0x694 => modify_reg!(scu.scu694(), pin.bit, pin.clear),
                _ => {}
            } //match
        } //for
    }
}
