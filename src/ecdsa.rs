use core::ptr::{read_volatile, write_volatile};
use ast1060_pac::Secure;
use proposed_traits::ecdsa::{EcdsaVerify, ErrorType as EcdsaErrorType, Error, ErrorKind};
use proposed_traits::common::{FromBytes, ToBytes, Endian, ErrorKind as CommonErrorKind, ErrorType as CommonErrorType, SerdeError as CommonSerdeError};
use proposed_traits::digest::DigestAlgorithm;
use embedded_hal::delay::DelayNs;

const ECDSA_BASE: usize = 0x7e6f2000; // SBC base address
const ECDSA_SRAM_BASE: usize = 0x79000000; // SRAM base address for ECDSA
const ASPEED_ECDSA_PAR_GX: usize = 0x0a00;
const ASPEED_ECDSA_PAR_GY: usize = 0x0a40;
const ASPEED_ECDSA_PAR_P:  usize = 0x0a80;
const ASPEED_ECDSA_PAR_N:  usize = 0x0ac0;

const SRAM_DST_GX: usize = 0x2000;
const SRAM_DST_GY: usize = 0x2040;
const SRAM_DST_A:  usize = 0x2140;
const SRAM_DST_P:  usize = 0x2100;
const SRAM_DST_N:  usize = 0x2180;
const SRAM_DST_QX: usize = 0x2080;
const SRAM_DST_QY: usize = 0x20c0;
const SRAM_DST_R:  usize = 0x21c0;
const SRAM_DST_S:  usize = 0x2200;
const SRAM_DST_M:  usize = 0x2240;

#[derive(Debug)]
pub enum SerdeError {
    NotSupported,
    BufferTooSmall,
}

impl CommonSerdeError for SerdeError {
    fn kind(&self) -> CommonErrorKind {
        match self {
            SerdeError::BufferTooSmall => CommonErrorKind::SourceBufferTooSmall,
            SerdeError::NotSupported => CommonErrorKind::NotSupported,
        }
    }
}

pub struct PublicKey {
    pub qx: [u8; 48],
    pub qy: [u8; 48],
}

impl CommonErrorType for PublicKey {
    type Error = SerdeError;
}

pub trait SerializeDeserialize: ToBytes + FromBytes {}
impl<T: ToBytes + FromBytes> SerializeDeserialize for T {}

impl ToBytes for PublicKey {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < 96 {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..48].copy_from_slice(&self.qx);
        dest[48..96].copy_from_slice(&self.qy);
        Ok(())
    }
}

impl FromBytes for PublicKey {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() < 96 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut qx = [0u8; 48];
        let mut qy = [0u8; 48];
        qx.copy_from_slice(&bytes[..48]);
        qy.copy_from_slice(&bytes[48..96]);
        Ok(PublicKey { qx, qy })
    }
}

pub struct Signature {
    pub r: [u8; 48],
    pub s: [u8; 48],
}

impl CommonErrorType for Signature {
    type Error = SerdeError;
}

impl ToBytes for Signature {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < 96 {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..48].copy_from_slice(&self.r);
        dest[48..96].copy_from_slice(&self.s);
        Ok(())
    }
}

impl FromBytes for Signature {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() < 96 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&bytes[..48]);
        s.copy_from_slice(&bytes[48..96]);
        Ok(Signature { r, s })
    }
}

#[derive(Debug)]
pub enum AspeedEcdsaError {
    InvalidSignature,
    Busy,
    BadInput,
}

impl Error for AspeedEcdsaError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidSignature => ErrorKind::InvalidSignature,
            Self::Busy => ErrorKind::Busy,
            _ => ErrorKind::Other,
        }
    }
}

pub struct AspeedEcdsa<'a, D: DelayNs> {
    secure: &'a Secure,
    ecdsa_base: *mut u32,
    sram_base: *mut u32,
    delay: D,
}

impl<D: DelayNs> EcdsaErrorType for AspeedEcdsa<'_, D> {
    type Error = AspeedEcdsaError;
}

impl<'a, D: DelayNs> AspeedEcdsa<'a, D> {
    pub fn new(secure: &'a Secure, delay: D) -> Self {
        let ecdsa_base = ECDSA_BASE as *mut u32; // SBC base address
        let sram_base = ECDSA_SRAM_BASE as *mut u32; // SRAM base address for ECDSA
        Self { secure, ecdsa_base, sram_base, delay }
    }

    #[inline(always)]
    fn sec_rd(&self, offset: usize) -> u32 {
        unsafe {
            read_volatile(self.ecdsa_base.add(offset / 4))
        }
    }

    fn sec_wr(&self, offset: usize, val: u32) {
        unsafe {
            write_volatile(self.ecdsa_base.add(offset / 4), val);
        }
    }

    #[inline(always)]
    fn sram_wr_u32(&self, offset: usize, val: u32) {
        unsafe {
            write_volatile(self.sram_base.add(offset / 4), val);
        }
    }
    #[inline(always)]
    fn sram_wr(&self, offset: usize, data: &[u8; 48]) {
        for i in (0..48).step_by(4) {
            let val = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            unsafe {
                write_volatile(self.sram_base.add((offset + i) / 4), val);
            }
        }
    }
    fn load_secp384r1_params(&self) {
        // (1) Gx
        for i in (0..48).step_by(4) {
            let val = self.sec_rd(ASPEED_ECDSA_PAR_GX + i);
            self.sram_wr_u32(SRAM_DST_GX + i, val);
        }

        // (2) Gy
        for i in (0..48).step_by(4) {
            let val = self.sec_rd(ASPEED_ECDSA_PAR_GY + i);
            self.sram_wr_u32(SRAM_DST_GY + i, val);
        }

        // (3) p
        for i in (0..48).step_by(4) {
            let val = self.sec_rd(ASPEED_ECDSA_PAR_P + i);
            self.sram_wr_u32(SRAM_DST_P + i, val);
        }

        // (4) n
        for i in (0..48).step_by(4) {
            let val = self.sec_rd(ASPEED_ECDSA_PAR_N + i);
            self.sram_wr_u32(SRAM_DST_N + i, val);
        }

        // (5) a
        for i in (0..48).step_by(4) {
            self.sram_wr_u32(SRAM_DST_A + i, 0);
        }
    }
}

impl<C, D> EcdsaVerify<C> for AspeedEcdsa<'_, D>
where
    C: DigestAlgorithm,
    C::DigestOutput: AsRef<[u8]>,
    D: DelayNs,
{
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        digest: C::DigestOutput,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        unsafe {
            let digest_bytes = digest.as_ref();
            if digest_bytes.len() != 48 {
                return Err(AspeedEcdsaError::BadInput);
            }

            let digest_array: &[u8; 48] = digest_bytes.try_into().map_err(|_| AspeedEcdsaError::BadInput)?;

            self.sec_wr(0x7c, 0x0100f00b);

            // Reset Engine
            self.secure.secure0b4().write(|w| w.bits(0));
            self.secure.secure0b4().write(|w| w.sec_boot_ecceng_enbl().set_bit());
            self.delay.delay_ns(5000);

            self.load_secp384r1_params();

            self.sec_wr(0x7c, 0x0300f00b);

            // Write qx, qy, r, s
            self.sram_wr(SRAM_DST_QX, &public_key.qx);
            self.sram_wr(SRAM_DST_QY, &public_key.qy);
            self.sram_wr(SRAM_DST_R, &signature.r);
            self.sram_wr(SRAM_DST_S, &signature.s);
            self.sram_wr(SRAM_DST_M, digest_array);

            self.sec_wr(0x7c, 0);

            // Write ECDSA instruction command
            self.sram_wr_u32(0x23c0, 1);

            // Trigger ECDSA Engine
            self.secure.secure0bc().write(|w| w.sec_boot_ecceng_trigger_reg().set_bit());
            self.delay.delay_ns(5000);
            self.secure.secure0bc().write(|w| w.sec_boot_ecceng_trigger_reg().clear_bit());

            // Poll
            let mut retry = 1000;
            while retry > 0 {
                let status = self.secure.secure014().read().bits();
                if status & (1 << 20) != 0 {
                    return if status & (1 << 21) != 0 {
                        Ok(())
                    } else {
                        Err(AspeedEcdsaError::InvalidSignature)
                    };
                }
                retry -= 1;
                self.delay.delay_ns(5000);
            }

            Err(AspeedEcdsaError::Busy)
        }
    }
}
