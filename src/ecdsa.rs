// Licensed under the Apache-2.0 license

use ast1060_pac::Secure;
use core::ptr::{read_volatile, write_volatile, NonNull};
use embedded_hal::delay::DelayNs;
use proposed_traits::common::{
    Endian, ErrorKind as CommonErrorKind, ErrorType as CommonErrorType, FromBytes,
    SerdeError as CommonSerdeError, ToBytes,
};
use proposed_traits::digest::DigestAlgorithm;
use proposed_traits::ecdsa::{
    Curve, EcdsaVerify, Error, ErrorKind, ErrorType as EcdsaErrorType, PubKeyForCurve,
    SignatureForCurve,
};

const ECDSA_BASE: usize = 0x7e6f_2000; // SBC base address
const ECDSA_SRAM_BASE: usize = 0x7900_0000; // SRAM base address for ECDSA
const ASPEED_ECDSA_PAR_GX: usize = 0x0a00;
const ASPEED_ECDSA_PAR_GY: usize = 0x0a40;
const ASPEED_ECDSA_PAR_P: usize = 0x0a80;
const ASPEED_ECDSA_PAR_N: usize = 0x0ac0;

const SRAM_DST_GX: usize = 0x2000;
const SRAM_DST_GY: usize = 0x2040;
const SRAM_DST_A: usize = 0x2140;
const SRAM_DST_P: usize = 0x2100;
const SRAM_DST_N: usize = 0x2180;
const SRAM_DST_QX: usize = 0x2080;
const SRAM_DST_QY: usize = 0x20c0;
const SRAM_DST_R: usize = 0x21c0;
const SRAM_DST_S: usize = 0x2200;
const SRAM_DST_M: usize = 0x2240;

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

pub struct Scalar48(pub [u8; 48]);

impl Scalar48 {
    pub const LEN: usize = core::mem::size_of::<Self>();
}

impl CommonErrorType for Scalar48 {
    type Error = SerdeError;
}

impl ToBytes for Scalar48 {
    fn to_bytes(&self, dest: &mut [u8], _: Endian) -> Result<(), Self::Error> {
        dest[..Self::LEN].copy_from_slice(&self.0);
        Ok(())
    }
}

impl FromBytes for Scalar48 {
    fn from_bytes(bytes: &[u8], _: Endian) -> Result<Self, Self::Error> {
        let mut out = [0u8; Scalar48::LEN];
        out.copy_from_slice(&bytes[..Self::LEN]);
        Ok(Scalar48(out))
    }
}

impl AsRef<[u8]> for Scalar48 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Scalar48 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Default for Scalar48 {
    fn default() -> Self {
        Scalar48([0u8; Scalar48::LEN])
    }
}

pub struct Sha384;

impl DigestAlgorithm for Sha384 {
    const OUTPUT_BITS: usize = 384;
    type DigestOutput = Scalar48;
}

pub struct Secp384r1Curve;

impl Curve for Secp384r1Curve {
    type Scalar = Scalar48;
    type DigestType = Sha384;
}

pub struct PublicKey {
    pub qx: Scalar48,
    pub qy: Scalar48,
}

impl CommonErrorType for PublicKey {
    type Error = SerdeError;
}

impl ToBytes for PublicKey {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        const LEN: usize = Scalar48::LEN;
        if dest.len() < 2 * LEN {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..LEN].copy_from_slice(&self.qx.0);
        dest[LEN..2 * LEN].copy_from_slice(&self.qy.0);
        Ok(())
    }
}

impl FromBytes for PublicKey {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        const LEN: usize = Scalar48::LEN;
        if bytes.len() < 2 * LEN {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut qx = [0u8; LEN];
        let mut qy = [0u8; LEN];
        qx.copy_from_slice(&bytes[..LEN]);
        qy.copy_from_slice(&bytes[LEN..2 * LEN]);
        Ok(PublicKey {
            qx: Scalar48(qx),
            qy: Scalar48(qy),
        })
    }
}

pub struct Signature {
    pub r: Scalar48,
    pub s: Scalar48,
}

impl CommonErrorType for Signature {
    type Error = SerdeError;
}

impl ToBytes for Signature {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        const LEN: usize = Scalar48::LEN;
        if dest.len() < 2 * LEN {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..LEN].copy_from_slice(&self.r.0);
        dest[LEN..2 * LEN].copy_from_slice(&self.s.0);
        Ok(())
    }
}

impl FromBytes for Signature {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        const LEN: usize = Scalar48::LEN;
        if bytes.len() < 2 * LEN {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut r = [0u8; LEN];
        let mut s = [0u8; LEN];
        r.copy_from_slice(&bytes[..LEN]);
        s.copy_from_slice(&bytes[LEN..2 * LEN]);
        Ok(Signature {
            r: Scalar48(r),
            s: Scalar48(s),
        })
    }
}

impl<C: Curve<Scalar = Scalar48>> SignatureForCurve<C> for Signature {
    fn r(&self) -> &C::Scalar {
        &self.r
    }

    fn s(&self) -> &C::Scalar {
        &self.s
    }

    fn new(r: C::Scalar, s: C::Scalar) -> Self {
        Signature { r, s }
    }
}

impl<C: Curve<Scalar = Scalar48>> PubKeyForCurve<C> for PublicKey {
    fn x(&self) -> &C::Scalar {
        &self.qx
    }

    fn y(&self) -> &C::Scalar {
        &self.qy
    }

    fn new(x: C::Scalar, y: C::Scalar) -> Self {
        PublicKey { qx: x, qy: y }
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
            Self::BadInput => ErrorKind::Other,
        }
    }
}

pub struct AspeedEcdsa<'a, D: DelayNs> {
    secure: &'a Secure,
    ecdsa_base: NonNull<u32>,
    sram_base: NonNull<u32>,
    delay: D,
}

impl<D: DelayNs> EcdsaErrorType for AspeedEcdsa<'_, D> {
    type Error = AspeedEcdsaError;
}

impl<'a, D: DelayNs> AspeedEcdsa<'a, D> {
    pub fn new(secure: &'a Secure, delay: D) -> Self {
        let ecdsa_base = unsafe { NonNull::new_unchecked(ECDSA_BASE as *mut u32) };
        let sram_base = unsafe { NonNull::new_unchecked(ECDSA_SRAM_BASE as *mut u32) };

        Self {
            secure,
            ecdsa_base,
            sram_base,
            delay,
        }
    }

    fn sec_rd(&self, offset: usize) -> u32 {
        unsafe { read_volatile(self.ecdsa_base.as_ptr().add(offset / 4)) }
    }

    fn sec_wr(&self, offset: usize, val: u32) {
        unsafe {
            write_volatile(self.ecdsa_base.as_ptr().add(offset / 4), val);
        }
    }

    fn sram_wr_u32(&self, offset: usize, val: u32) {
        unsafe {
            write_volatile(self.sram_base.as_ptr().add(offset / 4), val);
        }
    }

    fn sram_wr(&self, offset: usize, data: &[u8; Scalar48::LEN]) {
        for i in (0..Scalar48::LEN).step_by(4) {
            let val = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            unsafe {
                write_volatile(self.sram_base.as_ptr().add((offset + i) / 4), val);
            }
        }
    }

    fn load_param(&self, from: usize, to: usize) {
        for i in (0..Scalar48::LEN).step_by(4) {
            let val = self.sec_rd(from + i);
            self.sram_wr_u32(to + i, val);
        }
    }

    fn load_secp384r1_params(&self) {
        // (1) Gx
        self.load_param(ASPEED_ECDSA_PAR_GX, SRAM_DST_GX);
        // (2) Gy
        self.load_param(ASPEED_ECDSA_PAR_GY, SRAM_DST_GY);
        // (3) p
        self.load_param(ASPEED_ECDSA_PAR_P, SRAM_DST_P);
        // (4) n
        self.load_param(ASPEED_ECDSA_PAR_N, SRAM_DST_N);
        // (5) a
        for i in (0..Scalar48::LEN).step_by(4) {
            self.sram_wr_u32(SRAM_DST_A + i, 0);
        }
    }
}

impl<D> EcdsaVerify<Secp384r1Curve> for AspeedEcdsa<'_, D>
where
    D: DelayNs,
{
    type PublicKey = PublicKey;
    type Signature = Signature;

    fn verify(
        &mut self,
        public_key: &Self::PublicKey,
        digest: <<Secp384r1Curve as Curve>::DigestType as DigestAlgorithm>::DigestOutput,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        unsafe {
            let digest_bytes = digest.as_ref();
            if digest_bytes.len() != 48 {
                return Err(AspeedEcdsaError::BadInput);
            }

            let digest_array: &[u8; 48] = digest_bytes
                .try_into()
                .map_err(|_| AspeedEcdsaError::BadInput)?;

            self.sec_wr(0x7c, 0x0100_f00b);

            // Reset Engine
            self.secure.secure0b4().write(|w| w.bits(0));
            self.secure
                .secure0b4()
                .write(|w| w.sec_boot_ecceng_enbl().set_bit());
            self.delay.delay_ns(5000);

            self.load_secp384r1_params();

            self.sec_wr(0x7c, 0x0300_f00b);

            // Write qx, qy, r, s
            self.sram_wr(SRAM_DST_QX, &public_key.qx.0);
            self.sram_wr(SRAM_DST_QY, &public_key.qy.0);
            self.sram_wr(SRAM_DST_R, &signature.r.0);
            self.sram_wr(SRAM_DST_S, &signature.s.0);
            self.sram_wr(SRAM_DST_M, digest_array);

            self.sec_wr(0x7c, 0);

            // Write ECDSA instruction command
            self.sram_wr_u32(0x23c0, 1);

            // Trigger ECDSA Engine
            self.secure
                .secure0bc()
                .write(|w| w.sec_boot_ecceng_trigger_reg().set_bit());
            self.delay.delay_ns(5000);
            self.secure
                .secure0bc()
                .write(|w| w.sec_boot_ecceng_trigger_reg().clear_bit());

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
