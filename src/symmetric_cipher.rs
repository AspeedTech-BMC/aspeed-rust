// Licensed under the Apache-2.0 license

use crate::hace_controller::{
    CryptoAlgo, HaceCipherError, HaceController, HasCryptoAlgo, KeyMaterial, HACE_CMD_ENCRYPT,
};
use core::fmt::Debug;
use proposed_traits::common::{
    Endian, ErrorKind as CommonErrorKind, ErrorType as CommonErrorType, FromBytes,
    SerdeError as CommonSerdeError, ToBytes,
};

use proposed_traits::symm_cipher::{
    BlockCipherMode, CipherInit, CipherMode, CipherOp, Error, ErrorKind, ErrorType, SymmetricCipher,
};

impl Error for HaceCipherError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidKeyLength => ErrorKind::KeyError,
            Self::InvalidIvLength | Self::InvalidDataLength => ErrorKind::InvalidInput,
            Self::HardwareFailure => ErrorKind::HardwareFailure,
            Self::Busy => ErrorKind::InvalidState,
            Self::UnsupportedMode => ErrorKind::UnsupportedAlgorithm,
        }
    }
}

#[derive(Debug)]
pub enum SerdeError {
    BufferTooSmall,
    Unsupported,
}

impl CommonSerdeError for SerdeError {
    fn kind(&self) -> CommonErrorKind {
        match self {
            SerdeError::BufferTooSmall => CommonErrorKind::SourceBufferTooSmall,
            SerdeError::Unsupported => CommonErrorKind::NotSupported,
        }
    }
}

impl CommonErrorType for HaceCipherError {
    type Error = SerdeError;
}

/// ECB/CBC key
#[derive(Clone)]
pub struct AesKey {
    pub data: [u8; 32],
    pub len: usize,
}

impl CommonErrorType for AesKey {
    type Error = SerdeError;
}

impl HasCryptoAlgo for AesKey {
    fn algo() -> CryptoAlgo {
        CryptoAlgo::Aes
    }
}

impl KeyMaterial for AesKey {
    fn key_len(&self) -> usize {
        self.len
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl FromBytes for AesKey {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 32 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 32];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }
}
impl ToBytes for AesKey {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < self.len {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..self.len].copy_from_slice(&self.data[..self.len]);
        Ok(())
    }
}

#[derive(Clone)]
pub struct DesKey {
    pub data: [u8; 8],
}
impl CommonErrorType for DesKey {
    type Error = SerdeError;
}
impl HasCryptoAlgo for DesKey {
    fn algo() -> CryptoAlgo {
        CryptoAlgo::Des
    }
}
impl KeyMaterial for DesKey {
    fn key_len(&self) -> usize {
        8
    }
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl FromBytes for DesKey {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() != 8 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }
}
impl ToBytes for DesKey {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < 8 {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..8].copy_from_slice(&self.data);
        Ok(())
    }
}

#[derive(Clone)]
pub struct TdesKey {
    pub data: [u8; 24],
}
impl CommonErrorType for TdesKey {
    type Error = SerdeError;
}
impl HasCryptoAlgo for TdesKey {
    fn algo() -> CryptoAlgo {
        CryptoAlgo::Tdes
    }
}
impl KeyMaterial for TdesKey {
    fn key_len(&self) -> usize {
        24
    }
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl FromBytes for TdesKey {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() != 24 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 24];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }
}
impl ToBytes for TdesKey {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < 24 {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..24].copy_from_slice(&self.data);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Iv {
    pub data: [u8; 16],
    pub len: usize, // 16 typical
}
impl CommonErrorType for Iv {
    type Error = SerdeError;
}
impl FromBytes for Iv {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 16 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 16];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }
}
impl ToBytes for Iv {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < self.len {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..self.len].copy_from_slice(&self.data[..self.len]);
        Ok(())
    }
}

impl Iv {
    pub const NONE: Self = Self {
        data: [0u8; 16],
        len: 0,
    };

    #[inline]
    #[must_use]
    pub const fn none() -> Self {
        Self::NONE
    }
}

#[derive(Clone)]
pub struct PlainText {
    pub data: [u8; 64],
    pub len: usize,
}
impl CommonErrorType for PlainText {
    type Error = SerdeError;
}
impl FromBytes for PlainText {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 64 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 64];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }
}
impl ToBytes for PlainText {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < self.len {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..self.len].copy_from_slice(&self.data[..self.len]);
        Ok(())
    }
}

#[derive(Clone)]
pub struct CipherText {
    pub data: [u8; 80],
    pub len: usize,
}
impl CommonErrorType for CipherText {
    type Error = SerdeError;
}
impl FromBytes for CipherText {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 80 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 80];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }
}
impl ToBytes for CipherText {
    fn to_bytes(&self, dest: &mut [u8], _endian: Endian) -> Result<(), Self::Error> {
        if dest.len() < self.len {
            return Err(SerdeError::BufferTooSmall);
        }
        dest[..self.len].copy_from_slice(&self.data[..self.len]);
        Ok(())
    }
}

pub struct HaceSymmetric<'ctrl, 'h, K>
where
    'h: 'ctrl,
{
    pub controller: &'ctrl mut HaceController<'h>,
    pub _key: core::marker::PhantomData<K>,
}

impl<K> ErrorType for HaceSymmetric<'_, '_, K> {
    type Error = HaceCipherError;
}

impl<K> SymmetricCipher for HaceSymmetric<'_, '_, K>
where
    K: FromBytes + ToBytes,
{
    type Key = K;
    type Nonce = Iv;
    type PlainText = PlainText;
    type CipherText = CipherText;
}

pub struct OpContextImpl<'a, 'ctrl, M: CipherMode, K> {
    pub controller: &'a mut HaceController<'ctrl>,

    cmd_base: u32,
    is_aes: bool,
    iv_len: u8,
    used: bool,

    _phantom: core::marker::PhantomData<(M, K)>,
}

impl<'a, 'ctrl, M: CipherMode, K> ErrorType for OpContextImpl<'a, 'ctrl, M, K> {
    type Error = HaceCipherError;
}

impl<'a, 'ctrl, M: CipherMode, K> SymmetricCipher for OpContextImpl<'a, 'ctrl, M, K>
where
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    type Key = K;
    type Nonce = Iv;
    type PlainText = PlainText;
    type CipherText = CipherText;
}

impl<'ctrl, 'h, M: BlockCipherMode + 'static, K> CipherInit<M> for HaceSymmetric<'ctrl, 'h, K>
where
    'h: 'ctrl,
    M: CipherMode,
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    type CipherContext<'a> = OpContextImpl<'a, 'h, M, K>
    where
        Self: 'a;

    fn init<'a>(
        &'a mut self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        _mode: M,
    ) -> Result<Self::CipherContext<'a>, Self::Error> {
        let (cmd_base, is_aes, iv_len, key_len) =
            HaceController::assemble_cmd_from_key_mode::<M, K>(key)?;
        let hw = self.controller.crypto_ctx_mut();
        hw.cmd = cmd_base;

        if HaceController::needs_iv(hw.cmd) {
            let n = core::cmp::min(nonce.len, iv_len);
            HaceController::iv_slice_mut(&mut hw.ctx, is_aes, n).copy_from_slice(&nonce.data[..n]);
        }

        HaceController::key_slice_mut(&mut hw.ctx, key_len)
            .copy_from_slice(&key.as_bytes()[..key_len]);

        Ok(OpContextImpl {
            controller: self.controller,
            cmd_base,
            is_aes,
            iv_len: u8::try_from(iv_len).map_err(|_| HaceCipherError::InvalidIvLength)?,
            used: false,

            _phantom: core::marker::PhantomData,
        })
    }
}

impl<'a, 'ctrl, M, K> CipherOp<M> for OpContextImpl<'a, 'ctrl, M, K>
where
    M: BlockCipherMode,
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    fn encrypt(&mut self, pt: Self::PlainText) -> Result<Self::CipherText, Self::Error> {
        if core::mem::take(&mut self.used) {
            return Err(HaceCipherError::Busy);
        }

        let hw = self.controller.crypto_ctx_mut();

        let mut out = CipherText {
            data: [0; 80],
            len: pt.len + self.iv_len as usize,
        };

        if HaceController::needs_iv(hw.cmd) {
            let iv_off = HaceController::iv_out_offset(self.is_aes);
            let n = self.iv_len as usize;
            let dst = &mut out.data[iv_off..][..n];
            dst.copy_from_slice(HaceController::iv_slice(&hw.ctx, self.is_aes, n));
        }

        hw.src_sg.addr = pt.data.as_ptr() as u32;
        hw.dst_sg.addr = out.data.as_mut_ptr() as u32;
        hw.cmd = self.cmd_base | HACE_CMD_ENCRYPT;

        self.controller.start_crypto_operation(
            u32::try_from(pt.len).map_err(|_| HaceCipherError::InvalidDataLength)?,
        );
        self.used = true;

        Ok(out)
    }

    fn decrypt(&mut self, ct: Self::CipherText) -> Result<Self::PlainText, Self::Error> {
        if core::mem::take(&mut self.used) {
            return Err(HaceCipherError::Busy);
        }

        let hw = self.controller.crypto_ctx_mut();

        let mut out = PlainText {
            data: [0; 64],
            len: ct.len,
        };

        hw.src_sg.addr = ct.data.as_ptr() as u32;
        hw.dst_sg.addr = out.data.as_mut_ptr() as u32;
        hw.cmd = self.cmd_base;

        self.controller.start_crypto_operation(
            u32::try_from(ct.len).map_err(|_| HaceCipherError::InvalidDataLength)?,
        );
        self.used = true;

        Ok(out)
    }
}
