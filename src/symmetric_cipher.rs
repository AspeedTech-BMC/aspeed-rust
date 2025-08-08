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

#[derive(Clone)]
pub struct PlainText {
    pub data: [u8; 256],
    pub len: usize,
}
impl CommonErrorType for PlainText {
    type Error = SerdeError;
}
impl FromBytes for PlainText {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 256 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 256];
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
    pub data: [u8; 272],
    pub len: usize,
}
impl CommonErrorType for CipherText {
    type Error = SerdeError;
}
impl FromBytes for CipherText {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 272 {
            return Err(SerdeError::BufferTooSmall);
        }
        let mut data = [0u8; 272];
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

pub struct HaceSymmetric<'ctrl, K> {
    pub controller: &'ctrl mut HaceController<'ctrl>,
    pub _key: core::marker::PhantomData<K>,
}

impl<K> ErrorType for HaceSymmetric<'_, K> {
    type Error = HaceCipherError;
}

impl<K> SymmetricCipher for HaceSymmetric<'_, K>
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
    iv_origin: Iv,
    iv_len: u8,

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

impl<'ctrl, M: BlockCipherMode + 'static, K> CipherInit<M> for HaceSymmetric<'ctrl, K>
where
    M: CipherMode,
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    type CipherContext<'a> = OpContextImpl<'a, 'ctrl, M, K>
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
        self.controller.crypto_ctx_mut().cmd = cmd_base;
        let hw = self.controller.crypto_ctx_mut();
        let n = core::cmp::min(nonce.len, iv_len);
        if is_aes {
            hw.ctx[0..n].copy_from_slice(&nonce.data[..n]);
        } else {
            hw.ctx[8..8 + n].copy_from_slice(&nonce.data[..n]);
        }
        let kb = key.as_bytes();
        hw.ctx[16..16 + key_len].copy_from_slice(&kb[..key_len]);

        Ok(OpContextImpl {
            controller: self.controller,
            cmd_base,
            is_aes,
            iv_origin: nonce.clone(),
            iv_len: iv_len as u8,

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
        let hw = self.controller.crypto_ctx_mut();
        if self.is_aes {
            let n = core::cmp::min(self.iv_len as usize, 16);
            hw.ctx[0..n].copy_from_slice(&self.iv_origin.data[..n]);
        } else {
            let n = core::cmp::min(self.iv_len as usize, 8);
            hw.ctx[8..8 + n].copy_from_slice(&self.iv_origin.data[..n]);
        }

        let mut out = CipherText {
            data: [0; 272],
            len: pt.len,
        };

        hw.src_sg.addr = pt.data.as_ptr() as u32;
        hw.dst_sg.addr = out.data.as_mut_ptr() as u32;
        hw.src_sg.len = pt.len as u32 | (1 << 31);
        hw.dst_sg.len = pt.len as u32 | (1 << 31);
        hw.cmd = self.cmd_base | HACE_CMD_ENCRYPT;

        self.controller.start_crypto_operation(pt.len as u32);

        Ok(out)
    }

    fn decrypt(&mut self, ct: Self::CipherText) -> Result<Self::PlainText, Self::Error> {
        let hw = self.controller.crypto_ctx_mut();
        let n = self.iv_len as usize;
        if self.is_aes {
            hw.ctx[0..n].copy_from_slice(&self.iv_origin.data[..n]);
        } else {
            hw.ctx[8..8 + n].copy_from_slice(&self.iv_origin.data[..n]);
        }

        let mut out = PlainText {
            data: [0; 256],
            len: ct.len,
        };

        hw.src_sg.addr = ct.data.as_ptr() as u32;
        hw.dst_sg.addr = out.data.as_mut_ptr() as u32;
        hw.src_sg.len = ct.len as u32 | (1 << 31);
        hw.dst_sg.len = ct.len as u32 | (1 << 31);
        hw.cmd = self.cmd_base;

        self.controller.start_crypto_operation(ct.len as u32);

        Ok(out)
    }
}
