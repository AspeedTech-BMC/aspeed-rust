// Licensed under the Apache-2.0 license

use core::fmt::Debug;
use crate::hace_controller::{HaceController, HACE_CMD_DES_SG_CTRL, HACE_CMD_MBUS_REQ_SYNC_EN, HACE_CMD_SRC_SG_CTRL, HaceCipherError, CryptoAlgo};
use proposed_traits::common::{
    Endian, ErrorKind as CommonErrorKind, ErrorType as CommonErrorType, FromBytes,
    SerdeError as CommonSerdeError, ToBytes,
};

use proposed_traits::symm_cipher::{SymmetricCipher, CipherInit, CipherOp, ErrorType, CipherMode, BlockCipherMode, ErrorKind, Error};

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

impl FromBytes for AesKey {
    fn from_bytes(bytes: &[u8], _endian: Endian) -> Result<Self, Self::Error> {
        if bytes.len() > 32 {
            return Err(SerdeError::BufferTooSmall);
        }

        let mut data = [0u8; 32];
        for (i, b) in bytes.iter().rev().enumerate() {
            data[i] = *b;
        }

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

        for (i, dest_item) in dest.iter_mut().enumerate().take(self.len) {
            *dest_item = self.data[self.len - i - 1];
        }

        Ok(())
    }
}

/// IV
#[derive(Clone)]
pub struct Iv {
    pub data: [u8; 16],
    pub len: usize,
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
        for (i, b) in bytes.iter().rev().enumerate() {
            data[i] = *b;
        }

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

        for (i, dest_item) in dest.iter_mut().enumerate().take(self.len) {
            *dest_item = self.data[self.len - i - 1];
        }

        Ok(())
    }
}

/// PlainText
#[derive(Clone)]
pub struct PlainText{
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
        for (i, b) in bytes.iter().rev().enumerate() {
            data[i] = *b;
        }

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

        for (i, dest_item) in dest.iter_mut().enumerate().take(self.len) {
            *dest_item = self.data[self.len - i - 1];
        }

        Ok(())
    }
}

/// CipherText
#[derive(Clone)]
pub struct CipherText{
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
        for (i, b) in bytes.iter().rev().enumerate() {
            data[i] = *b;
        }

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

        for (i, dest_item) in dest.iter_mut().enumerate().take(self.len) {
            *dest_item = self.data[self.len - i - 1];
        }

        Ok(())
    }
}

pub struct HaceSymmetric<'ctrl> {
    pub controller: &'ctrl mut HaceController<'ctrl>,
    pub algo: CryptoAlgo,
}

impl ErrorType for HaceSymmetric<'_> {
    type Error = HaceCipherError;
}

impl SymmetricCipher for HaceSymmetric<'_> {
    type Key = AesKey;
    type Nonce = Iv;
    type PlainText = PlainText;
    type CipherText = CipherText;
}

pub struct OpContextImpl<'a, 'ctrl, M: CipherMode> {
    pub controller: &'a mut HaceController<'ctrl>,
    _phantom: core::marker::PhantomData<M>,
}

impl<'a, 'ctrl, M: CipherMode> ErrorType for OpContextImpl<'a, 'ctrl, M> {
    type Error = HaceCipherError;
}

impl<'a, 'ctrl, M: CipherMode> SymmetricCipher for OpContextImpl<'a, 'ctrl, M> {
    type Key = AesKey;
    type Nonce = Iv;
    type PlainText = PlainText;
    type CipherText = CipherText;
}


impl<'ctrl, M: BlockCipherMode + 'static> CipherInit<M> for HaceSymmetric<'ctrl>
where
    M: CipherMode,
{
    type CipherContext<'a> = OpContextImpl<'a, 'ctrl, M>
    where
        Self: 'a;

    fn init<'a>(
        &'a mut self,
        key: &Self::Key,
        _nonce: &Self::Nonce,
        _mode: M,
    ) -> Result<Self::CipherContext<'a>, Self::Error> {
        self.controller.crypto_ctx_mut().cmd = HACE_CMD_DES_SG_CTRL | HACE_CMD_SRC_SG_CTRL | HACE_CMD_MBUS_REQ_SYNC_EN;
        let _cmd = HaceController::setup_crypto_session::<M>(key.len, self.algo);

        Ok(OpContextImpl {
            controller: self.controller,
            _phantom: core::marker::PhantomData,
        })
    }
}

impl<'a, 'ctrl, M> CipherOp<M> for OpContextImpl<'a, 'ctrl, M>
where
    M: BlockCipherMode,
{
    fn encrypt(&mut self, _input: Self::PlainText) -> Result<Self::CipherText, Self::Error> {
        todo!("Implement encryption logic here")
    }

    fn decrypt(&mut self, _input: Self::CipherText) -> Result<Self::PlainText, Self::Error> {
        todo!("Implement decryption logic here")
    }
}

