// Licensed under the Apache-2.0 license

use ast1060_pac::Hace;
use core::any::TypeId;
use core::convert::Infallible;
use core::ptr::write_volatile;
use proposed_traits::digest::ErrorType as DigestErrorType;
use proposed_traits::mac::ErrorType as MacErrorType;
use proposed_traits::symm_cipher::BlockCipherMode;
use proposed_traits::symm_cipher::CipherMode;
use proposed_traits::symm_cipher::ErrorType as SymmCipherErrorType;

fn dsync_fence_full() {
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn write_reg(addr: u32, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

pub fn cache_data_invd_all() {
    const CACHE_AREA_OFFSET: u32 = 0x7E6E_2A50;
    const CACHE_INVAL_OFFSET: u32 = 0x7E6E_2A54;
    const CACHE_CTRL_OFFSET: u32 = 0x7E6E_2A58;

    const CACHE_AREA_VAL: u32 = 0x000F_FFFF;
    const CACHE_INVAL_VAL: u32 = 0x8660_0000;

    cortex_m::interrupt::free(|_| {
        write_reg(CACHE_CTRL_OFFSET, 0);
        dsync_fence_full();

        write_reg(CACHE_AREA_OFFSET, CACHE_AREA_VAL);
        write_reg(CACHE_INVAL_OFFSET, CACHE_INVAL_VAL);
        dsync_fence_full();

        write_reg(CACHE_CTRL_OFFSET, 1);
        dsync_fence_full();
    });

    write_reg(CACHE_CTRL_OFFSET, 0);
    dsync_fence_full();

    write_reg(CACHE_AREA_OFFSET, CACHE_AREA_VAL);
    write_reg(CACHE_INVAL_OFFSET, CACHE_INVAL_VAL);
    dsync_fence_full();

    write_reg(CACHE_CTRL_OFFSET, 1);
    dsync_fence_full();
}

const SHA1_IV: [u32; 8] = [
    0x0123_4567,
    0x89ab_cdef,
    0xfedc_ba98,
    0x7654_3210,
    0xf0e1_d2c3,
    0,
    0,
    0,
];

const SHA224_IV: [u32; 8] = [
    0xd89e_05c1,
    0x07d5_7c36,
    0x17dd_7030,
    0x3959_0ef7,
    0x310b_c0ff,
    0x1115_5868,
    0xa78f_f964,
    0xa44f_fabe,
];

const SHA256_IV: [u32; 8] = [
    0x67e6_096a,
    0x85ae_67bb,
    0x72f3_6e3c,
    0x3af5_4fa5,
    0x7f52_0e51,
    0x8c68_059b,
    0xabd9_831f,
    0x19cd_e05b,
];

const SHA384_IV: [u32; 16] = [
    0x5d9d_bbcb,
    0xd89e_05c1,
    0x2a29_9a62,
    0x07d5_7c36,
    0x5a01_5991,
    0x17dd_7030,
    0xd8ec_2f15,
    0x3959_0ef7,
    0x6726_3367,
    0x310b_c0ff,
    0x874a_b48e,
    0x1115_5868,
    0x0d2e_0cdb,
    0xa78f_f964,
    0x1d48_b547,
    0xa44f_fabe,
];

const SHA512_IV: [u32; 16] = [
    0x67e6_096a,
    0x08c9_bcf3,
    0x85ae_67bb,
    0x3ba7_ca84,
    0x72f3_6e3c,
    0x2bf8_94fe,
    0x3af5_4fa5,
    0xf136_1d5f,
    0x7f52_0e51,
    0xd182_e6ad,
    0x8c68_059b,
    0x1f6c_3e2b,
    0xabd9_831f,
    0x6bbd_41fb,
    0x19cd_e05b,
    0x7921_7e13,
];

const SHA512_224_IV: [u32; 16] = [
    0xC837_3D8C,
    0xA24D_5419,
    0x6699_E173,
    0xD6D4_DC89,
    0xAEB7_FA1D,
    0x829C_FF32,
    0x14D5_9D67,
    0xCF9F_2F58,
    0x692B_6D0F,
    0xA84D_D47B,
    0x736F_E377,
    0x4289_C404,
    0xA885_9D3F,
    0xC836_1D6A,
    0xADE6_1211,
    0xA192_D691,
];

const SHA512_256_IV: [u32; 16] = [
    0x9421_3122,
    0x2CF7_2BFC,
    0xA35F_559F,
    0xC264_4CC8,
    0x6BB8_9323,
    0x51B1_536F,
    0x1977_3896,
    0xBDEA_4059,
    0xE23E_2896,
    0xE3FF_8EA8,
    0x251E_5EBE,
    0x9239_8653,
    0xFC99_012B,
    0xAAB8_852C,
    0xDC2D_B70E,
    0xA22C_C581,
];

const HACE_SHA_BE_EN: u32 = 1 << 3;
const HACE_CMD_ACC_MODE: u32 = 1 << 8;
pub const HACE_SG_EN: u32 = 1 << 18;
pub const HACE_SG_LAST: u32 = 1 << 31;

const HACE_ALGO_SHA1: u32 = 1 << 5;
const HACE_ALGO_SHA224: u32 = 1 << 6;
const HACE_ALGO_SHA256: u32 = (1 << 4) | (1 << 6);
const HACE_ALGO_SHA512: u32 = (1 << 5) | (1 << 6);
const HACE_ALGO_SHA384: u32 = (1 << 5) | (1 << 6) | (1 << 10);
const HACE_ALGO_SHA512_224: u32 = (1 << 5) | (1 << 6) | (1 << 10) | (1 << 11);
const HACE_ALGO_SHA512_256: u32 = (1 << 5) | (1 << 6) | (1 << 11);

// Crypto control registers
pub const ASPEED_HACE_SRC: u32 = 0x00;
pub const ASPEED_HACE_DEST: u32 = 0x04;
pub const ASPEED_HACE_CONTEXT: u32 = 0x08; // 8 byte aligned
pub const ASPEED_HACE_DATA_LEN: u32 = 0x0C;
pub const ASPEED_HACE_CMD: u32 = 0x10;

// HACE_CMD bit definitions
pub const HACE_CMD_AES_KEY_FROM_OTP: u32 = 1 << 24;
pub const HACE_CMD_MBUS_REQ_SYNC_EN: u32 = 1 << 20;
pub const HACE_CMD_DES_SG_CTRL: u32 = 1 << 19;
pub const HACE_CMD_SRC_SG_CTRL: u32 = 1 << 18;

pub const HACE_CMD_SINGLE_DES: u32 = 0;
pub const HACE_CMD_TRIPLE_DES: u32 = 1 << 17;

pub const HACE_CMD_AES_SELECT: u32 = 0;
pub const HACE_CMD_DES_SELECT: u32 = 1 << 16;

pub const HACE_CMD_CTR_IV_AES_128: u32 = 0;

pub const HACE_CMD_AES_KEY_HW_EXP: u32 = 1 << 13;
pub const HACE_CMD_ISR_EN: u32 = 1 << 12;

pub const HACE_CMD_DECRYPT: u32 = 0;
pub const HACE_CMD_ENCRYPT: u32 = 1 << 7;

// AES Modes
pub const HACE_CMD_MODE_MASK: u32 = 0x7 << 4;
pub const HACE_CMD_ECB: u32 = 0;
pub const HACE_CMD_CBC: u32 = 0x1 << 4;
pub const HACE_CMD_CFB: u32 = 0x2 << 4;
pub const HACE_CMD_OFB: u32 = 0x3 << 4;
pub const HACE_CMD_CTR: u32 = 0x4 << 4;

// AES Key sizes
pub const HACE_CMD_AES128: u32 = 0;
pub const HACE_CMD_AES192: u32 = 0x1 << 2;
pub const HACE_CMD_AES256: u32 = 0x2 << 2;

#[derive(Debug, Clone, Copy)]
pub struct Ecb;
impl CipherMode for Ecb {}
impl BlockCipherMode for Ecb {}

#[derive(Debug, Clone, Copy)]
pub struct Cbc;
impl CipherMode for Cbc {}
impl BlockCipherMode for Cbc {}

#[derive(Debug, Clone, Copy)]
pub struct Cfb;
impl CipherMode for Cfb {}
impl BlockCipherMode for Cfb {}

#[derive(Debug, Clone, Copy)]
pub struct Ofb;
impl CipherMode for Ofb {}
impl BlockCipherMode for Ofb {}

#[derive(Debug, Clone, Copy)]
pub struct Ctr;
impl CipherMode for Ctr {}
impl BlockCipherMode for Ctr {}

/// Common context cleanup functionality
pub trait ContextCleanup {
    fn cleanup_context(&mut self);
    fn cleanup_crypto_context(&mut self);
}

impl ContextCleanup for crate::hace_controller::HaceController<'_> {
    fn cleanup_context(&mut self) {
        let ctx = self.ctx_mut();
        ctx.bufcnt = 0;
        ctx.buffer.fill(0);
        ctx.digest.fill(0);
        ctx.digcnt = [0; 2];

        unsafe {
            self.hace.hace30().write(|w| w.bits(0));
        }
    }

    fn cleanup_crypto_context(&mut self) {
        let ctx = self.crypto_ctx_mut();
        ctx.ctx.fill(0);
        ctx.cmd = 0;
    }
}

#[derive(Default, Copy, Clone)]
pub struct AspeedSg {
    pub len: u32,
    pub addr: u32,
}

impl AspeedSg {
    #[must_use]
    pub const fn new() -> Self {
        Self { len: 0, addr: 0 }
    }

    #[must_use]
    pub fn phys_addr(&self) -> u32 {
        core::ptr::from_ref::<Self>(self) as u32
    }
}

#[repr(C)]
#[repr(align(64))]
pub struct AspeedCryptoContext {
    pub ctx: [u8; 64],
    pub src_sg: AspeedSg,
    pub dst_sg: AspeedSg,
    pub cmd: u32,
}

impl Default for AspeedCryptoContext {
    fn default() -> Self {
        Self {
            ctx: [0; 64],
            src_sg: AspeedSg::default(),
            dst_sg: AspeedSg::default(),
            cmd: 0,
        }
    }
}

impl AspeedCryptoContext {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ctx: [0; 64],
            src_sg: AspeedSg::new(),
            dst_sg: AspeedSg::new(),
            cmd: 0,
        }
    }
}

#[repr(C)]
#[repr(align(64))]
pub struct AspeedHashContext {
    pub sg: [AspeedSg; 2],
    pub digest: [u8; 64],
    pub method: u32,
    pub block_size: u32,
    pub key: [u8; 128],
    pub key_len: u32,
    pub ipad: [u8; 128],
    pub opad: [u8; 128],
    pub digcnt: [u64; 2],
    pub bufcnt: u32,
    pub buffer: [u8; 256],
    pub iv_size: u8,
}

impl Default for AspeedHashContext {
    fn default() -> Self {
        Self {
            sg: [AspeedSg::default(); 2],
            digest: [0; 64],
            method: 0,
            block_size: 0,
            key: [0; 128],
            key_len: 0,
            ipad: [0; 128],
            opad: [0; 128],
            digcnt: [0; 2],
            bufcnt: 0,
            buffer: [0; 256],
            iv_size: 0,
        }
    }
}

impl AspeedHashContext {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sg: [AspeedSg::new(), AspeedSg::new()],
            digest: [0; 64],
            method: 0,
            block_size: 0,
            digcnt: [0; 2],
            key: [0; 128],
            key_len: 0,
            ipad: [0; 128],
            opad: [0; 128],
            bufcnt: 0,
            buffer: [0; 256],
            iv_size: 0,
        }
    }
}

use core::cell::UnsafeCell;

/// Safe wrapper for section-placed context
struct SectionPlacedContext(UnsafeCell<AspeedHashContext>);

unsafe impl Sync for SectionPlacedContext {}

impl SectionPlacedContext {
    const fn new() -> Self {
        Self(UnsafeCell::new(AspeedHashContext::new()))
    }

    fn get(&self) -> *mut AspeedHashContext {
        self.0.get()
    }
}

/// Context specifically allocated in non-cacheable RAM section
#[link_section = ".ram_nc"]
static SHARED_HASH_CTX: SectionPlacedContext = SectionPlacedContext::new();

struct SectionPlacedCryptoContext(UnsafeCell<AspeedCryptoContext>);

unsafe impl Sync for SectionPlacedCryptoContext {}

impl SectionPlacedCryptoContext {
    const fn new() -> Self {
        Self(UnsafeCell::new(AspeedCryptoContext::new()))
    }

    fn get(&self) -> *mut AspeedCryptoContext {
        self.0.get()
    }
}

#[link_section = ".ram_nc"]
static SHARED_CRYPTO_CTX: SectionPlacedCryptoContext = SectionPlacedCryptoContext::new();

#[derive(Copy, Clone)]
pub enum HashAlgo {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
}

impl HashAlgo {
    #[must_use]
    pub const fn digest_size(&self) -> usize {
        match self {
            HashAlgo::SHA1 => 20,
            HashAlgo::SHA224 | HashAlgo::SHA512_224 => 28,
            HashAlgo::SHA256 | HashAlgo::SHA512_256 => 32,
            HashAlgo::SHA384 => 48,
            HashAlgo::SHA512 => 64,
        }
    }

    #[must_use]
    pub const fn block_size(&self) -> usize {
        match self {
            HashAlgo::SHA1 | HashAlgo::SHA224 | HashAlgo::SHA256 => 64,
            HashAlgo::SHA384 | HashAlgo::SHA512 | HashAlgo::SHA512_224 | HashAlgo::SHA512_256 => {
                128
            }
        }
    }

    #[must_use]
    pub const fn bitmask(&self) -> u32 {
        match self {
            HashAlgo::SHA1 => HACE_ALGO_SHA1,
            HashAlgo::SHA224 => HACE_ALGO_SHA224,
            HashAlgo::SHA256 => HACE_ALGO_SHA256,
            HashAlgo::SHA512 => HACE_ALGO_SHA512,
            HashAlgo::SHA384 => HACE_ALGO_SHA384,
            HashAlgo::SHA512_224 => HACE_ALGO_SHA512_224,
            HashAlgo::SHA512_256 => HACE_ALGO_SHA512_256,
        }
    }

    #[must_use]
    pub const fn iv(&self) -> &'static [u32] {
        match self {
            HashAlgo::SHA1 => &SHA1_IV,
            HashAlgo::SHA224 => &SHA224_IV,
            HashAlgo::SHA256 => &SHA256_IV,
            HashAlgo::SHA384 => &SHA384_IV,
            HashAlgo::SHA512 => &SHA512_IV,
            HashAlgo::SHA512_224 => &SHA512_224_IV,
            HashAlgo::SHA512_256 => &SHA512_256_IV,
        }
    }

    #[must_use]
    pub const fn iv_size(&self) -> usize {
        match self {
            HashAlgo::SHA1 => SHA1_IV.len(),
            HashAlgo::SHA224 => SHA224_IV.len(),
            HashAlgo::SHA256 => SHA256_IV.len(),
            HashAlgo::SHA384 => SHA384_IV.len(),
            HashAlgo::SHA512 => SHA512_IV.len(),
            HashAlgo::SHA512_224 => SHA512_224_IV.len(),
            HashAlgo::SHA512_256 => SHA512_256_IV.len(),
        }
    }

    #[must_use]
    pub fn hash_cmd(&self) -> u32 {
        const COMMON_FLAGS: u32 = HACE_CMD_ACC_MODE | HACE_SHA_BE_EN | HACE_SG_EN;
        COMMON_FLAGS | self.bitmask()
    }
}

pub struct HaceController<'ctrl> {
    pub hace: &'ctrl Hace,
    pub algo: HashAlgo,
    pub aspeed_hash_ctx: AspeedHashContext, // Own the context instead of using a pointer
    pub aspeed_crypto_ctx: AspeedCryptoContext,
}

impl<'ctrl> HaceController<'ctrl> {
    #[must_use]
    pub fn new(hace: &'ctrl Hace) -> Self {
        Self {
            hace,
            algo: HashAlgo::SHA256,
            aspeed_hash_ctx: AspeedHashContext::new(), // Create a new context instance
            aspeed_crypto_ctx: AspeedCryptoContext::new(),
        }
    }

    /// Get a mutable reference to the shared context in `.ram_nc` section
    /// This approach uses the section-placed context directly
    pub fn shared_ctx() -> *mut AspeedHashContext {
        SHARED_HASH_CTX.get()
    }

    pub fn shared_crypto_ctx() -> *mut AspeedCryptoContext {
        SHARED_CRYPTO_CTX.get()
    }
}

impl DigestErrorType for HaceController<'_> {
    type Error = Infallible;
}

impl MacErrorType for HaceController<'_> {
    type Error = Infallible;
}

#[derive(Debug)]
pub enum HaceCipherError {
    InvalidKeyLength,
    InvalidIvLength,
    InvalidDataLength,
    HardwareFailure,
    Busy,
    UnsupportedMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgo {
    Aes,
    Des,
    Tdes,
}

pub trait HasCryptoAlgo {
    fn algo() -> CryptoAlgo;
}

pub trait KeyMaterial {
    fn key_len(&self) -> usize;
    fn as_bytes(&self) -> &[u8];
}

impl SymmCipherErrorType for HaceController<'_> {
    type Error = HaceCipherError;
}

impl HaceController<'_> {
    pub fn ctx_mut(&mut self) -> &mut AspeedHashContext {
        unsafe { &mut *Self::shared_ctx() }
    }

    pub fn crypto_ctx_mut(&mut self) -> &mut AspeedCryptoContext {
        unsafe { &mut *Self::shared_crypto_ctx() }
    }

    pub fn start_hash_operation(&mut self, len: u32) {
        let ctx = self.ctx_mut();

        let src_addr = if (ctx.method & HACE_SG_EN) != 0 {
            ctx.sg.as_ptr() as u32
        } else {
            ctx.buffer.as_ptr() as u32
        };

        let digest_addr = ctx.digest.as_ptr() as u32;
        let method = ctx.method;

        unsafe {
            self.hace.hace1c().write(|w| w.hash_intflag().set_bit());
            self.hace.hace20().write(|w| w.bits(src_addr));
            self.hace.hace24().write(|w| w.bits(digest_addr));
            self.hace.hace28().write(|w| w.bits(digest_addr));
            self.hace.hace2c().write(|w| w.bits(len));
            self.hace.hace30().write(|w| w.bits(method));
            // blocking wait until hash engine ready
            while self.hace.hace1c().read().hash_intflag().bit_is_clear() {
                // wait for the hash operation to complete
                cortex_m::asm::nop();
            }
        }
    }

    pub fn copy_iv_to_digest(&mut self) {
        let iv = self.algo.iv();
        let iv_bytes =
            unsafe { core::slice::from_raw_parts(iv.as_ptr().cast::<u8>(), iv.len() * 4) };

        self.ctx_mut().digest[..iv_bytes.len()].copy_from_slice(iv_bytes);
    }

    pub fn hash_key(&mut self, key: &impl AsRef<[u8]>) {
        let key_bytes = key.as_ref();
        let key_len = key_bytes.len();
        let digest_len = self.algo.digest_size();

        self.ctx_mut().digcnt[0] = key_len as u64;
        self.ctx_mut().bufcnt = u32::try_from(key_len).expect("key_len too large to fit in u32");
        self.ctx_mut().buffer[..key_len].copy_from_slice(key_bytes);
        self.ctx_mut().method &= !HACE_SG_EN; // Disable SG mode for key hashing
        self.copy_iv_to_digest();
        self.fill_padding(0);
        let bufcnt = self.ctx_mut().bufcnt;
        self.start_hash_operation(bufcnt);

        let slice =
            unsafe { core::slice::from_raw_parts(self.ctx_mut().digest.as_ptr(), digest_len) };

        self.ctx_mut().key[..digest_len].copy_from_slice(slice);
        self.ctx_mut().ipad[..digest_len].copy_from_slice(slice);
        self.ctx_mut().opad[..digest_len].copy_from_slice(slice);
        self.ctx_mut().key_len =
            u32::try_from(digest_len).expect("digest_len too large to fit in u32");
    }

    pub fn fill_padding(&mut self, remaining: usize) {
        let ctx = self.ctx_mut();
        let block_size = ctx.block_size as usize;
        let bufcnt = ctx.bufcnt as usize;

        let index = (bufcnt + remaining) & (block_size - 1);
        let padlen = if block_size == 64 {
            if index < 56 {
                56 - index
            } else {
                64 + 56 - index
            }
        } else if index < 112 {
            112 - index
        } else {
            128 + 112 - index
        };

        ctx.buffer[bufcnt] = 0x80;
        ctx.buffer[bufcnt + 1..bufcnt + padlen].fill(0);

        if block_size == 64 {
            let bits = (ctx.digcnt[0] << 3).to_be_bytes();
            ctx.buffer[bufcnt + padlen..bufcnt + padlen + 8].copy_from_slice(&bits);
            ctx.bufcnt += u32::try_from(padlen + 8).expect("padlen + 8 too large to fit in u32");
        } else {
            let low = (ctx.digcnt[0] << 3).to_be_bytes();
            let high = ((ctx.digcnt[1] << 3) | (ctx.digcnt[0] >> 61)).to_be_bytes();

            ctx.buffer[bufcnt + padlen..bufcnt + padlen + 8].copy_from_slice(&high);
            ctx.buffer[bufcnt + padlen + 8..bufcnt + padlen + 16].copy_from_slice(&low);

            ctx.bufcnt += u32::try_from(padlen + 16).expect("padlen + 16 too large to fit in u32");
        }
    }

    fn crypto_mode_to_cmd<M: CipherMode + 'static>() -> Result<u32, HaceCipherError> {
        if TypeId::of::<M>() == TypeId::of::<Ecb>() {
            Ok(HACE_CMD_ECB)
        } else if TypeId::of::<M>() == TypeId::of::<Cbc>() {
            Ok(HACE_CMD_CBC)
        } else if TypeId::of::<M>() == TypeId::of::<Cfb>() {
            Ok(HACE_CMD_CFB)
        } else if TypeId::of::<M>() == TypeId::of::<Ofb>() {
            Ok(HACE_CMD_OFB)
        } else if TypeId::of::<M>() == TypeId::of::<Ctr>() {
            Ok(HACE_CMD_CTR)
        } else {
            Err(HaceCipherError::UnsupportedMode)
        }
    }

    pub fn assemble_cmd_from_key_mode<M, K>(
        key: &K,
    ) -> Result<(u32, bool, usize, usize), HaceCipherError>
    where
        M: CipherMode + 'static,
        K: HasCryptoAlgo + KeyMaterial,
    {
        let mut cmd = HACE_CMD_DES_SG_CTRL | HACE_CMD_SRC_SG_CTRL | HACE_CMD_MBUS_REQ_SYNC_EN;

        cmd |= Self::crypto_mode_to_cmd::<M>()?;

        let (is_aes, iv_len, key_len) = match K::algo() {
            CryptoAlgo::Aes => {
                cmd |= HACE_CMD_AES_SELECT | HACE_CMD_AES_KEY_HW_EXP;

                let kl = key.key_len();
                match kl {
                    16 => cmd |= HACE_CMD_AES128,
                    24 => cmd |= HACE_CMD_AES192,
                    32 => cmd |= HACE_CMD_AES256,
                    _ => return Err(HaceCipherError::InvalidKeyLength),
                }
                (true, 16usize, kl)
            }
            CryptoAlgo::Des => {
                if key.key_len() != 8 {
                    return Err(HaceCipherError::InvalidKeyLength);
                }
                cmd |= HACE_CMD_DES_SELECT;
                (false, 8usize, 8usize)
            }
            CryptoAlgo::Tdes => {
                if key.key_len() != 24 {
                    return Err(HaceCipherError::InvalidKeyLength);
                }
                cmd |= HACE_CMD_DES_SELECT | HACE_CMD_TRIPLE_DES;
                (false, 8usize, 24usize)
            }
        };

        Ok((cmd, is_aes, iv_len, key_len))
    }

    pub fn start_crypto_operation(&mut self, data_len: u32) {
        let (src_sg_ptr, dst_sg_ptr, ctx_ptr, cmd) = {
            let hw = self.crypto_ctx_mut();

            hw.src_sg.len = data_len | HACE_SG_LAST;
            hw.dst_sg.len = data_len | HACE_SG_LAST;

            let src = hw.src_sg.phys_addr();
            let dst = hw.dst_sg.phys_addr();
            let ctx = hw.ctx.as_ptr() as u32;
            let cmd = hw.cmd;

            (src, dst, ctx, cmd)
        };

        unsafe {
            self.hace.hace1c().write(|w| w.crypto_intflag().set_bit());

            self.hace.hace00().write(|w| w.bits(src_sg_ptr));
            self.hace.hace04().write(|w| w.bits(dst_sg_ptr));
            self.hace.hace08().write(|w| w.bits(ctx_ptr));
            self.hace.hace0c().write(|w| w.bits(data_len));
            self.hace.hace10().write(|w| w.bits(cmd));

            while self.hace.hace1c().read().crypto_intflag().bit_is_clear() {
                cortex_m::asm::nop();
            }
        }

        cache_data_invd_all();
    }

    #[must_use]
    pub fn needs_iv(cmd: u32) -> bool {
        (cmd & HACE_CMD_MODE_MASK) != HACE_CMD_ECB
    }

    #[must_use]
    pub fn mode_block_size(is_aes: bool) -> usize {
        if is_aes {
            16
        } else {
            8
        }
    }

    pub fn iv_slice_mut(ctx: &mut [u8; 64], is_aes: bool, n: usize) -> &mut [u8] {
        if is_aes {
            &mut ctx[0..n]
        } else {
            &mut ctx[8..8 + n]
        }
    }

    #[must_use]
    pub fn iv_slice(ctx: &[u8; 64], is_aes: bool, n: usize) -> &[u8] {
        if is_aes {
            &ctx[0..n]
        } else {
            &ctx[8..8 + n]
        }
    }
    pub fn key_slice_mut(ctx: &mut [u8; 64], key_len: usize) -> &mut [u8] {
        &mut ctx[16..16 + key_len]
    }

    #[must_use]
    pub fn iv_out_offset(is_aes: bool) -> usize {
        if is_aes {
            0
        } else {
            8
        }
    }
}
