use ast1060_pac::Hace;
use proposed_traits::mac::*;
use core::convert::Infallible;

#[link_section = ".ram_nc"]
static mut HMAC_CTX: AspeedHashContext = AspeedHashContext::new();


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
const HACE_SG_EN: u32 = 1 << 18;
const HACE_CMD_ACC_MODE: u32 = 1 << 8;

const HACE_ALGO_SHA1: u32 = 1 << 5;
const HACE_ALGO_SHA224: u32 = 1 << 6;
const HACE_ALGO_SHA256: u32 = (1 << 4) | (1 << 6);
const HACE_ALGO_SHA512: u32 = (1 << 5) | (1 << 6);
const HACE_ALGO_SHA384: u32 = (1 << 5) | (1 << 6) | (1 << 10);
const HACE_ALGO_SHA512_224: u32 = (1 << 5) | (1 << 6) | (1 << 10) | (1 << 11);
const HACE_ALGO_SHA512_256: u32 = (1 << 5) | (1 << 6) | (1 << 11);

#[derive(Default, Copy, Clone)]
pub struct AspeedSg {
    pub len: u32,
    pub addr: u32,
}

impl AspeedSg {
    pub const fn new() -> Self {
        Self { len: 0, addr: 0 }
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
    pub const fn digest_size(&self) -> usize {
        match self {
            HashAlgo::SHA1 => 20,
            HashAlgo::SHA224 | HashAlgo::SHA512_224 => 28,
            HashAlgo::SHA256 | HashAlgo::SHA512_256 => 32,
            HashAlgo::SHA384 => 48,
            HashAlgo::SHA512 => 64,
        }
    }

    pub const fn block_size(&self) -> usize {
        match self {
            HashAlgo::SHA1 | HashAlgo::SHA224 | HashAlgo::SHA256 => 64,
            HashAlgo::SHA384 | HashAlgo::SHA512 | HashAlgo::SHA512_224 | HashAlgo::SHA512_256 => {
                128
            }
        }
    }

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

    pub fn hash_cmd(&self) -> u32 {
        const COMMON_FLAGS: u32 = HACE_CMD_ACC_MODE | HACE_SHA_BE_EN | HACE_SG_EN;
        COMMON_FLAGS | self.bitmask()
    }
}

// MacAlgorithm implementation for HashAlgo
impl MacAlgorithm for HashAlgo {
    const OUTPUT_BITS: usize = 512; // Maximum size for all variants
    type MacOutput = [u8; 64]; // Use the maximum size for all variants
    type Key = [u8; 64]; // Use the maximum size for all variants
}

pub trait IntoHashAlgo {
    fn to_hash_algo() -> HashAlgo;
}

pub struct Digest48(pub [u8; 48]);

impl Default for Digest48 {
    fn default() -> Self {
        Digest48([0u8; 48])
    }
}

impl AsRef<[u8]> for Digest48 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Digest48 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

pub struct Digest64(pub [u8; 64]);
impl Default for Digest64 {
    fn default() -> Self {
        Digest64([0u8; 64])
    }
}

impl AsRef<[u8]> for Digest64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Digest64 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}


pub struct Sha1;
pub struct Sha224;
pub struct Sha256;
pub struct Sha384;
pub struct Sha512;

impl MacAlgorithm for Sha1 {
    const OUTPUT_BITS: usize = 160;
    type MacOutput = [u8; 20];
    type Key = [u8; 64];
}

impl MacAlgorithm for Sha224 {
    const OUTPUT_BITS: usize = 224;
    type MacOutput = [u8; 28];
    type Key = [u8; 64];
}

impl MacAlgorithm for Sha256 {
    const OUTPUT_BITS: usize = 256;
    type MacOutput = [u8; 32];
    type Key = [u8; 32];
}

impl MacAlgorithm for Sha384 {
    const OUTPUT_BITS: usize = 384;
    type MacOutput = Digest48; // Use Digest48 for 384 bits
    type Key = [u8; 48];
}

impl MacAlgorithm for Sha512 {
    const OUTPUT_BITS: usize = 512;
    type MacOutput = Digest64; // Use Digest64 for 512 bits
    type Key = [u8; 64];
}

impl Default for Sha256 {
    fn default() -> Self { Sha256 }
}

impl Default for Sha384 {
    fn default() -> Self { Sha384 }
}

impl Default for Sha512 {
    fn default() -> Self { Sha512 }
}

impl IntoHashAlgo for Sha256 {
    fn to_hash_algo() -> HashAlgo {
        HashAlgo::SHA256
    }
}

impl IntoHashAlgo for Sha384 {
    fn to_hash_algo() -> HashAlgo {
        HashAlgo::SHA384
    }
}

impl IntoHashAlgo for Sha512 {
    fn to_hash_algo() -> HashAlgo {
        HashAlgo::SHA512
    }
}

pub struct Controller<'ctrl> {
    pub hace: &'ctrl Hace,
    algo: HashAlgo,
    aspeed_hash_ctx: *mut AspeedHashContext,
}

impl<'ctrl> Controller<'ctrl> {
    pub fn new(hace: &'ctrl Hace) -> Self {
        Self {
            hace,
            algo: HashAlgo::SHA256,
            aspeed_hash_ctx: core::ptr::addr_of_mut!(HMAC_CTX),
        }
    }
}


impl<'a> ErrorType for Controller<'_> {
    type Error = Infallible;
}

impl Controller<'_> {
    pub fn ctx_mut(&mut self) -> &mut AspeedHashContext {
        unsafe { &mut *self.aspeed_hash_ctx }
    }

    fn start_hash_operation(&mut self, len: u32) {
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

    fn copy_iv_to_digest(&mut self) {
        let iv = self.algo.iv();
        let iv_bytes =
            unsafe { core::slice::from_raw_parts(iv.as_ptr() as *const u8, iv.len() * 4) };

        self.ctx_mut().digest[..iv_bytes.len()].copy_from_slice(iv_bytes);
    }

    fn hash_key(&mut self, key: &impl AsRef<[u8]>) {
        let key_bytes = key.as_ref();
        let key_len = key_bytes.len();
        let digest_len = self.algo.digest_size();

        self.ctx_mut().digcnt[0] = key_len as u64;
        self.ctx_mut().bufcnt = key_len as u32;
        self.ctx_mut().buffer[..key_len].copy_from_slice(key_bytes);
        self.ctx_mut().method &= !HACE_SG_EN; // Disable SG mode for key hashing
        self.copy_iv_to_digest();
        self.fill_padding(0);
        let bufcnt = self.ctx_mut().bufcnt;
        self.start_hash_operation(bufcnt as u32);

        let slice = unsafe {
            core::slice::from_raw_parts(self.ctx_mut().digest.as_ptr(), digest_len)
        };

        self.ctx_mut().key[..digest_len].copy_from_slice(slice);
        self.ctx_mut().ipad[..digest_len].copy_from_slice(slice);
        self.ctx_mut().opad[..digest_len].copy_from_slice(slice);
        self.ctx_mut().key_len = digest_len as u32;
    }

    fn fill_padding(&mut self, remaining: usize) {
        let ctx = &mut self.ctx_mut();
        let block_size = ctx.block_size as usize;
        let bufcnt = ctx.bufcnt as usize;

        let index = (bufcnt + remaining) & (block_size - 1);
        let padlen = if block_size == 64 {
            if index < 56 {
                56 - index
            } else {
                64 + 56 - index
            }
        } else {
            if index < 112 {
                112 - index
            } else {
                128 + 112 - index
            }
        };

        ctx.buffer[bufcnt] = 0x80;
        ctx.buffer[bufcnt + 1..bufcnt + padlen].fill(0);

        if block_size == 64 {
            let bits = (ctx.digcnt[0] << 3).to_be_bytes();
            ctx.buffer[bufcnt + padlen..bufcnt + padlen + 8].copy_from_slice(&bits);
            ctx.bufcnt += (padlen + 8) as u32;
        } else {
            let low = (ctx.digcnt[0] << 3).to_be_bytes();
            let high = ((ctx.digcnt[1] << 3) | (ctx.digcnt[0] >> 61)).to_be_bytes();

            ctx.buffer[bufcnt + padlen..bufcnt + padlen + 8].copy_from_slice(&high);
            ctx.buffer[bufcnt + padlen + 8..bufcnt + padlen + 16].copy_from_slice(&low);

            ctx.bufcnt += (padlen + 16) as u32;
        }
    }
}


impl<'ctrl, A> MacInit<A> for Controller<'ctrl>
where
    A: MacAlgorithm + IntoHashAlgo,
    A::MacOutput: Default + AsMut<[u8]>,
    A::Key: AsRef<[u8]>,
{
    type OpContext<'a> = OpContextImpl<'a, 'ctrl, A> where Self: 'a; // Define your OpContext type here

    fn init<'a>(&'a mut self, _algo: A, key: &A::Key) -> Result<Self::OpContext<'a>, Self::Error> {
        self.algo = A::to_hash_algo();
        self.ctx_mut().method = self.algo.hash_cmd();
        self.copy_iv_to_digest();
        self.ctx_mut().block_size = self.algo.block_size() as u32;
        self.ctx_mut().bufcnt = 0;
        self.ctx_mut().digcnt = [0; 2];
        self.ctx_mut().buffer.fill(0);
        self.ctx_mut().digest.fill(0);
        self.ctx_mut().ipad.fill(0);
        self.ctx_mut().opad.fill(0);
        self.ctx_mut().key.fill(0);

        if key.as_ref().len() > self.ctx_mut().key.len() {
            // hash key if it is too long
            self.hash_key(key);
        } else {
            self.ctx_mut().key[..key.as_ref().len()].copy_from_slice(key.as_ref());
            self.ctx_mut().ipad[..key.as_ref().len()].copy_from_slice(key.as_ref());
            self.ctx_mut().opad[..key.as_ref().len()].copy_from_slice(key.as_ref());
            self.ctx_mut().key_len = key.as_ref().len() as u32;
        }

        for i in 0..self.ctx_mut().block_size as usize {
            self.ctx_mut().ipad[i] ^= 0x36;
            self.ctx_mut().opad[i] ^= 0x5c;
        }

        Ok(OpContextImpl {
            controller: self,
            _phantom: core::marker::PhantomData,
        })
    }
}

pub struct OpContextImpl<'a, 'ctrl, A: MacAlgorithm + IntoHashAlgo> {
    pub controller: &'a mut Controller<'ctrl>,
    _phantom: core::marker::PhantomData<A>,
}

impl<'a, 'ctrl, A> ErrorType for OpContextImpl<'a, 'ctrl, A>
where
    A: MacAlgorithm + IntoHashAlgo,
{
    type Error = Infallible;
}

impl<'a, 'ctrl, A> MacOp for OpContextImpl<'a, 'ctrl, A>
where
    A: MacAlgorithm + IntoHashAlgo,
    A::MacOutput: Default + AsMut<[u8]>
{
    type Output = A::MacOutput;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let ctrl = &mut self.controller;
        let algo = ctrl.algo;
        let block_size = algo.block_size();
        let digest_size = algo.digest_size();
        let mut bufcnt: u32;

        {
            let ctx = ctrl.ctx_mut();
            ctx.digcnt[0] = block_size as u64;
            ctx.bufcnt = block_size as u32;

            // H(ipad + input)
            let ipad = &ctx.ipad[..block_size];
            ctx.buffer[..algo.block_size()].copy_from_slice(ipad);
            ctx.buffer[algo.block_size()..(algo.block_size() + input.len())].copy_from_slice(input);
            ctx.digcnt[0] += input.len() as u64;
            ctx.bufcnt += input.len() as u32;
            ctx.method &= !HACE_SG_EN; // Disable SG mode for key hashing
        }

        ctrl.fill_padding(0);
        bufcnt = ctrl.ctx_mut().bufcnt;
        ctrl.copy_iv_to_digest();
        ctrl.start_hash_operation(bufcnt);
        let slice = unsafe {
            core::slice::from_raw_parts(ctrl.ctx_mut().digest.as_ptr(), digest_size)
        };

        // H(opad + H(opad + hash sum))
        {
            let ctx = ctrl.ctx_mut();
            ctx.digcnt[0] = block_size as u64 + digest_size as u64;
            ctx.bufcnt = block_size as u32 + digest_size as u32;
            ctx.buffer[..block_size].copy_from_slice(&ctx.opad[..block_size]);
            ctx.buffer[block_size..(block_size + digest_size)]
                .copy_from_slice(slice);
        }
        ctrl.fill_padding(0);
        bufcnt = ctrl.ctx_mut().bufcnt;
        ctrl.copy_iv_to_digest();
        ctrl.start_hash_operation(bufcnt);

        Ok(())
    }

    fn finalize(self) -> Result<Self::Output, Self::Error> {
        let digest_size = self.controller.algo.digest_size();
        let ctx = self.controller.ctx_mut();


        let slice = unsafe {
            core::slice::from_raw_parts(ctx.digest.as_ptr(), digest_size)
        };

        let mut output = A::MacOutput::default();
        output.as_mut()[..digest_size].copy_from_slice(slice);

        let ctx = self.controller.ctx_mut();
        ctx.bufcnt = 0;
        ctx.buffer.fill(0);
        ctx.digest.fill(0);
        ctx.digcnt = [0; 2];

        unsafe {
            self.controller.hace.hace30().write(|w| w.bits(0));
        }

        Ok(output) // Return the final output
    }
}
