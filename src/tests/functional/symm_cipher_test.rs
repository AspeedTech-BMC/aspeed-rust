// Licensed under the Apache-2.0 license

use crate::hace_controller::{Cbc, Cfb, Ctr, Ecb, HaceController, HasCryptoAlgo, KeyMaterial, Ofb};
use crate::symmetric_cipher::{AesKey, CipherText, DesKey, HaceSymmetric, Iv, PlainText, TdesKey};
use crate::uart::UartController;
use embedded_io::Write;
use proposed_traits::common::{FromBytes, ToBytes};
use proposed_traits::symm_cipher::{BlockCipherMode, CipherInit, CipherOp};

use crate::tests::functional::cbc_test_vec::{
    Aes128CbcTestVec, Aes192CbcTestVec, Aes256CbcTestVec, DesCbcTestVec, TdesCbcTestVec,
};
use crate::tests::functional::cfb_test_vec::{
    Aes128CfbTestVec, Aes192CfbTestVec, Aes256CfbTestVec, DesCfbTestVec, TdesCfbTestVec,
};
use crate::tests::functional::ctr_test_vec::{
    Aes128CtrTestVec, Aes192CtrTestVec, Aes256CtrTestVec, DesCtrTestVec, TdesCtrTestVec,
};
use crate::tests::functional::ecb_test_vec::{
    Aes128EcbTestVec, Aes192EcbTestVec, Aes256EcbTestVec, DesEcbTestVec, TdesEcbTestVec,
};
use crate::tests::functional::ofb_test_vec::{
    Aes128OfbTestVec, Aes192OfbTestVec, Aes256OfbTestVec, DesOfbTestVec, TdesOfbTestVec,
};

fn print_hex_array(uart: &mut UartController, data: &[u8], bytes_per_line: usize) {
    for (i, b) in data.iter().enumerate() {
        if i % bytes_per_line == 0 {
            let _ = writeln!(uart, "\r");
        } else {
            let _ = write!(uart, " ");
        }
        let _ = write!(uart, "{b:02x}");
    }
    let _ = writeln!(uart);
}

fn key_bytes<K: KeyMaterial + HasCryptoAlgo>(k: &K) -> &[u8] {
    let klen = k.key_len();
    &k.as_bytes()[..klen]
}

// Pretty-print mode names via type.
trait ModeInfo {
    const NAME: &'static str;
}
impl ModeInfo for Cfb {
    const NAME: &'static str = "CFB";
}
impl ModeInfo for Ctr {
    const NAME: &'static str = "CTR";
}
impl ModeInfo for Ofb {
    const NAME: &'static str = "OFB";
}
impl ModeInfo for Cbc {
    const NAME: &'static str = "CBC";
}
impl ModeInfo for Ecb {
    const NAME: &'static str = "ECB";
}

// ------------------------- Generic runners -------------------------

struct IvModeCase<'a, K> {
    name: &'a str,
    key: &'a K,
    iv: &'a Iv,
    pt: &'a PlainText,
    ct_expected: &'a CipherText,
}

/// One generic runner for all IV modes: CFB / CTR / OFB / CBC.
fn run_iv_mode_case<M, K>(
    uart: &mut UartController,
    symm: &mut HaceSymmetric<'_, '_, K>,
    case: &IvModeCase<'_, K>,
    mode: M,
) where
    M: ModeInfo + BlockCipherMode + Copy + 'static,
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    // Encrypt
    {
        let mut ctx_enc = symm.init(case.key, case.iv, mode).unwrap();
        let ct: CipherText = ctx_enc.encrypt(case.pt.clone()).unwrap();

        let _ = write!(uart, "\r\n[{}] {} Encrypt Input (PT):", case.name, M::NAME);
        print_hex_array(uart, &case.pt.data[..case.pt.len], 16);
        let _ = write!(uart, "\r\n[{}] {} Encrypt Key:", case.name, M::NAME);
        print_hex_array(uart, key_bytes(case.key), 16);
        let _ = write!(uart, "\r\n[{}] {} Encrypt IV:", case.name, M::NAME);
        print_hex_array(uart, &case.iv.data[..case.iv.len], 16);
        let _ = write!(uart, "\r\n[{}] {} Encrypt Output (CT):", case.name, M::NAME);
        print_hex_array(uart, &ct.data[..case.ct_expected.len], 16);

        if ct.data[..case.ct_expected.len] == case.ct_expected.data[..case.ct_expected.len] {
            let _ = writeln!(uart, "\r\n[{}] ✅ Encrypt: PASS", case.name);
        } else {
            let _ = writeln!(uart, "\r\n[{}] ❌ Encrypt: FAIL", case.name);
        }
    }

    // Decrypt
    {
        let mut ctx_dec = symm.init(case.key, case.iv, mode).unwrap();
        let pt_out: PlainText = ctx_dec.decrypt(case.ct_expected.clone()).unwrap();

        let _ = write!(uart, "\r\n[{}] {} Decrypt Input (CT):", case.name, M::NAME);
        print_hex_array(uart, &case.ct_expected.data[..case.ct_expected.len], 16);
        let _ = write!(uart, "\r\n[{}] {} Decrypt Output (PT):", case.name, M::NAME);
        print_hex_array(uart, &pt_out.data[..pt_out.len], 16);

        if pt_out.data[..case.pt.len] == case.pt.data[..case.pt.len] {
            let _ = writeln!(uart, "\r\n[{}] ✅ Decrypt: PASS", case.name);
        } else {
            let _ = writeln!(uart, "\r\n[{}] ❌ Decrypt: FAIL", case.name);
        }
    }
}

/// ECB has no IV.
fn run_ecb_case_generic<K>(
    uart: &mut UartController,
    symm: &mut HaceSymmetric<'_, '_, K>,
    name: &str,
    key: &K,
    pt: &PlainText,
    ct_expected: &CipherText,
) where
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    let iv = Iv::NONE;

    // Encrypt
    {
        let mut ctx_enc = symm.init(key, &iv, Ecb).unwrap();
        let ct: CipherText = ctx_enc.encrypt(pt.clone()).unwrap();

        let _ = write!(uart, "\r\n[{name}] ECB Encrypt Input (PT):");
        print_hex_array(uart, &pt.data[..pt.len], 16);
        let _ = write!(uart, "\r\n[{name}] ECB Encrypt Key:");
        print_hex_array(uart, key_bytes(key), 16);
        let _ = write!(uart, "\r\n[{name}] ECB Encrypt Output (CT):");
        print_hex_array(uart, &ct.data[..ct_expected.len], 16);

        if ct.data[..ct_expected.len] == ct_expected.data[..ct_expected.len] {
            let _ = writeln!(uart, "\r\n[{name}] ✅ Encrypt: PASS");
        } else {
            let _ = writeln!(uart, "\r\n[{name}] ❌ Encrypt: FAIL");
        }
    }

    // Decrypt
    {
        let mut ctx_dec = symm.init(key, &iv, Ecb).unwrap();
        let pt_out: PlainText = ctx_dec.decrypt(ct_expected.clone()).unwrap();

        let _ = write!(uart, "\r\n[{name}] ECB Decrypt Input (CT):");
        print_hex_array(uart, &ct_expected.data[..ct_expected.len], 16);
        let _ = write!(uart, "\r\n[{name}] ECB Decrypt Output (PT):");
        print_hex_array(uart, &pt_out.data[..pt_out.len], 16);

        if pt_out.data[..pt.len] == pt.data[..pt.len] {
            let _ = writeln!(uart, "\r\n[{name}] ✅ Decrypt: PASS");
        } else {
            let _ = writeln!(uart, "\r\n[{name}] ❌ Decrypt: FAIL");
        }
    }
}

// ------------------------- Tiny macros on top of generics -------------------------

macro_rules! run_ivmode_tv {
    ($mode:expr, $uart:expr, $symm:expr, $label:expr, $tv:expr) => {{
        let tv = $tv;
        let case = IvModeCase {
            name: $label,
            key: &tv.key,
            iv: &tv.iv,
            pt: &tv.ptext,
            ct_expected: &tv.ctext,
        };
        run_iv_mode_case($uart, $symm, &case, $mode);
    }};
}

macro_rules! run_ecb_tv {
    ($uart:expr, $symm:expr, $label:expr, $tv:expr) => {{
        let tv = $tv;
        run_ecb_case_generic($uart, $symm, $label, &tv.key, &tv.ptext, &tv.ctext);
    }};
}

// ------------------------- Per-suite wrappers -------------------------

fn run_aes_cbc_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, AesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running AES-CBC tests...");
    run_ivmode_tv!(Cbc, uart, &mut symm, "AES-128", Aes128CbcTestVec::new());
    run_ivmode_tv!(Cbc, uart, &mut symm, "AES-192", Aes192CbcTestVec::new());
    run_ivmode_tv!(Cbc, uart, &mut symm, "AES-256", Aes256CbcTestVec::new());
}

fn run_des_cbc_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, DesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running DES-CBC tests...");
    run_ivmode_tv!(Cbc, uart, &mut symm, "DES", DesCbcTestVec::new());
}

fn run_tdes_cbc_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, TdesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running TDES-CBC tests...");
    run_ivmode_tv!(Cbc, uart, &mut symm, "TDES", TdesCbcTestVec::new());
}

fn run_aes_cfb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, AesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running AES-CFB tests...");
    run_ivmode_tv!(Cfb, uart, &mut symm, "AES-128", Aes128CfbTestVec::new());
    run_ivmode_tv!(Cfb, uart, &mut symm, "AES-192", Aes192CfbTestVec::new());
    run_ivmode_tv!(Cfb, uart, &mut symm, "AES-256", Aes256CfbTestVec::new());
}

fn run_des_cfb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, DesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running DES-CFB tests...");
    run_ivmode_tv!(Cfb, uart, &mut symm, "DES", DesCfbTestVec::new());
}

fn run_tdes_cfb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, TdesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running TDES-CFB tests...");
    run_ivmode_tv!(Cfb, uart, &mut symm, "TDES", TdesCfbTestVec::new());
}

fn run_aes_ctr_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, AesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running AES-CTR tests...");
    run_ivmode_tv!(Ctr, uart, &mut symm, "AES-128", Aes128CtrTestVec::new());
    run_ivmode_tv!(Ctr, uart, &mut symm, "AES-192", Aes192CtrTestVec::new());
    run_ivmode_tv!(Ctr, uart, &mut symm, "AES-256", Aes256CtrTestVec::new());
}

fn run_des_ctr_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, DesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running DES-CTR tests...");
    run_ivmode_tv!(Ctr, uart, &mut symm, "DES", DesCtrTestVec::new());
}

fn run_tdes_ctr_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, TdesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running TDES-CTR tests...");
    run_ivmode_tv!(Ctr, uart, &mut symm, "TDES", TdesCtrTestVec::new());
}

fn run_aes_ofb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, AesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running AES-OFB tests...");
    run_ivmode_tv!(Ofb, uart, &mut symm, "AES-128", Aes128OfbTestVec::new());
    run_ivmode_tv!(Ofb, uart, &mut symm, "AES-192", Aes192OfbTestVec::new());
    run_ivmode_tv!(Ofb, uart, &mut symm, "AES-256", Aes256OfbTestVec::new());
}

fn run_des_ofb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, DesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running DES-OFB tests...");
    run_ivmode_tv!(Ofb, uart, &mut symm, "DES", DesOfbTestVec::new());
}

fn run_tdes_ofb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, TdesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running TDES-OFB tests...");
    run_ivmode_tv!(Ofb, uart, &mut symm, "TDES", TdesOfbTestVec::new());
}

fn run_aes_ecb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, AesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running AES-ECB tests...");
    run_ecb_tv!(uart, &mut symm, "AES-128", Aes128EcbTestVec::new());
    run_ecb_tv!(uart, &mut symm, "AES-192", Aes192EcbTestVec::new());
    run_ecb_tv!(uart, &mut symm, "AES-256", Aes256EcbTestVec::new());
}

fn run_des_ecb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, DesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running DES-ECB tests...");
    run_ecb_tv!(uart, &mut symm, "DES", DesEcbTestVec::new());
}

fn run_tdes_ecb_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, TdesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running TDES-ECB tests...");
    run_ecb_tv!(uart, &mut symm, "TDES", TdesEcbTestVec::new());
}

// ------------------------- Entry point -------------------------

pub fn run_symm_cipher_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    run_aes_cbc_tests(uart, &mut *hace);
    run_des_cbc_tests(uart, &mut *hace);
    run_tdes_cbc_tests(uart, &mut *hace);

    run_aes_cfb_tests(uart, &mut *hace);
    run_des_cfb_tests(uart, &mut *hace);
    run_tdes_cfb_tests(uart, &mut *hace);

    run_aes_ctr_tests(uart, &mut *hace);
    run_des_ctr_tests(uart, &mut *hace);
    run_tdes_ctr_tests(uart, &mut *hace);

    run_aes_ofb_tests(uart, &mut *hace);
    run_des_ofb_tests(uart, &mut *hace);
    run_tdes_ofb_tests(uart, &mut *hace);

    run_aes_ecb_tests(uart, &mut *hace);
    run_des_ecb_tests(uart, &mut *hace);
    run_tdes_ecb_tests(uart, &mut *hace);
}
