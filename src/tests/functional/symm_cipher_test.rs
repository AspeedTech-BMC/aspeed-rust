// Licensed under the Apache-2.0 license

use crate::hace_controller::{Cbc, Ecb, HaceController, HasCryptoAlgo, KeyMaterial};
use crate::symmetric_cipher::{AesKey, CipherText, DesKey, HaceSymmetric, Iv, PlainText, TdesKey};
use crate::uart::UartController;
use embedded_io::Write;
use proposed_traits::common::{FromBytes, ToBytes};
use proposed_traits::symm_cipher::{CipherInit, CipherOp};

use crate::tests::functional::cbc_test_vec::{
    Aes128CbcTestVec, Aes192CbcTestVec, Aes256CbcTestVec, DesCbcTestVec, TdesCbcTestVec,
};
use crate::tests::functional::ecb_test_vec::{
    Aes128EcbTestVec, Aes192EcbTestVec, Aes256EcbTestVec, DesEcbTestVec, TdesEcbTestVec,
};

fn print_hex_array(uart: &mut UartController, data: &[u8], bytes_per_line: usize) {
    for (i, b) in data.iter().enumerate() {
        if i % bytes_per_line == 0 {
            writeln!(uart, "\r").unwrap();
        } else {
            write!(uart, " ").unwrap();
        }
        write!(uart, "{b:02x}").unwrap();
    }
    writeln!(uart).unwrap();
}

struct CbcTest<'a, K> {
    name: &'a str,
    key: &'a K,
    iv: &'a Iv,
    pt: &'a PlainText,
    ct_expected: &'a CipherText,
    iv_out_expected: &'a Iv,
}

struct EcbTest<'a, K> {
    name: &'a str,
    key: &'a K,
    pt: &'a PlainText,
    ct_expected: &'a CipherText,
}
fn run_cbc_case<K>(
    uart: &mut UartController,
    symm: &mut HaceSymmetric<'_, '_, K>,
    t: &CbcTest<'_, K>,
) where
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    let klen = t.key.key_len();
    let kbytes = &t.key.as_bytes()[..klen];

    {
        let mut ctx_enc = symm.init(t.key, t.iv, Cbc).unwrap();
        let ct: CipherText = ctx_enc.encrypt(t.pt.clone()).unwrap();

        let _ = write!(uart, "\r\n[{}] CBC Encrypt Input (PT):", t.name);
        print_hex_array(uart, &t.pt.data[..t.pt.len], 16);
        let _ = write!(uart, "\r\n[{}] CBC Encrypt Key:", t.name);
        print_hex_array(uart, kbytes, 16);
        let _ = write!(uart, "\r\n[{}] CBC Encrypt IV:", t.name);
        print_hex_array(uart, &t.iv.data[..t.iv.len], 16);
        let _ = write!(uart, "\r\n[{}] CBC Encrypt Output (CT):", t.name);
        print_hex_array(uart, &ct.data[..t.ct_expected.len], 16);

        if ct.data[..t.ct_expected.len] == t.ct_expected.data[..t.ct_expected.len] {
            let _ = writeln!(uart, "\r\n[{}] ✅ Encrypt: PASS", t.name);
        } else {
            let _ = writeln!(uart, "\r\n[{}] ❌ Encrypt: FAIL", t.name);
        }
    }

    // Decrypt
    {
        let mut ctx_dec = symm.init(t.key, t.iv, Cbc).unwrap();
        let pt_out: PlainText = ctx_dec.decrypt(t.ct_expected.clone()).unwrap();

        let _ = write!(uart, "\r\n[{}] CBC Decrypt Input (CT):", t.name);
        print_hex_array(uart, &t.ct_expected.data[..t.ct_expected.len], 16);
        let _ = write!(uart, "\r\n[{}] CBC Decrypt IV(out):", t.name);
        print_hex_array(uart, &t.iv_out_expected.data[..t.iv_out_expected.len], 16);
        let _ = write!(uart, "\r\n[{}] CBC Decrypt Output (PT):", t.name);
        print_hex_array(uart, &pt_out.data[..pt_out.len], 16);

        if pt_out.data[..t.pt.len] == t.pt.data[..t.pt.len] {
            let _ = writeln!(uart, "\r\n[{}] ✅ Decrypt: PASS", t.name);
        } else {
            let _ = writeln!(uart, "\r\n[{}] ❌ Decrypt: FAIL", t.name);
        }
    }
}

fn run_ecb_case<K>(
    uart: &mut UartController,
    symm: &mut HaceSymmetric<'_, '_, K>,
    t: &EcbTest<'_, K>,
) where
    K: KeyMaterial + FromBytes + ToBytes + HasCryptoAlgo,
{
    let iv = Iv::NONE;
    let klen = t.key.key_len();
    let kbytes = &t.key.as_bytes()[..klen];

    // Encrypt
    {
        let mut ctx_enc = symm.init(t.key, &iv, Ecb).unwrap();
        let ct: CipherText = ctx_enc.encrypt(t.pt.clone()).unwrap();

        let _ = write!(uart, "\r\n[{}] ECB Encrypt Input (PT):", t.name);
        print_hex_array(uart, &t.pt.data[..t.pt.len], 16);
        let _ = write!(uart, "\r\n[{}] ECB Encrypt Key:", t.name);
        print_hex_array(uart, kbytes, 16);
        let _ = write!(uart, "\r\n[{}] ECB Encrypt Output (CT):", t.name);
        print_hex_array(uart, &ct.data[..t.ct_expected.len], 16);

        if ct.data[..t.ct_expected.len] == t.ct_expected.data[..t.ct_expected.len] {
            let _ = writeln!(uart, "\r\n[{}] ✅ Encrypt: PASS", t.name);
        } else {
            let _ = writeln!(uart, "\r\n[{}] ❌ Encrypt: FAIL", t.name);
        }
    }

    // Decrypt
    {
        let mut ctx_dec = symm.init(t.key, &iv, Ecb).unwrap();
        let pt_out: PlainText = ctx_dec.decrypt(t.ct_expected.clone()).unwrap();

        let _ = write!(uart, "\r\n[{}] ECB Decrypt Input (CT):", t.name);
        print_hex_array(uart, &t.ct_expected.data[..t.ct_expected.len], 16);
        let _ = write!(uart, "\r\n[{}] ECB Decrypt Key:", t.name);
        print_hex_array(uart, kbytes, 16);
        let _ = write!(uart, "\r\n[{}] ECB Decrypt Output (PT):", t.name);
        print_hex_array(uart, &pt_out.data[..pt_out.len], 16);

        if pt_out.data[..t.pt.len] == t.pt.data[..t.pt.len] {
            let _ = writeln!(uart, "\r\n[{}] ✅ Decrypt: PASS", t.name);
        } else {
            let _ = writeln!(uart, "\r\n[{}] ❌ Decrypt: FAIL", t.name);
        }
    }
}

macro_rules! run_cbc_tv {
    ($uart:expr, $symm:expr, $label:expr, $tv:expr) => {{
        let tv = $tv;
        let case = CbcTest {
            name: $label,
            key: &tv.key,
            iv: &tv.iv,
            pt: &tv.ptext,
            ct_expected: &tv.ctext,
            iv_out_expected: &tv.iv_out,
        };
        run_cbc_case($uart, $symm, &case);
    }};
}

macro_rules! run_ecb_tv {
    ($uart:expr, $symm:expr, $label:expr, $tv:expr) => {{
        let tv = $tv;
        let case = EcbTest {
            name: $label,
            key: &tv.key,
            pt: &tv.ptext,
            ct_expected: &tv.ctext,
        };
        run_ecb_case($uart, $symm, &case);
    }};
}

fn run_aes_cbc_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, AesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running AES-CBC tests...");
    run_cbc_tv!(uart, &mut symm, "AES-128", Aes128CbcTestVec::new());
    run_cbc_tv!(uart, &mut symm, "AES-192", Aes192CbcTestVec::new());
    run_cbc_tv!(uart, &mut symm, "AES-256", Aes256CbcTestVec::new());
}

fn run_des_cbc_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, DesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running DES-CBC tests...");
    run_cbc_tv!(uart, &mut symm, "DES", DesCbcTestVec::new());
}

fn run_tdes_cbc_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    let mut symm: HaceSymmetric<'_, '_, TdesKey> = HaceSymmetric {
        controller: hace,
        _key: core::marker::PhantomData,
    };
    let _ = writeln!(uart, "\r\n\n#################### Running TDES-CBC tests...");
    run_cbc_tv!(uart, &mut symm, "TDES", TdesCbcTestVec::new());
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

pub fn run_symm_cipher_tests(uart: &mut UartController, hace: &mut HaceController<'_>) {
    run_aes_cbc_tests(uart, &mut *hace);
    run_des_cbc_tests(uart, &mut *hace);
    run_tdes_cbc_tests(uart, &mut *hace);
    run_aes_ecb_tests(uart, &mut *hace);
    run_des_ecb_tests(uart, &mut *hace);
    run_tdes_ecb_tests(uart, &mut *hace);
}
