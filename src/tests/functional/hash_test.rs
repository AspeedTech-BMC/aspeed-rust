use crate::uart::UartController;
use crate::hash::{HaceController, HashAlgo};
use peripheral_traits_steven::digest::Digest;

use embedded_io::Write;

fn print_hex_array(uart: &mut UartController, data: &[u8], bytes_per_line: usize) {
    for (i, b) in data.iter().enumerate() {
        if i % bytes_per_line == 0 {
            writeln!(uart, "\r").unwrap();
        } else {
            write!(uart, " ").unwrap();
        }
        write!(uart, "{:02x}", b).unwrap();
    }
    writeln!(uart).unwrap();
}

fn print_input(uart: &mut UartController, algo: &str, input: &[u8]) {
    match core::str::from_utf8(input) {
        Ok(ascii) => {
            write!(uart, "\r\n{} of \"{}\" [", algo, ascii).unwrap();
        }
        Err(_) => {
            write!(uart, "\r\n{} of [", algo).unwrap();
        }
    }

    for (i, b) in input.iter().enumerate() {
        if i > 0 {
            write!(uart, ", ").unwrap();
        }
        write!(uart, "0x{:02x}", b).unwrap();
    }
    writeln!(uart, "]:").unwrap();
}

pub fn run_hash_tests(uart: &mut UartController, hace: &mut HaceController) {
    let mut input = *b"hello_world";
    run_hash(uart, hace, HashAlgo::SHA256, &mut input, 32);
    run_hash(uart, hace, HashAlgo::SHA384, &mut input, 48);
    run_hash(uart, hace, HashAlgo::SHA512, &mut input, 64);
}

fn run_hash(uart: &mut UartController, ctrl: &mut HaceController, algo: HashAlgo, input: &mut [u8], digest_len: usize) {
    let string_algo = match algo {
        HashAlgo::SHA1 => "SHA1",
        HashAlgo::SHA224 => "SHA224",
        HashAlgo::SHA256 => "SHA256",
        HashAlgo::SHA384 => "SHA384",
        HashAlgo::SHA512 => "SHA512",
        HashAlgo::SHA512_224 => "SHA512_224",
        HashAlgo::SHA512_256 => "SHA512_256",
    };

    ctrl.init(algo).unwrap();

    ctrl.update(input).unwrap();

    let mut output = [0u8; 64]; // max buffer
    ctrl.finalize(&mut output[..digest_len]).unwrap();

    print_input(uart, string_algo, input);
    print_hex_array(uart, &output[..digest_len], 16);
}

