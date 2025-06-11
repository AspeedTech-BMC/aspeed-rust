use crate::uart::UartController;
use crate::hash::{Sha256, Sha384, Sha512, Controller, IntoHashAlgo};
use proposed_traits::digest::{DigestInit, DigestOp, DigestAlgorithm};
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

pub fn run_hash_tests(uart: &mut UartController, hace: &mut Controller) {
    let input = *b"hello_world";

    run_hash::<Sha256>(uart, hace, &input);
    run_hash::<Sha384>(uart, hace, &input);
    run_hash::<Sha512>(uart, hace, &input);
}

fn run_hash<A>(uart: &mut UartController, ctrl: &mut Controller, input: &[u8])
where
    A: DigestAlgorithm + IntoHashAlgo + Default,
    A::DigestOutput: Default + AsRef<[u8]> + AsMut<[u8]>,
{
    let mut ctx = ctrl.init(A::default()).unwrap();
    ctx.update(input).unwrap();
    let output = ctx.finalize().unwrap();

    print_input(uart, core::any::type_name::<A>(), input);
    print_hex_array(uart, output.as_ref(), 16);
}
