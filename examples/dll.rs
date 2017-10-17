extern crate pe_load;

use std::fs::File;
use std::io::prelude::*;

const PATH: &'static str = "F:\\Programming\\C++\\call\\build\\Debug\\call.dll";

fn main() {
    let mut file = File::open(PATH).expect("couldn't open file");
    let mut contents = vec![];
    file.read_to_end(&mut contents).expect("couldn't read file");
    let loader = pe_load::Loader::new(contents);
    let loaded = loader.load().expect("couldn't load .exe");
    let entry = loaded.entry_point.expect("entry point is empty");
    pe_load::wrapped_dll_main(entry)();
    println!("done");
}
