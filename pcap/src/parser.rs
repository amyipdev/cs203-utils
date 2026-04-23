use etherparse::err::packet::SliceError;
use etherparse::{SlicedPacket, TransportSlice};

use separator::Separatable;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;

use std::fs;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

fn parse_packet(packet: &[u8]) -> Option<Vec<u8>> {
    match SlicedPacket::from_ethernet(packet) {
        Err(value) => {
            match value {
                SliceError::Len(_) => {}
                _ => println!("Err {:?}", value),
            };
            None
        }
        Ok(value) => {
            let v = match value.transport {
                Some(TransportSlice::Icmpv4(s)) => s.payload(),
                Some(TransportSlice::Icmpv6(s)) => s.payload(),
                Some(TransportSlice::Udp(s)) => s.payload(),
                Some(TransportSlice::Tcp(s)) => s.payload(),
                None => return None,
            };
            if v.is_empty() {
                return None;
            }
            Some(v.to_vec())
        }
    }
}

fn parse_pcap(path: &str) -> Vec<Vec<u8>> {
    let file = File::open(path).unwrap();

    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    let mut payloads: Vec<Vec<u8>> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {}
                    PcapBlockOwned::Legacy(b) => {
                        match parse_packet(b.data) {
                            Some(payload) => payloads.push(payload),
                            None => {}
                        };
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    payloads
}

pub fn parse_dir(data_dir: &str, data_name: &str) {
    let filename = Path::new(data_name).with_extension("bin");

    println!("Creating File: {:?}", filename);
    let write_file = File::create(filename).unwrap();
    let mut writer = BufWriter::new(write_file);

    let mut total_packets = 0;

    for entry in fs::read_dir(data_dir).unwrap() {
        let path = entry.unwrap().path();
        println!("\t- Processing file: {:?}", path);

        if path.is_file() {
            let payloads = parse_pcap(path.to_str().unwrap());
            total_packets += payloads.len();

            for payload in payloads {
                // payloads are stored as bytes in the format [len (4 byte int), payload]
                let len = payload.len() as u32;
                writer.write_all(&len.to_le_bytes()).unwrap(); // write 4 byte int in little endian
                writer.write_all(&payload).unwrap();
            }
        }
    }
    println!("Total packets = {}", total_packets.separated_string());
}
