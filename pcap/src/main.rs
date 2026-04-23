mod parser;

fn main() {
    parser::parse_dir("data/Anonymized_bras_dataset", "bras"); // pcap
    parser::parse_dir("data/Anonymized_onu_dataset", "onu"); // pcapng
}
