# Pcap Parser
All data was taken from this [link](https://springernature.figshare.com/articles/dataset/Tracffic_data_from_real_network_environment/28380347).

## Steps
1. Download the zip file on the linked website.
2. Unzip the file into a data directory.
3. Execute `cargo run` from the pcap directory.

The resulting `bras.bin` and `onu.bin` files will follow the convention of a 4 byte integer specifying the number of bytes in the payload, followed by the bytes of the payload.

