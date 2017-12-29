extern crate pcap;
extern crate termion;
extern crate dns_lookup;

use std::collections::HashMap;
use dns_lookup::lookup_addr;

static ETHERNET_HEADER_SIZE: usize = 14;
#[derive(Debug)] // not necessary
#[repr(C)]
struct IpHeader{
    ver_ihl: u8,        // Version (4 bits) + Internet header length (4 bits)
    tos: u8,           // Type of service 
    tlen: u16,           // Total length 
    identification: u16, // Identification
    flags_fo: u16,       // Flags (3 bits) + Fragment offset (13 bits)
    ttl: u8,            // Time to live
    proto: u8,          // Protocol
    crc: u16,            // Header checksum
    saddr: [u8; 4],      // Source address
    daddr: [u8; 4],     // Destination address
}

impl IpHeader {
   fn source_ip(&self) -> String {
       format!( "{}.{}.{}.{}", self.saddr[0], self.saddr[1], self.saddr[2], self.saddr[3])
   }

   fn destination_ip(&self) -> String {
       format!( "{}.{}.{}.{}", self.daddr[0], self.daddr[1], self.daddr[2], self.daddr[3])
   }
}

fn main() {
    let mut cap = pcap::Capture::from_device("en0").unwrap().open().unwrap();
    // To capture all IPv4 HTTP packets to and from port 443, i.e. print only packets that contain data, not, for example, SYN and FIN packets and ACK-only packets.
    cap.filter("tcp port 443 or 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)").unwrap();

    let mut ip_count: HashMap<String, u16> = HashMap::new();
    println!("Starting to listen....", );
    while let Ok(packet) = cap.next() {
        println!("    Address    |    ip      ");
        println!("----------------------------");
        let eth = &packet.data[ETHERNET_HEADER_SIZE..];

        let ip_header: IpHeader = unsafe{
           std::ptr::read(eth.as_ptr() as *const _) 
        };

        if ip_header.source_ip() != "192.168.1.156" {
            // perform reverse lookup of IP address
            let ip: std::net::IpAddr = ip_header.source_ip().parse().unwrap();
            let hostname = lookup_addr(&ip).unwrap();
            // Ensures a value is in the entry by inserting the default if empty, and returns a mutable reference to the value in the entry.
            let counter = ip_count.entry(hostname).or_insert(1);
            *counter += 1;
        }
        
        for (address, count) in &ip_count {
            println!("address: {i}, count: {c}", i=address, c=count);
        }

        print!("{}{}", termion::clear::All, termion::cursor::Goto(1, 1));
    }
}
