extern crate pcap;

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
       format!( "{}.{}.{}.{}", self.saddr[0],self.saddr[1],self.saddr[2],self.saddr[3])
   }

   fn destination_ip(&self) -> String {
       format!( "{}.{}.{}.{}", self.daddr[0],self.daddr[1],self.daddr[2],self.daddr[3])
   }
}

fn main() {
    let mut cap = pcap::Capture::from_device("en5").unwrap().open().unwrap();
    // To capture all IPv4 HTTP packets to and from port 443, i.e. print only packets that contain data, not, for example, SYN and FIN packets and ACK-only packets. (IPv6 is left as an exercise for the reader.)
    cap.filter("tcp port 443 or 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)").unwrap();

    while let Ok(packet) = cap.next() {
        let eth = &packet.data[ETHERNET_HEADER_SIZE..];

        // TODO: Look into using byteorder crate or using transmute. This works but it's funky
        let ip_header: IpHeader = unsafe{
           std::ptr::read(eth.as_ptr() as *const _) 
        };

        println!("ip version: {}", (ip_header.ver_ihl & 0b11110000) >> 4 );
        print!("source IP: {} -> ", ip_header.source_ip() );
        println!("destination IP: {}", ip_header.destination_ip() )

    }
}
