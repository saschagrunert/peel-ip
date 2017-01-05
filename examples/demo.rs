extern crate peel_ip;
use peel_ip::prelude::*;

extern crate pcap;
use pcap::{Active, Capture, Device};

extern crate rain;
use rain::Graph;

extern crate time;
use time::Duration;

use std::thread::{self, JoinHandle};
use std::sync::mpsc::{channel, Sender, Receiver};

type IpIdentifier = Identifier<IpProtocol>;

#[derive(Debug)]
struct Packet {
    identifier: IpIdentifier,
    length: usize,
}

impl Packet {
    fn new(identifier: IpIdentifier, length: usize) -> Packet {
        Packet {
            identifier: identifier,
            length: length,
        }
    }
}

pub fn main() {
    start().expect("Failed in main function");
}

fn start() -> Result<(), Box<Error>> {
    let (tx, rx) = channel();

    // Worker thread for capturing packets
    let capture = Device::lookup()?.open()?;
    let peel = PeelIp::new();
    let packet_capture = start_packet_capture_thread(capture, peel, tx);

    // Worker thread for doing the computation on packets
    let mut path: Path<IpProtocol, usize> = Path::new();
    path.timeout = Duration::seconds(4);
    let graph = Graph::with_prefix_length(10 /* TODO: 100 should fit good */);
    let computation = start_graph_drawing_thread(path, graph, rx);

    // Join the threads together
    computation.join().unwrap();
    packet_capture.join().unwrap();
    Ok(())
}

fn start_packet_capture_thread(mut capture: Capture<Active>, mut peel: PeelIp, tx: Sender<Packet>) -> JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(packet) = capture.next() {
            // Parse the packet
            if let Ok(res) = peel.traverse(packet.data, vec![]) {
                if let Some(identifier) = get_identifier(&res) {
                    let packet = Packet::new(identifier, packet.data.len());
                    tx.send(packet).unwrap();
                }
            }
        }
    })
}

fn start_graph_drawing_thread(mut path: Path<IpProtocol, usize>,
                              mut graph: Graph<u32>,
                              rx: Receiver<Packet>)
                              -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            thread::sleep(std::time::Duration::from_secs(2));

            // Get all pending values
            for packet in rx.try_iter() {
                // Track the connection as usual if no error happended
                match path.track(packet.identifier.clone()) {
                    Ok(connection) => {
                        connection.data.custom = Some(connection.data.custom.unwrap_or_default() + packet.length);
                        graph.add(connection.identifier,
                                 connection.data.custom.unwrap_or_default() as u32)
                            .is_ok();
                    }
                    Err(_) => {
                        graph.remove(&packet.identifier).is_ok();
                    }
                };

                // Flush connections with a timeout
                for identifier in path.flush() {
                    graph.remove(identifier).is_ok();
                }
            }

            // Print the graph
            graph.print().unwrap();
        }
    })
}

fn get_identifier(result: &Vec<Layer>) -> Option<IpIdentifier> {
    // Try to get the ports
    let ports = match result.get(2) {
        Some(&Layer::Tcp(ref tcp)) => Some((tcp.header.source_port, tcp.header.dest_port)),
        Some(&Layer::Udp(ref udp)) => Some((udp.header.source_port, udp.header.dest_port)),
        _ => None,
    };

    let identifier = match (result.get(1), ports) {
        (Some(&Layer::Ipv4(ref p)), Some((src_port, dst_port))) => {
            Some(Identifier::new(IpAddr::V4(p.src),
                                 src_port,
                                 IpAddr::V4(p.dst),
                                 dst_port,
                                 p.protocol))
        }
        (Some(&Layer::Ipv6(ref p)), Some((src_port, dst_port))) => {
            Some(Identifier::new(IpAddr::V6(p.src),
                                 src_port,
                                 IpAddr::V6(p.dst),
                                 dst_port,
                                 p.next_header))
        }
        // Previous result found, but not the correct one
        _ => None,
    };

    identifier
}
