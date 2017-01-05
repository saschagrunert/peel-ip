//! Transport Layer packets
pub mod tcp;
pub mod tls;
pub mod udp;

use prelude::*;
use path::error::PathResult;

/// Track a connection based in the current parsing result and return the connection data
pub fn track_connection<'a>(path: Option<&'a mut PathIp>,
                            result: Option<&Vec<Layer>>,
                            src_port: u16,
                            dst_port: u16) -> PathResult<()> {
    // Get the identifier
    let identifier = match result {
        Some(vector) => match vector.get(1) {
            // IPv4
            Some(&Layer::Ipv4(ref p)) => Some(Identifier::new(IpAddr::V4(p.src), src_port,
                                                              IpAddr::V4(p.dst), dst_port,
                                                              p.protocol)),

            // IPv6
            Some(&Layer::Ipv6(ref p)) => Some(Identifier::new(IpAddr::V6(p.src), src_port,
                                                              IpAddr::V6(p.dst), dst_port,
                                                              p.next_header)),

            // Previous result found, but not the correct one
            _ => None,
        },
        None => None,
    };

    // Just track the connection, do nothing additional with the data
    if let (Some(path), Some(identifier)) = (path, identifier) {
        path.track(identifier)?;
    }

    Ok(())
}
