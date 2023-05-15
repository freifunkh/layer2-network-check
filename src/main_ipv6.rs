#![allow(clippy::option_map_unit_fn)]
mod utils;

use std::cmp;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv6Address, IpAddress, NdiscPrefixInformation, Icmpv6Repr};
use smoltcp::{
    phy::{wait as phy_wait, Device, Medium, RawSocket},
    time::Duration,
};
use smoltcp::socket::icmp;

use smoltcp::wire::{
    Icmpv6Packet, NdiscRepr, Ipv6Cidr
};

use byteorder::{ByteOrder, NetworkEndian};

use core::str::FromStr;
use std::env;

use std::fs;
use std::path::Path;

macro_rules! send_icmp_ping {
    ( $repr_type:ident, $packet_type:ident, $ident:expr, $seq_no:expr,
      $echo_payload:expr, $socket:expr, $remote_addr:expr ) => {{
        let icmp_repr = $repr_type::EchoRequest {
            ident: $ident,
            seq_no: $seq_no,
            data: &$echo_payload,
        };

        let icmp_payload = $socket.send(icmp_repr.buffer_len(), $remote_addr).unwrap();

        let icmp_packet = $packet_type::new_unchecked(icmp_payload);
        (icmp_repr, icmp_packet)
    }};
}

macro_rules! get_icmp_pong {
    ( $repr_type:ident, $repr:expr, $payload:expr, $waiting_queue:expr, $remote_addr:expr,
      $timestamp:expr, $received:expr ) => {{
        if let $repr_type::EchoReply { seq_no, data, .. } = $repr {
            if let Some(_) = $waiting_queue.get(&seq_no) {
                let packet_timestamp_ms = NetworkEndian::read_i64(data);
                println!(
                    "{} bytes from {}: icmp_seq={}, time={}ms",
                    data.len(),
                    $remote_addr,
                    seq_no,
                    $timestamp.total_millis() - packet_timestamp_ms
                );
                $waiting_queue.remove(&seq_no);
                $received += 1;
            }
        }
    }};
}

const IPV6_PREFIX_LINK_LOCAL_UNICAST : Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
const EUI64_MIDDLE_VALUE: [u8; 2] = [0xff, 0xfe];

pub fn mac_as_eui64(mac: &EthernetAddress) -> [u8; 8] {
    let mut bytes = [0; 8];
    let mac_bytes = mac.as_bytes();

    bytes[0..3].copy_from_slice(&mac_bytes[0..3]);
    bytes[3..5].copy_from_slice(&EUI64_MIDDLE_VALUE[..]);
    bytes[5..8].copy_from_slice(&mac_bytes[3..6]);

    bytes[0] ^= 1 << 1;

    return bytes;
}

pub fn ipv6_from_prefix(prefix: &Ipv6Address, mac: &EthernetAddress) -> Ipv6Address {
    let mut bytes : [u8; 16] = [0; 16];
    
    bytes[0..8].copy_from_slice(&prefix.as_bytes()[0..8]);
    bytes[8..16].copy_from_slice(&mac_as_eui64(mac));

    Ipv6Address::from_bytes(&bytes)
}

pub fn ipv6_is_global(ip: &Ipv6Address) -> bool {
    let bytes = ip.as_bytes();

    bytes[0] & 0xe0 == 0x20
}

fn main() {

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    opts.optopt(
        "r",
        "remote",
        "destination to send RA to",
        "LL_ADDR",
    );
    opts.optopt(
        "i",
        "interface",
        "iface to open raw socket on",
        "IFACE"
    );
    opts.optopt(
        "m",
        "mac",
        "mac to use for the raw socket",
        "MAC"
    );

    #[cfg(feature = "log")] {
        opts.optflag(
            "l",
            "log",
            "do extensive logging"
        );
    }

    let args = opts.parse(env::args().skip(1)).unwrap();

    #[cfg(feature = "log")] {
        if args.opt_present("l") {
            utils::setup_logging("");
        }
    }

    let remote_addr = args
        .opt_str("remote")
        .map(|s| Ipv6Address::from_str(&s).unwrap())
        .unwrap_or(Ipv6Address::LINK_LOCAL_ALL_ROUTERS);
    let iface_name = args
        .opt_str("interface")
        .unwrap_or("wlp3s0".into());

    let mut matches = utils::parse_options(&opts, free);
    //let device = utils::parse_tuntap_options(&mut matches);
    let device = RawSocket::new(&iface_name, Medium::Ethernet).unwrap();

    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    let mac_str = match args.opt_str("mac") {
        Some(mac_str) => mac_str,
        None => {
            let mac_str_file_content = fs::read_to_string(
                Path::new("/sys/class/net/")
                    .join(iface_name)
                    .join("address")).unwrap();
            mac_str_file_content.strip_suffix("\n").unwrap().to_owned()
        }
    };

    let mac = EthernetAddress::from_str(mac_str.as_str()).unwrap();
    println!("Using MAC: {}.", mac_str);

    // Create interface
    let mut config = match device.capabilities().medium {
        Medium::Ethernet => {
            Config::new(mac.into()).into()
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        Medium::Ieee802154 => todo!(),
    };
    config.random_seed = rand::random();
    let mut iface: Interface = Interface::new(config, &mut device);

    // Create sockets
    let mut dhcp_socket = dhcpv4::Socket::new();
    //dhcp_socket.set_ports(67, 68);

    // Set a ridiculously short max lease time to show DHCP renews work properly.
    // This will cause the DHCP client to start renewing after 5 seconds, and give up the
    // lease after 10 seconds if renew hasn't succeeded.
    // IMPORTANT: This should be removed in production.
    dhcp_socket.set_max_lease_duration(Some(Duration::from_secs(100)));

    let mut sockets = SocketSet::new(vec![]);
    let ll_prefix = &IPV6_PREFIX_LINK_LOCAL_UNICAST;
    let ll_addr = IpCidr::new(
        ipv6_from_prefix(ll_prefix, &mac).into_address(),
        64
    );
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(ll_addr.clone())
            .unwrap();
    });
    println!("Assigned IP: {}", ll_addr);

    // Create sockets
    let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
    let icmp_handle = sockets.add(icmp_socket);

    let mut send_at = Instant::from_millis(0);

    let mut sent = false;
    let mut selected_ip : Option<Ipv6Cidr> = None;
    let mut selected_router : Option<Ipv6Address> = None;

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let timestamp = Instant::now();
        let socket = sockets.get_mut::<icmp::Socket>(icmp_handle);
        if !socket.is_open() {
            // socket.bind(icmp::Endpoint::Ident(ident)).unwrap();
            //socket.bind(icmp::Endpoint::Unspecified).unwrap();
            socket.bind(icmp::Endpoint::IPv6Ndisc).unwrap();
            // router solicitations must be sent with hop_limit = 255
            socket.set_hop_limit(Some(255));
            send_at = timestamp;
        }

        if !sent && socket.can_send() && send_at <= timestamp {

            let icmp_repr = NdiscRepr::RouterSolicit {
                lladdr: Some(mac.into())
            };
    
            let icmp_payload = socket.send(icmp_repr.buffer_len(), remote_addr.into_address()).unwrap();
    
            let mut icmp_packet = Icmpv6Packet::new_unchecked(icmp_payload);

            icmp_repr.emit(&mut icmp_packet);
            sent = true;

            println!("Sent RS to {}", remote_addr);
        }

        if socket.can_recv() {
            let (payload, source_addr) = socket.recv().unwrap();

            let ip6_source_addr = match source_addr {
                IpAddress::Ipv6(ip6) => ip6,
                _ => {
                    break;
                }
            };

            let icmp_packet = Icmpv6Packet::new_checked(&payload).unwrap();
            let x = NdiscRepr::parse(&icmp_packet).unwrap();

            if let NdiscRepr::RouterAdvert { prefix_infos, router_lifetime, .. } = x {
                println!("RA received.");

                if remote_addr != Ipv6Address::LINK_LOCAL_ALL_ROUTERS && ip6_source_addr != remote_addr {
                    println!("Wrong source address. Ignoring.");
                    continue;
                }

                if router_lifetime.secs() == 0 {
                    println!("No default router.");
                    continue;
                }

                println!("Router lifetime: {}", router_lifetime.secs());

                for i in 0..8 {
                    if let Some(NdiscPrefixInformation { prefix, prefix_len, .. }) = prefix_infos[i] {
                        println!("Prefix: {}/{}", prefix, prefix_len);

                        let ip6 = ipv6_from_prefix(&prefix, &mac);
                        println!("IP: {}", ip6);

                        println!("Is global? {}", ipv6_is_global(&ip6));

                        if prefix_len != 64 {
                            println!("Prefix length must be 64.");
                        }

                        if ipv6_is_global(&ip6) {
                            selected_ip = Some(Ipv6Cidr::new(ip6, prefix_len));
                            selected_router = Some(ip6_source_addr);
                        }
                    }
                }
            }


            // let icmp_packet = Icmpv4Packet::new_checked(&payload).unwrap();
            // let icmp_repr = Icmpv4Repr::parse(&icmp_packet, &device_caps.checksum).unwrap();
            // get_icmp_pong!(
            //     Icmpv4Repr,
            //     icmp_repr,
            //     payload,
            //     waiting_queue,
            //     remote_addr,
            //     timestamp,
            //     received
            // );
        }

        // let timestamp = Instant::now();
        // match iface.poll_at(timestamp, &sockets) {
        //     Some(poll_at) if timestamp < poll_at => {
        //         let resume_at = cmp::min(poll_at, send_at);
        //         phy_wait(fd, Some(resume_at - timestamp)).expect("wait error");
        //     }
        //     Some(_) => (),
        //     None => {
        //         phy_wait(fd, Some(send_at - timestamp)).expect("wait error");
        //     }
        // }

        if selected_ip.is_some() {
            break;
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }

    sockets.remove(icmp_handle);

    println!("Assigned IP: {}", selected_ip.unwrap());
    println!("Assigned Router: {}", selected_router.unwrap());

    set_ipv6_addr(&mut iface, selected_ip.unwrap());

    iface.routes_mut().add_default_ipv6_route(selected_router.unwrap()).unwrap();

    // Create sockets
    let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
    let icmp_handle = sockets.add(icmp_socket);

    let mut send_at = Instant::from_millis(0);
    let mut seq_no = 0;
    let mut received = 0;
    let mut echo_payload = [0xffu8; 40];
    let mut waiting_queue = HashMap::new();
    let ident = 0x22b;

    let remote_addr = IpAddress::v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844); // from("2001:4860:4860:0:0:0:0:8844");

    let count = 4;
    let timeout = Duration::from_secs(1);
    let interval = Duration::from_secs(1);
    let device_caps = device.capabilities();

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, &mut device, &mut sockets);

        let timestamp = Instant::now();
        let socket = sockets.get_mut::<icmp::Socket>(icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::Ident(ident)).unwrap();
            send_at = timestamp;
        }

        if socket.can_send() && seq_no < count as u16 && send_at <= timestamp {
            NetworkEndian::write_i64(&mut echo_payload, timestamp.total_millis());

            let (icmp_repr, mut icmp_packet) = send_icmp_ping!(
                Icmpv6Repr,
                Icmpv6Packet,
                ident,
                seq_no,
                echo_payload,
                socket,
                remote_addr
            );
            icmp_repr.emit(
                &iface.ipv6_addr().unwrap().into_address(),
                &remote_addr,
                &mut icmp_packet,
                &device_caps.checksum,
            );

            waiting_queue.insert(seq_no, timestamp);
            seq_no += 1;
            send_at += interval;
        }

        if socket.can_recv() {
            let (payload, _) = socket.recv().unwrap();

            let icmp_packet = Icmpv6Packet::new_checked(&payload).unwrap();
            let icmp_repr = Icmpv6Repr::parse(
                &remote_addr,
                &iface.ipv6_addr().unwrap().into_address(),
                &icmp_packet,
                &device_caps.checksum,
            ).unwrap();
            get_icmp_pong!(
                Icmpv6Repr,
                icmp_repr,
                payload,
                waiting_queue,
                remote_addr,
                timestamp,
                received
            );
        }

        waiting_queue.retain(|seq, from| {
            if timestamp - *from < timeout {
                true
            } else {
                println!("From {remote_addr} icmp_seq={seq} timeout");
                false
            }
        });

        if seq_no == count as u16 && waiting_queue.is_empty() {
            break;
        }

        let timestamp = Instant::now();
        match iface.poll_at(timestamp, &sockets) {
            Some(poll_at) if timestamp < poll_at => {
                let resume_at = cmp::min(poll_at, send_at);
                phy_wait(fd, Some(resume_at - timestamp)).expect("wait error");
            }
            Some(_) => (),
            None => {
                phy_wait(fd, Some(send_at - timestamp)).expect("wait error");
            }
        }
    }

    println!("--- {remote_addr} ping statistics ---");
    println!(
        "{} packets transmitted, {} received, {:.0}% packet loss",
        seq_no,
        received,
        100.0 * (seq_no - received) as f64 / seq_no as f64
    );
}

fn set_ipv6_addr(iface: &mut Interface, cidr: Ipv6Cidr) {
    iface.update_ip_addrs_without_flushing_cache(|addrs| {
        if cidr.address() == Ipv6Address::UNSPECIFIED {
            return;
        }

        let old_addr = addrs.pop();
        if let Some(addr) = old_addr {
            println!("deconfigured IP {}", addr);
        }

        addrs
            .push(IpCidr::Ipv6(cidr))
            .unwrap();
        println!("configured IP {}....", cidr);

    });
}