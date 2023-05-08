#![allow(clippy::option_map_unit_fn)]
mod utils;

use std::os::unix::io::AsRawFd;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv6Address, IpAddress, NdiscPrefixInformation};
use smoltcp::{
    phy::{wait as phy_wait, Device, Medium, RawSocket},
    time::Duration,
};
use smoltcp::socket::icmp;

use smoltcp::wire::{
    Icmpv6Packet, NdiscRepr
};


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
    #[cfg(feature = "log")]
    utils::setup_logging("");

    let (mut opts, mut free) = utils::create_options();
    utils::add_tuntap_options(&mut opts, &mut free);
    utils::add_middleware_options(&mut opts, &mut free);

    opts.optopt(
        "c",
        "count",
        "Amount of echo request packets to send (default: 4)",
        "COUNT",
    );
    opts.optopt(
        "i",
        "interval",
        "Interval between successive packets sent (seconds) (default: 1)",
        "INTERVAL",
    );
    opts.optopt(
        "",
        "timeout",
        "Maximum wait duration for an echo response packet (seconds) (default: 5)",
        "TIMEOUT",
    );

    let mut matches = utils::parse_options(&opts, free);
    //let device = utils::parse_tuntap_options(&mut matches);
    let device = RawSocket::new("wlp3s0", Medium::Ethernet).unwrap();

    let fd = device.as_raw_fd();
    let mut device =
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ false);

    // Mac is: e8:b1:fc:f6:4d:16
    let mac = EthernetAddress([0xe8, 0xb1, 0xfc, 0xf6, 0x4d, 0x16]);

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

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 13, 37), 64))
            .unwrap();
    });

    let remote_addr = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;

    // Create sockets
    let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
    let icmp_handle = sockets.add(icmp_socket);

    let mut send_at = Instant::from_millis(0);

    let mut sent = false;
    let mut selected_ip : Option<Ipv6Address> = None;
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
        }

        if socket.can_recv() {
            let (payload, _) = socket.recv().unwrap();

            let icmp_packet = Icmpv6Packet::new_checked(&payload).unwrap();
            let x = NdiscRepr::parse(&icmp_packet).unwrap();

            println!("can_recv()");

            if let NdiscRepr::RouterAdvert { prefix_infos, router_lifetime, .. } = x {
                println!("RA received.");

                if router_lifetime.secs() == 0 {
                    println!("No default router.");
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
                            selected_ip = Some(ip6);
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
}