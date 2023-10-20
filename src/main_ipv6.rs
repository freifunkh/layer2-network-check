#![allow(clippy::option_map_unit_fn)]
mod utils;

extern crate libc;

use std::os::unix::io::RawFd;

use std::cmp;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;

use smoltcp::iface::{Config, Interface, SocketSet, SocketHandle};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv6Address, IpAddress,
    NdiscPrefixInformation, Icmpv6Repr, RawHardwareAddress};
use smoltcp::{
    phy::{wait as phy_wait, Device, Medium, RawSocket},
    time::Duration,
};
use smoltcp::socket::icmp::{self, Socket};

use smoltcp::wire::{
    Icmpv6Packet, NdiscRepr, Ipv6Cidr
};

use byteorder::{ByteOrder, NetworkEndian};

use core::str::FromStr;
use std::env;

use std::fs;
use std::path::Path;

use rand::Rng;

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
      $timestamp:expr, $received:expr, $verbose:expr ) => {{
        if let $repr_type::EchoReply { seq_no, data, .. } = $repr {
            if let Some(_) = $waiting_queue.get(&seq_no) {
                let packet_timestamp_ms = NetworkEndian::read_i64(data);
                if $verbose {
                    println!(
                        "{} bytes from {}: icmp_seq={}, time={}ms",
                        data.len(),
                        $remote_addr,
                        seq_no,
                        $timestamp.total_millis() - packet_timestamp_ms
                    );
                }
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

pub fn emit_ipv6_rs(socket: &mut Socket, remote_addr: &Ipv6Address, source_mac: &EthernetAddress) {

    let icmp_repr = NdiscRepr::RouterSolicit {
        lladdr: Some(RawHardwareAddress::from(*source_mac))
    };

    let icmp_payload = socket.send(
        icmp_repr.buffer_len(),
        remote_addr.into_address()).unwrap();

    let mut icmp_packet = Icmpv6Packet::new_unchecked(icmp_payload);

    icmp_repr.emit(&mut icmp_packet);
}

pub fn parse_ipv6_ra_get_public_ipv6(payload: &[u8], mac: &EthernetAddress, verbose: bool) -> Option<Ipv6Cidr> {
    let icmp_packet = Icmpv6Packet::new_checked(&payload).unwrap();
    let x = NdiscRepr::parse(&icmp_packet).unwrap();

    if let NdiscRepr::RouterAdvert { prefix_infos, router_lifetime, .. } = x {
        if verbose {
            println!("RA received.");
        }

        if router_lifetime.secs() == 0 {
            if verbose {
                println!("No default router.");
            }
            return None;
        }

        if verbose {
            println!("Router lifetime: {}", router_lifetime.secs());
        }

        for i in 0..8 {
            if let Some(NdiscPrefixInformation { prefix, prefix_len, .. }) = prefix_infos[i] {
                if verbose {
                    println!("Prefix: {}/{}", prefix, prefix_len);
                }

                let ip6 = ipv6_from_prefix(&prefix, &mac);
                if verbose {
                    println!("IP: {}", ip6);
                    println!("Is global? {}", ipv6_is_global(&ip6));
                }

                if prefix_len != 64 {
                    if verbose {
                        println!("Prefix length must be 64.");
                    }
                    continue;
                }

                if ipv6_is_global(&ip6) {
                    return Some(Ipv6Cidr::new(ip6, prefix_len));
                }
            }
        }
    }

    return None;
}

struct NetworkState<'a> {
    sockets: SocketSet<'a>,
    device: RawSocket,
    iface: Interface,
    fd: i32
}

impl<'a> NetworkState<'a> {
    fn new(iface_name: &str, mac: &EthernetAddress) -> NetworkState<'a> {
        let mut device = RawSocket::new(&iface_name, Medium::Ethernet).unwrap();
        let fd = device.as_raw_fd();

        let mut config = match device.capabilities().medium {
            Medium::Ethernet => {
                Config::new((*mac).into()).into()
            }
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();
        let iface: Interface = Interface::new(config, &mut device);

        let sockets = SocketSet::new(vec![]);

        return NetworkState {
            sockets: sockets,
            device: device,
            iface: iface,
            fd: fd
        };
    }

    fn send_from_and_receive_to_sockets(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }
}

trait GetFDs {
    fn get_fds(&self) -> Vec<RawFd>;
}

impl<'a> GetFDs for Vec<NetworkState<'a>> {
    fn get_fds(&self) -> Vec<RawFd> {
        let mut res = Vec::new();
        for network_state in self.iter() {
            res.push(network_state.fd);
        }
        return res;
    }
}

trait NetworkTask<'a> {
    fn maybe_send<'b>(&mut self, now: Instant, network_state: &'b mut NetworkState<'a>);
    fn maybe_recv(&mut self, now: Instant, network_state: &mut NetworkState<'a>, verbose: bool);
    fn housekeeping(&mut self, now: Instant, verbose: bool);
    fn can_send(&self, network_state: &NetworkState<'a>) -> bool;
    fn can_recv(&self, network_state: &NetworkState<'a>) -> bool;
    fn is_finished(&self) -> bool;
}

struct PingTask<'a> {
    socket_handle: SocketHandle,

    // static data
    num_pings: u16,
    remote_addr: &'a Ipv6Address,
    ident: u16,
    interval: Duration,
    timeout: Duration,

    // dynamic data
    send_next_at: Instant,
    seq_no: u16,
    received: u16,
    waiting_queue: HashMap<u16, Instant>,
}

impl<'a> PingTask<'a> {
    fn new(network_state: &mut NetworkState<'a>, remote_addr: &'a Ipv6Address) -> PingTask<'a> {
        let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
        let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);

        let mut socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
        let mut rng = rand::thread_rng();
        let ident = rng.gen();

        socket.bind(icmp::Endpoint::Ident(ident)).unwrap();
        socket.set_hop_limit(Some(255));

        let socket_handle = network_state.sockets.add(socket);

        PingTask {
            socket_handle: socket_handle,
            num_pings: 4,
            remote_addr: remote_addr,
            ident: ident,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            send_next_at: Instant::now(),
            seq_no: 0,
            received: 0,
            waiting_queue: HashMap::new(),
        }
    }

    fn get_socket_mut<'b>(&self, network_state: &'b mut NetworkState<'a>) -> &'b mut icmp::Socket<'a> {
        network_state.sockets.get_mut::<icmp::Socket>(self.socket_handle)
    }

    fn get_socket<'b>(&self, network_state: &'b NetworkState<'a>) -> &'b icmp::Socket {
        network_state.sockets.get::<icmp::Socket>(self.socket_handle)
    }
}

impl<'a> NetworkTask<'a> for PingTask<'a> {

    fn can_send<'b>(&self, network_state: &'b NetworkState<'a>) -> bool {
        self.get_socket(network_state).can_send()
    }

    fn can_recv<'b>(&self, network_state: &'b NetworkState<'a>) -> bool {
        self.get_socket(network_state).can_recv()
    }

    fn maybe_send<'b>(&mut self, now: Instant, network_state: &'b mut NetworkState<'a>) {
        if self.send_next_at > now || self.seq_no >= self.num_pings {
            return;
        }

        let src_addr = &network_state.iface.ipv6_addr().unwrap().into_address();
        let device_caps = network_state.device.capabilities();
        let mut echo_payload = [0xffu8; 40];

        NetworkEndian::write_i64(&mut echo_payload, now.total_millis());

        let socket = self.get_socket_mut(network_state);
        let (icmp_repr, mut icmp_packet) = send_icmp_ping!(
            Icmpv6Repr,
            Icmpv6Packet,
            self.ident,
            self.seq_no,
            echo_payload,
            socket,
            self.remote_addr.into_address()
        );
        icmp_repr.emit(
            src_addr,
            &self.remote_addr.into_address(),
            &mut icmp_packet,
            &device_caps.checksum,
        );

        self.waiting_queue.insert(self.seq_no, now);
        self.seq_no += 1;
        self.send_next_at += self.interval;
    }

    fn maybe_recv(&mut self, now: Instant, network_state: &mut NetworkState<'a>, verbose: bool) {

        let dst_addr = &network_state.iface.ipv6_addr().unwrap().into_address();
        let device_caps = network_state.device.capabilities();

        let socket = self.get_socket_mut(network_state);
        let (payload, _) = socket.recv().unwrap();

        let icmp_packet = Icmpv6Packet::new_checked(&payload).unwrap();
        let maybe_icmp_repr = Icmpv6Repr::parse(
            &self.remote_addr.into_address(),
            dst_addr,
            &icmp_packet,
            &device_caps.checksum,
        );

        if let Ok(icmp_repr) = maybe_icmp_repr {
            get_icmp_pong!(
                Icmpv6Repr,
                icmp_repr,
                payload,
                self.waiting_queue,
                self.remote_addr,
                now,
                self.received,
                verbose
            );
        } else {
            println!("ignored packet");
        }
    }

    fn is_finished(&self) -> bool {
        self.seq_no >= self.num_pings && self.waiting_queue.is_empty()
    }

    fn housekeeping(&mut self, now: Instant, verbose: bool) {
        self.waiting_queue.retain(|seq, from| {
            let remote_addr = self.remote_addr;
            if now - *from < self.timeout {
                true
            } else {
                if verbose {
                    println!("From {remote_addr} icmp_seq={seq} timeout");
                }
                false
            }
        });
    }
}

fn obtain_public_ip6_via_ra(network_state: &mut NetworkState,
    remote_addr: &Ipv6Address, mac: & EthernetAddress, verbose: bool)
        -> Option<(Ipv6Cidr, Ipv6Address)>
{
    // Create sockets
    let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
    let icmp_socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
    let icmp_handle = network_state.sockets.add(icmp_socket);

    let mut send_at = Instant::from_millis(0);

    let mut selected_ip : Option<Ipv6Cidr> = None;
    let mut selected_router : Option<Ipv6Address> = None;

    let mut ra_remaining_attempts = 3;
    let ra_timeout = Duration::from_secs(1);

    loop {
        let timestamp = Instant::now();
        network_state.iface.poll(timestamp, &mut network_state.device, &mut network_state.sockets);

        let timestamp = Instant::now();
        let socket = network_state.sockets.get_mut::<icmp::Socket>(icmp_handle);
        if !socket.is_open() {
            socket.bind(icmp::Endpoint::IPv6Ndisc).unwrap();
            socket.set_hop_limit(Some(255));
            send_at = timestamp;
        }

        if socket.can_send() && send_at <= timestamp {

            if ra_remaining_attempts < 1 {
                break;
            }

            ra_remaining_attempts -= 1;

            emit_ipv6_rs(socket, &remote_addr, &mac);

            if verbose {
                println!("Sent RS to {}", remote_addr);
            }

            send_at = Instant::now() + ra_timeout;
        }

        if socket.can_recv() {
            let (payload, source_addr) = socket.recv().unwrap();

            let ip6_source_addr = match source_addr {
                IpAddress::Ipv6(ip6) => ip6,
                _ => {
                    break;
                }
            };

            if *remote_addr != Ipv6Address::LINK_LOCAL_ALL_ROUTERS && ip6_source_addr != *remote_addr {
                if verbose {
                    println!("Wrong source address. Ignoring.");
                }
                continue;
            }

            selected_ip = parse_ipv6_ra_get_public_ipv6(&payload, &mac, verbose);
            if selected_ip.is_some() {
                selected_router = Some(ip6_source_addr);
                break;
            }
        }

        phy_wait(network_state.fd, network_state.iface.poll_delay(timestamp, &network_state.sockets)).expect("wait error");
    }

    network_state.sockets.remove(icmp_handle);

    if selected_ip.is_some() {
        return Some((selected_ip.unwrap(), selected_router.unwrap()));
    }

    None
}


fn ping6<'a>(network_state: &mut NetworkState<'a>,
    remote_addr: &'a Ipv6Address, verbose: bool)
        -> u16
{
    let mut ping_task = PingTask::new(network_state, remote_addr);

    loop {
        let now = Instant::now();

        network_state.send_from_and_receive_to_sockets(now);

        let now = Instant::now();
        let can_send = ping_task.can_send(&network_state);
        if can_send {
            ping_task.maybe_send(now, network_state)
        }

        if ping_task.can_recv(&network_state) {
            ping_task.maybe_recv(now, network_state, verbose)
        }

        ping_task.housekeeping(now, verbose);

        if ping_task.is_finished() {
            break;
        }

        let timestamp = Instant::now();
        match network_state.iface.poll_at(timestamp, &network_state.sockets) {
            Some(poll_at) if timestamp < poll_at => {
                let resume_at = cmp::min(poll_at, ping_task.send_next_at);
                phy_wait(network_state.fd, Some(resume_at - timestamp)).expect("wait error");
            }
            Some(_) => (),
            None => {
                phy_wait(network_state.fd, Some(ping_task.send_next_at - timestamp)).expect("wait error");
            }
        }
    }

    if verbose {
        println!("--- {remote_addr} ping statistics ---");
        println!(
            "{} packets transmitted, {} received, {:.0}% packet loss",
            &ping_task.seq_no,
            &ping_task.received,
            100.0 * (ping_task.seq_no - ping_task.received) as f64 / ping_task.seq_no as f64
        );
    }

    return ping_task.received
}

fn print_json_result(address_obtained: bool, pings_sent: u16, pings_answered: u16) {
    println!("{{ \"address_obtained\": {}, \"echo_requests\": {{ \"sent\": {}, \"answered\": {} }} }}",
        address_obtained as i32, pings_sent, pings_answered);
}

fn main() {

    let (mut opts, _) = utils::create_options();

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
    opts.optopt(
        "",
        "allowed-drops",
        "number of icmp ping packets that can be lost while the return code is still ok. (Default: 1)",
        "NUM"
    );
    opts.optflag(
        "v",
        "verbose",
        "show verbose information"
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
    let ping_allowed_drops = args
        .opt_str("allowed-drops")
        .map(|s| s.parse().unwrap() )
        .unwrap_or(1);
    let verbose = args.opt_present("verbose");


    let mac_str = match args.opt_str("mac") {
        Some(mac_str) => mac_str,
        None => {
            let mac_str_file_content = fs::read_to_string(
                Path::new("/sys/class/net/")
                    .join(&iface_name)
                    .join("address")).unwrap();
            mac_str_file_content.strip_suffix("\n").unwrap().to_owned()
        }
    };

    let mac = EthernetAddress::from_str(mac_str.as_str()).unwrap();
    if verbose {
        println!("Using MAC: {}.", mac_str);
    }

    let ll_prefix = &IPV6_PREFIX_LINK_LOCAL_UNICAST;
    let ll_addr = Ipv6Cidr::new(
        ipv6_from_prefix(ll_prefix, &mac),
        64
    );

    let network_state = NetworkState::new(&iface_name, &mac);
    let network_state2 = NetworkState::new(&iface_name, &mac);

    let mut network_states = vec![network_state, network_state2];

    let fds = network_states.get_fds();

    set_ipv6_addr(&mut network_states[0].iface, ll_addr, verbose);
    set_ipv6_addr(&mut network_states[1].iface, ll_addr, verbose);

    let ra_result = obtain_public_ip6_via_ra(
        &mut network_states[0],
        &remote_addr,
        &mac,
        verbose
    );

    if ra_result.is_none() {
        if verbose {
            println!("Did not obtain a public ip via RA.");
        }
        print_json_result(false, 0, 0);
        std::process::exit(1);
    }

    let (selected_ip, selected_router) = ra_result.unwrap();

    if verbose {
        println!("Assigned IP: {}", selected_ip);
        println!("Assigned Router: {}", selected_router);
    }

    set_ipv6_addr(&mut network_states[0].iface, selected_ip, verbose);
    set_ipv6_addr(&mut network_states[1].iface, selected_ip, verbose);

    network_states[0].iface.routes_mut().add_default_ipv6_route(selected_router).unwrap();
    network_states[1].iface.routes_mut().add_default_ipv6_route(selected_router).unwrap();

    let remote_addr = Ipv6Address(
        [0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44]); // from("2001:4860:4860:0:0:0:0:8844");

    let received = ping6(
        &mut network_states[0],
        &remote_addr,
        verbose);

    let received2 = ping6(
        &mut network_states[1],
        &remote_addr,
        verbose);

    print_json_result(true, 4, received);
    print_json_result(true, 4, received2);

    if 4 - received > ping_allowed_drops {
        std::process::exit(1);
    }
}

fn set_ipv6_addr(iface: &mut Interface, cidr: Ipv6Cidr, verbose: bool) {
    iface.update_ip_addrs_without_flushing_cache(|addrs| {
        if cidr.address() == Ipv6Address::UNSPECIFIED {
            return;
        }

        let old_addr = addrs.pop();
        if let Some(addr) = old_addr {
            if verbose {
                println!("deconfigured IP {}", addr);
            }
        }

        addrs
            .push(IpCidr::Ipv6(cidr))
            .unwrap();
        if verbose {
            println!("configured IP {}....", cidr);
        }
    });
}