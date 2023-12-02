#![allow(clippy::option_map_unit_fn)]
mod utils;

extern crate libc;

use std::cell::RefCell;
use std::os::unix::io::RawFd;

use std::{cmp, mem, io, ptr};
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;

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


/// Wait until given file descriptor becomes readable, but no longer than given timeout.
pub fn wait_fds(fds: Vec<RawFd>, duration: Option<Duration>) -> io::Result<()> {
    unsafe {
        let mut readfds = {
            let mut readfds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(readfds.as_mut_ptr());
            for fd in fds.iter() {
                libc::FD_SET(*fd, readfds.as_mut_ptr());
            }
            readfds.assume_init()
        };

        let mut writefds = {
            let mut writefds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(writefds.as_mut_ptr());
            writefds.assume_init()
        };

        let mut exceptfds = {
            let mut exceptfds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(exceptfds.as_mut_ptr());
            exceptfds.assume_init()
        };

        let mut timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let timeout_ptr = if let Some(duration) = duration {
            timeout.tv_sec = duration.secs() as libc::time_t;
            timeout.tv_usec = (duration.millis() * 1_000) as libc::suseconds_t;
            &mut timeout as *mut _
        } else {
            ptr::null_mut()
        };

        let res = libc::select(
            fds.iter().max().unwrap_or(&0).clone() + 1,
            &mut readfds,
            &mut writefds,
            &mut exceptfds,
            timeout_ptr,
        );
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}


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

fn min_option<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    // Returns the minimal of two options (if both are Some(_)).
    // Otherwise, it returns a or b depending which of which is Some(_)
    match (a, b) {
        (Some(a_val), Some(b_val)) => Some(cmp::min(a_val, b_val)),
        (Some(a_val), None) => Some(a_val),
        (None, Some(b_val)) => Some(b_val),
        (None, None) => None
    }
}

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
    fd: i32,

    tasks: Rc<RefCell<Vec<PingTask<'a>>>>,
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
            fd: fd,
            tasks: Rc::new(RefCell::new(vec![]))
        };
    }

    fn send_from_and_receive_to_sockets(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    fn next_wakeup_at(&self) -> Option<Instant> {
        let mut res: Option<Instant> = None;

        for task in self.tasks.borrow().iter() {
            res = min_option(res, task.next_wakeup_at());
        }

        return res;
    }

    fn add_task(&mut self, task: PingTask<'a>) {
        self.tasks.borrow_mut().push(task);
    }

    fn has_pending_tasks(&self) -> bool {
        let mut res = false;

        for task in self.tasks.borrow().iter() {
            res = res || !task.is_finished();
        }

        return res;
    }

    fn handle_tasks(&mut self, now: Instant, verbose: bool) {
        let tasks = self.tasks.clone();

        // tasks.borrow_mut() panics if tasks is already mutuably borrowed.
        for task in tasks.borrow_mut().iter_mut() {
            if task.is_finished() {
                continue;
            }

            task.do_everything(self, now, verbose);
        }
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
    fn do_everything(&mut self, network_state: &mut NetworkState<'a>, now: Instant, verbose: bool);
    fn next_wakeup_at(&self) -> Option<Instant>;
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

    // result data
    rtt: SlidingWindowRTT,
}

struct SlidingWindowRTT {
    data: Vec<f64>,
    window_length: usize,
    last_data_index: usize,
}

impl SlidingWindowRTT {
    fn new(window_length: usize) -> SlidingWindowRTT {
        SlidingWindowRTT {
            data: Vec::with_capacity(window_length),
            window_length: window_length,
            last_data_index: 0
        }
    }

    fn add_rtt(&mut self, new_data: f64) {
        if self.data.len() < self.window_length {
            // Sliding Window is not yet filled.
            self.data.push(new_data);
            self.last_data_index = self.data.len() - 1;
        } else {
            // Override existing values
            let new_index = (self.last_data_index + 1) % self.window_length;
            self.data[new_index] = new_data;
            self.last_data_index = new_index;
        }
    }

    fn add_lost_package(&mut self) {
        self.add_rtt(f64::NAN);
    }

    fn avg_rtt(&self) -> Option<f64> {
        if self.data.is_empty() {
            return None;
        }

        let mut sum = 0.0;
        let mut count : usize = 0;
        for d in self.data.iter() {
            if *d == f64::NAN {
                continue;
            }
            sum += d;
            count += 1;
        }
        Some(sum / count as f64)
    }

    fn avg_packageloss(&self) -> Option<f64> {
        if self.data.is_empty() {
            return None;
        }

        let mut count : usize = 0;
        for d in self.data.iter() {
            if *d == f64::NAN {
                count += 1;
            }
        }
        Some(count as f64 / self.data.len() as f64)
    }
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
            rtt: SlidingWindowRTT::new(30),
        }
    }

    fn get_socket_mut<'b>(&self, network_state: &'b mut NetworkState<'a>) -> &'b mut icmp::Socket<'a> {
        network_state.sockets.get_mut::<icmp::Socket>(self.socket_handle)
    }

    fn get_socket<'b>(&self, network_state: &'b NetworkState<'a>) -> &'b icmp::Socket {
        network_state.sockets.get::<icmp::Socket>(self.socket_handle)
    }

    fn all_pings_sent(&self) -> bool {
        self.seq_no >= self.num_pings
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

        let Ok(icmp_repr) = maybe_icmp_repr else {
            println!("ignored packet");
            return;
        };

        let Icmpv6Repr::EchoReply { seq_no, data, .. } = icmp_repr else {
            return;
        };

        if self.waiting_queue.get(&seq_no).is_none() {
            return;
        }

        let packet_timestamp_ms = NetworkEndian::read_i64(data);
        let rtt = now.total_millis() - packet_timestamp_ms;
        self.rtt.add_rtt(rtt as f64 * 0.001);
        self.waiting_queue.remove(&seq_no);
    }

    fn is_finished(&self) -> bool {
        self.all_pings_sent() && self.waiting_queue.is_empty()
    }

    fn next_wakeup_at(&self) -> Option<Instant> {
        if self.is_finished() {
            return None;
        }

        if self.all_pings_sent() {
            return Some(self.waiting_queue.values().min().unwrap().clone() + self.timeout);
        }

        return Some(self.send_next_at);
    }

    fn housekeeping(&mut self, now: Instant, verbose: bool) {
        self.waiting_queue.retain(|seq, from| {
            let remote_addr = self.remote_addr;
            if now - *from < self.timeout {
                true
            } else {
                self.rtt.add_lost_package();
                if verbose {
                    println!("From {remote_addr} icmp_seq={seq} timeout");
                }
                false
            }
        });
    }

    fn do_everything(&mut self, network_state: &mut NetworkState<'a>, now: Instant, verbose: bool) {
        if self.can_send(&network_state) {
            self.maybe_send(now, network_state)
        }

        if self.can_recv(&network_state) {
            self.maybe_recv(now, network_state, verbose)
        }

        self.housekeeping(now, verbose);
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


fn run_tasks_to_completion<'a>(network_states: &mut Vec<NetworkState<'a>>, verbose: bool) {

    loop {
        let now = Instant::now();

        let mut are_tasks_left = false;
        let mut min_poll_at = None;

        for network_state in network_states.iter_mut() {

            network_state.send_from_and_receive_to_sockets(now);

            let now: Instant = Instant::now();

            network_state.handle_tasks(now, verbose);

            if network_state.has_pending_tasks() {
                are_tasks_left = true;
            }

            let next_poll_at = network_state.iface.poll_at(now, &network_state.sockets);
            let next_wakeup_at = network_state.next_wakeup_at();

            min_poll_at = min_option(min_poll_at, min_option(next_poll_at, next_wakeup_at));
        }

        if min_poll_at.is_none() || !are_tasks_left {
            return;
        }

        let poll_at = min_poll_at.unwrap();

        if now < poll_at {
            wait_fds(network_states.get_fds(), Some(poll_at - now)).expect("error during wait");
        }
    }
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

    let ping_task = PingTask::new(&mut network_states[0], &remote_addr);
    let ping_task2 = PingTask::new(&mut network_states[1], &remote_addr);

    network_states[0].add_task(ping_task);
    network_states[1].add_task(ping_task2);

    run_tasks_to_completion(&mut network_states, verbose);

    println!("{}", network_states[0].tasks.clone().borrow()[0].rtt.avg_packageloss().unwrap_or(f64::NAN));
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