#![allow(clippy::option_map_unit_fn)]
mod utils;

extern crate libc;

use std::cell::RefCell;
use std::net::TcpListener;
use std::os::unix::io::RawFd;
use std::io::{Write, Read};

use std::{cmp, mem, io, ptr};
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;

use smoltcp::iface::{Config, Interface, SocketSet, SocketHandle};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv6Address,
    NdiscPrefixInformation, Icmpv6Repr, RawHardwareAddress};
use smoltcp::{
    phy::{Device, Medium, RawSocket},
    time::Duration,
};
use smoltcp::socket::icmp::{self, Socket};

use smoltcp::wire::{
    Icmpv6Packet, NdiscRepr, Ipv6Cidr
};

use byteorder::{ByteOrder, NetworkEndian};

use core::str::FromStr;
use std::env;

use std::fs::{self, File};
use std::path::Path;

use rand::Rng;

use serde_derive::{Deserialize, Serialize};
use std::net::Ipv6Addr;


/// Wait until given file descriptor becomes readable, but no longer than given timeout.
pub fn wait_fds(fds: &Vec<RawFd>, duration: Option<Duration>) -> io::Result<()> {
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
    name: String,
    sockets: SocketSet<'a>,
    device: RawSocket,
    iface: Interface,
    fd: i32,

    tasks: Rc<RefCell<Vec<PingTask>>>,
}

impl<'a> NetworkState<'a> {
    fn new(iface_name: &str, mac: &EthernetAddress, name: String) -> NetworkState<'a> {
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
            name: name,
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

    fn add_task(&mut self, task: PingTask) {
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

struct PingTask {
    name: String,
    socket_handle: SocketHandle,

    // static data
    remote_addr: Ipv6Address,
    ident: u16,
    interval: Duration,
    timeout: Duration,

    // dynamic data
    send_next_at: Instant,
    seq_no: u16,
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
            if d.is_nan() {
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
            if d.is_nan() {
                count += 1;
            }
        }
        Some(count as f64 / self.data.len() as f64)
    }
}

impl<'a> PingTask {
    fn new(network_state: &mut NetworkState<'a>, remote_addr: Ipv6Address, name: String) -> PingTask {
        let icmp_rx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);
        let icmp_tx_buffer = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; 256]);

        let mut socket = icmp::Socket::new(icmp_rx_buffer, icmp_tx_buffer);
        let mut rng = rand::thread_rng();
        let ident = rng.gen();

        socket.bind(icmp::Endpoint::Ident(ident)).unwrap();
        socket.set_hop_limit(Some(255));

        let socket_handle = network_state.sockets.add(socket);

        PingTask {
            name: name,
            socket_handle: socket_handle,
            remote_addr: remote_addr,
            ident: ident,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            send_next_at: Instant::now(),
            seq_no: 0,
            waiting_queue: HashMap::new(),
            rtt: SlidingWindowRTT::new(30),
        }
    }

    fn get_socket_mut<'b>(&self, network_state: &'b mut NetworkState<'a>) -> &'b mut icmp::Socket<'a> {
        network_state.sockets.get_mut::<icmp::Socket>(self.socket_handle)
    }

    fn get_socket<'b>(&'b self, network_state: &'b NetworkState<'a>) -> &icmp::Socket {
        network_state.sockets.get::<icmp::Socket>(self.socket_handle)
    }
}

impl<'a> NetworkTask<'a> for PingTask {

    fn can_send<'b>(&self, network_state: &'b NetworkState<'a>) -> bool {
        self.get_socket(network_state).can_send()
    }

    fn can_recv<'b>(&self, network_state: &'b NetworkState<'a>) -> bool {
        self.get_socket(network_state).can_recv()
    }

    fn maybe_send<'b>(&mut self, now: Instant, network_state: &'b mut NetworkState<'a>) {
        if self.send_next_at > now {
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

    fn maybe_recv(&mut self, now: Instant, network_state: &mut NetworkState<'a>, _verbose: bool) {

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
        false // run infinitely
    }

    fn next_wakeup_at(&self) -> Option<Instant> {
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

fn run_tasks_to_completion<'a>(network_states: &mut Vec<NetworkState<'a>>, verbose: bool) {
    let listener = TcpListener::bind("127.0.0.1:12123").expect("Error during bind of the TcpListener");
    listener.set_nonblocking(true).expect("Cannot set non-blocking");

    let mut fds = network_states.get_fds();
    fds.push(listener.as_raw_fd());

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

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    for network_state in network_states.iter() {
                        let network_tasks = network_state.tasks.clone();
                        for task in network_tasks.borrow().iter() {
                            let vars = format!("context=\"{}\",target=\"{}\"", network_state.name.replace(" ", "\\ "), task.name.replace(" ", "\\ "));
                            let packageloss = task.rtt.avg_packageloss().unwrap_or(f64::NAN);
                            let rtt = task.rtt.avg_rtt().unwrap_or(f64::NAN);

                            let write_res = writeln!(stream, "netcheck,{vars} packageloss={packageloss},rtt={rtt}");
                            if let Err(err) = write_res {
                                println!("Tcp socket write failed: {}", err);
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        eprintln!("Fehler beim Akzeptieren einer Verbindung: {}", e);
                    }
                    break;
                }
            }
        }

        if now < poll_at {
            wait_fds(&fds, Some(poll_at - now)).expect("error during wait");
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Target {
    ip: Ipv6Addr,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Context {
    iface: String,
    source_ip: Ipv6Addr,
    source_netmask_length: u8,
    gateway: Option<Ipv6Addr>,
    name: String,
    #[serde(default)]
    targets: Vec<Target>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Conf {
    context: Vec<Context>
}

fn get_iface_mac(iface_name: &str) -> EthernetAddress {
    let mac_str_file_content = fs::read_to_string(
        Path::new("/sys/class/net/")
            .join(&iface_name)
            .join("address")).expect(format!("Iface {} does not exist.", iface_name).as_str());
    let mac_str = mac_str_file_content.strip_suffix("\n").unwrap().to_owned();
    EthernetAddress::from_str(mac_str.as_str()).unwrap()
}

fn main() {

    let file_path = "config.toml";

    let mut file = File::open(file_path).expect("Failed to open config.toml.");
    let mut toml_data = String::new();
    file.read_to_string(&mut toml_data).expect("Failed to read config.toml.");

    let parsed_data: Conf = toml::from_str(&toml_data).expect("Failed to parse TOML");

    let (mut opts, _) = utils::create_options();

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

    let verbose = args.opt_present("verbose");

    let mut network_states: Vec<NetworkState<'_>> = vec![];

    for context in parsed_data.context {
        let mac = get_iface_mac(&context.iface);
        let mut network_state = NetworkState::new(&context.iface, &mac, context.name);

        if verbose {
            println!("Using MAC: {}.", mac.to_string());
        }

        let cidr = Ipv6Cidr::new(context.source_ip.into(), context.source_netmask_length);

        set_ipv6_addr(&mut network_state.iface, cidr, verbose);

        if let Some(default_router) = context.gateway {
            network_state.iface.routes_mut().add_default_ipv6_route(default_router.into()).unwrap();
        }

        for target in context.targets {
            let ping_task = PingTask::new(&mut network_state, target.ip.into(), target.name);
            network_state.add_task(ping_task);
        }

        network_states.push(network_state);
    }

    run_tasks_to_completion(&mut network_states, verbose);
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