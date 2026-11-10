use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareInfo {
    pub name: String,
    pub kind: &'static str,
}

/// An active IPv4 address of a local network adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
}

impl LocalNetwork {
    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) & self.mask())
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask() == u32::from(self.address) & self.mask()
    }

    /// Host range of the subnet (network and broadcast excluded). Subnets larger
    /// than /22 are narrowed to the /24 that contains the adapter address.
    pub fn host_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        let prefix = if self.prefix < 22 { 24 } else { self.prefix };
        let mask = if prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        let network = u32::from(self.address) & mask;
        let broadcast = network | !mask;
        if prefix >= 31 {
            (Ipv4Addr::from(network), Ipv4Addr::from(broadcast))
        } else {
            (Ipv4Addr::from(network + 1), Ipv4Addr::from(broadcast - 1))
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsEnrichment {
    pub users: Vec<String>,
    pub shares: Vec<ShareInfo>,
    pub remote_time: Option<String>,
}

#[cfg(windows)]
mod imp {
    use super::{LocalNetwork, ShareInfo, WindowsEnrichment};
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::ptr;
    use std::time::Duration;

    const NO_ERROR: u32 = 0;
    const ERROR_MORE_DATA: u32 = 234;
    const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
    const NI_NAMEREQD: i32 = 0x4;
    const AF_INET: u16 = 2;

    type Handle = *mut c_void;

    #[repr(C)]
    struct SockAddrIn {
        family: u16,
        port: u16,
        address: u32,
        zero: [u8; 8],
    }

    #[repr(C)]
    struct ShareInfo1 {
        net_name: *mut u16,
        share_type: u32,
        remark: *mut u16,
    }

    #[repr(C)]
    struct WorkstationUserInfo1 {
        user_name: *mut u16,
        logon_domain: *mut u16,
        other_domains: *mut u16,
        logon_server: *mut u16,
    }

    #[repr(C)]
    struct TimeOfDayInfo {
        elapsed_seconds: u32,
        milliseconds: u32,
        hours: u32,
        minutes: u32,
        seconds: u32,
        hundredths: u32,
        timezone: i32,
        interval: u32,
        day: u32,
        month: u32,
        year: u32,
        weekday: u32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> Handle;
        fn IcmpCloseHandle(handle: Handle) -> i32;
        fn IcmpSendEcho(
            handle: Handle,
            destination: u32,
            request_data: *const c_void,
            request_size: u16,
            request_options: *const c_void,
            reply_buffer: *mut c_void,
            reply_size: u32,
            timeout_ms: u32,
        ) -> u32;
        fn SendARP(
            destination: u32,
            source: u32,
            mac_address: *mut u32,
            physical_address_length: *mut u32,
        ) -> u32;
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut c_void,
            addresses: *mut AdapterAddresses,
            size: *mut u32,
        ) -> u32;
    }

    #[repr(C)]
    struct AdapterAddresses {
        length: u32,
        if_index: u32,
        next: *mut AdapterAddresses,
        adapter_name: *mut u8,
        first_unicast: *mut UnicastAddress,
        first_anycast: *mut c_void,
        first_multicast: *mut c_void,
        first_dns_server: *mut c_void,
        dns_suffix: *mut u16,
        description: *mut u16,
        friendly_name: *mut u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: u32,
    }

    #[repr(C)]
    struct SocketAddress {
        sockaddr: *mut SockAddrIn,
        length: i32,
    }

    #[repr(C)]
    struct UnicastAddress {
        length: u32,
        flags: u32,
        next: *mut UnicastAddress,
        address: SocketAddress,
        prefix_origin: i32,
        suffix_origin: i32,
        dad_state: i32,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        lease_lifetime: u32,
        on_link_prefix_length: u8,
    }

    pub fn local_networks() -> Vec<LocalNetwork> {
        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        const SKIP_ANYCAST_MULTICAST_DNS: u32 = 0x2 | 0x4 | 0x8;
        const IF_TYPE_LOOPBACK: u32 = 24;
        const OPER_STATUS_UP: u32 = 1;

        let mut size = 16 * 1024_u32;
        let mut buffer: Vec<u64>;
        loop {
            buffer = vec![0; (size as usize).div_ceil(8)];
            let status = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_INET),
                    SKIP_ANYCAST_MULTICAST_DNS,
                    ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            match status {
                NO_ERROR => break,
                ERROR_BUFFER_OVERFLOW => continue,
                _ => return Vec::new(),
            }
        }

        let mut networks = Vec::new();
        let mut adapter = buffer.as_ptr().cast::<AdapterAddresses>();
        while let Some(current) = unsafe { adapter.as_ref() } {
            adapter = current.next;
            if current.if_type == IF_TYPE_LOOPBACK || current.oper_status != OPER_STATUS_UP {
                continue;
            }
            let name = unsafe { wide_ptr_to_string(current.friendly_name) }
                .unwrap_or_else(|| "Red".to_owned());
            let mut unicast = current.first_unicast;
            while let Some(entry) = unsafe { unicast.as_ref() } {
                unicast = entry.next;
                let Some(sockaddr) = (unsafe { entry.address.sockaddr.as_ref() }) else {
                    continue;
                };
                if sockaddr.family != AF_INET {
                    continue;
                }
                let address = Ipv4Addr::from(sockaddr.address.to_ne_bytes());
                if address.is_loopback() || address.is_link_local() {
                    continue;
                }
                networks.push(LocalNetwork {
                    name: name.clone(),
                    address,
                    prefix: entry.on_link_prefix_length.min(32),
                });
            }
        }
        networks
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn GetNameInfoW(
            address: *const c_void,
            address_length: i32,
            host: *mut u16,
            host_length: u32,
            service: *mut u16,
            service_length: u32,
            flags: i32,
        ) -> i32;
    }

    #[link(name = "netapi32")]
    extern "system" {
        fn NetApiBufferFree(buffer: *mut c_void) -> u32;
        fn NetShareEnum(
            server_name: *const u16,
            level: u32,
            buffer: *mut *mut u8,
            preferred_maximum_length: u32,
            entries_read: *mut u32,
            total_entries: *mut u32,
            resume_handle: *mut u32,
        ) -> u32;
        fn NetWkstaUserEnum(
            server_name: *const u16,
            level: u32,
            buffer: *mut *mut u8,
            preferred_maximum_length: u32,
            entries_read: *mut u32,
            total_entries: *mut u32,
            resume_handle: *mut u32,
        ) -> u32;
        fn NetRemoteTOD(server_name: *const u16, buffer: *mut *mut u8) -> u32;
    }

    pub fn icmp_echo(address: Ipv4Addr, timeout: Duration) -> bool {
        unsafe {
            let handle = IcmpCreateFile();
            if handle.is_null() || handle as isize == -1 {
                return false;
            }
            let mut reply = [0_u8; 256];
            let result = IcmpSendEcho(
                handle,
                windows_ipv4(address),
                ptr::null(),
                0,
                ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout.as_millis().min(u128::from(u32::MAX)) as u32,
            );
            IcmpCloseHandle(handle);
            result > 0
        }
    }

    pub fn mac_address(address: Ipv4Addr) -> Option<String> {
        unsafe {
            let mut bytes = [0_u8; 8];
            let mut length = bytes.len() as u32;
            let status = SendARP(
                windows_ipv4(address),
                0,
                bytes.as_mut_ptr().cast(),
                &mut length,
            );
            if status != NO_ERROR || length == 0 || length as usize > bytes.len() {
                return None;
            }
            Some(
                bytes[..length as usize]
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            )
        }
    }

    pub fn reverse_dns(address: Ipv4Addr) -> Option<String> {
        let socket_address = SockAddrIn {
            family: AF_INET,
            port: 0,
            address: windows_ipv4(address),
            zero: [0; 8],
        };
        let mut host = [0_u16; 1025];
        let result = unsafe {
            GetNameInfoW(
                (&socket_address as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as i32,
                host.as_mut_ptr(),
                host.len() as u32,
                ptr::null_mut(),
                0,
                NI_NAMEREQD,
            )
        };
        (result == 0).then(|| wide_slice_to_string(&host)).flatten()
    }

    pub fn windows_enrichment(address: Ipv4Addr) -> WindowsEnrichment {
        let server = wide_null(&format!("\\\\{address}"));
        WindowsEnrichment {
            users: enumerate_users(&server),
            shares: enumerate_shares(&server),
            remote_time: remote_time(&server),
        }
    }

    fn enumerate_users(server: &[u16]) -> Vec<String> {
        let mut users = Vec::new();
        let mut resume = 0_u32;
        loop {
            let mut buffer = ptr::null_mut();
            let mut entries = 0_u32;
            let mut total = 0_u32;
            let status = unsafe {
                NetWkstaUserEnum(
                    server.as_ptr(),
                    1,
                    &mut buffer,
                    MAX_PREFERRED_LENGTH,
                    &mut entries,
                    &mut total,
                    &mut resume,
                )
            };
            if !buffer.is_null() {
                let records = unsafe {
                    std::slice::from_raw_parts(
                        buffer.cast::<WorkstationUserInfo1>(),
                        entries as usize,
                    )
                };
                for record in records {
                    if let Some(user) = unsafe { wide_ptr_to_string(record.user_name) } {
                        let domain = unsafe { wide_ptr_to_string(record.logon_domain) };
                        users.push(match domain {
                            Some(domain) if !domain.is_empty() => format!("{domain}\\{user}"),
                            _ => user,
                        });
                    }
                }
                unsafe { NetApiBufferFree(buffer.cast()) };
            }
            if status != ERROR_MORE_DATA {
                break;
            }
        }
        users.sort();
        users.dedup();
        users
    }

    fn enumerate_shares(server: &[u16]) -> Vec<ShareInfo> {
        let mut shares = Vec::new();
        let mut resume = 0_u32;
        loop {
            let mut buffer = ptr::null_mut();
            let mut entries = 0_u32;
            let mut total = 0_u32;
            let status = unsafe {
                NetShareEnum(
                    server.as_ptr(),
                    1,
                    &mut buffer,
                    MAX_PREFERRED_LENGTH,
                    &mut entries,
                    &mut total,
                    &mut resume,
                )
            };
            if !buffer.is_null() {
                let records = unsafe {
                    std::slice::from_raw_parts(buffer.cast::<ShareInfo1>(), entries as usize)
                };
                for record in records {
                    if let Some(name) = unsafe { wide_ptr_to_string(record.net_name) } {
                        shares.push(ShareInfo {
                            name,
                            kind: share_kind(record.share_type),
                        });
                    }
                }
                unsafe { NetApiBufferFree(buffer.cast()) };
            }
            if status != ERROR_MORE_DATA {
                break;
            }
        }
        shares
    }

    fn remote_time(server: &[u16]) -> Option<String> {
        let mut buffer = ptr::null_mut();
        let status = unsafe { NetRemoteTOD(server.as_ptr(), &mut buffer) };
        if status != NO_ERROR || buffer.is_null() {
            return None;
        }
        let info = unsafe { &*buffer.cast::<TimeOfDayInfo>() };
        let value = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            info.year, info.month, info.day, info.hours, info.minutes, info.seconds
        );
        unsafe { NetApiBufferFree(buffer.cast()) };
        Some(value)
    }

    fn windows_ipv4(address: Ipv4Addr) -> u32 {
        u32::from_ne_bytes(address.octets())
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn wide_slice_to_string(value: &[u16]) -> Option<String> {
        let length = value.iter().position(|character| *character == 0)?;
        let value = String::from_utf16_lossy(&value[..length]);
        (!value.is_empty()).then_some(value)
    }

    unsafe fn wide_ptr_to_string(value: *const u16) -> Option<String> {
        if value.is_null() {
            return None;
        }
        let mut length = 0;
        while length < 32_768 && *value.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(value, length));
        (!value.is_empty()).then_some(value)
    }

    fn share_kind(share_type: u32) -> &'static str {
        match share_type & 0xff {
            0 => "disk",
            1 => "printer",
            2 => "device",
            3 => "ipc",
            _ => "unknown",
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{LocalNetwork, WindowsEnrichment};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    pub fn local_networks() -> Vec<LocalNetwork> {
        Vec::new()
    }

    pub fn icmp_echo(_address: Ipv4Addr, _timeout: Duration) -> bool {
        false
    }

    pub fn mac_address(_address: Ipv4Addr) -> Option<String> {
        None
    }

    pub fn reverse_dns(_address: Ipv4Addr) -> Option<String> {
        None
    }

    pub fn windows_enrichment(_address: Ipv4Addr) -> WindowsEnrichment {
        WindowsEnrichment::default()
    }
}

pub fn icmp_echo(address: Ipv4Addr, timeout: Duration) -> bool {
    imp::icmp_echo(address, timeout)
}

pub fn mac_address(address: Ipv4Addr) -> Option<String> {
    imp::mac_address(address)
}

pub fn reverse_dns(address: Ipv4Addr) -> Option<String> {
    imp::reverse_dns(address)
}

pub fn windows_enrichment(address: Ipv4Addr) -> WindowsEnrichment {
    imp::windows_enrichment(address)
}

/// Active IPv4 networks of the local adapters (loopback and link-local excluded).
pub fn local_networks() -> Vec<LocalNetwork> {
    imp::local_networks()
}

#[cfg(test)]
mod tests {
    use super::LocalNetwork;
    use std::net::Ipv4Addr;

    fn network(address: [u8; 4], prefix: u8) -> LocalNetwork {
        LocalNetwork {
            name: "test".to_owned(),
            address: Ipv4Addr::from(address),
            prefix,
        }
    }

    #[test]
    fn computes_host_ranges() {
        assert_eq!(
            network([192, 168, 1, 37], 24).host_range(),
            (
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 254)
            )
        );
        assert_eq!(
            network([10, 0, 5, 9], 22).host_range(),
            (Ipv4Addr::new(10, 0, 4, 1), Ipv4Addr::new(10, 0, 7, 254))
        );
        assert_eq!(
            network([10, 20, 30, 40], 8).host_range(),
            (Ipv4Addr::new(10, 20, 30, 1), Ipv4Addr::new(10, 20, 30, 254))
        );
    }

    #[test]
    fn checks_subnet_membership() {
        let lan = network([192, 168, 1, 37], 24);
        assert!(lan.contains(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!lan.contains(Ipv4Addr::new(192, 168, 2, 1)));
    }
}
