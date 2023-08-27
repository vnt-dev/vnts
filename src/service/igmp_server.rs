use crate::error::*;
use moka::sync::Cache;
use packet::igmp::igmp_v2::IgmpV2Packet;
use packet::igmp::igmp_v3::{IgmpV3RecordType, IgmpV3ReportPacket};
use packet::igmp::IgmpType;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

lazy_static::lazy_static! {
    //组播缓存 30分钟 (token,group_address) -> members
    static ref MULTICAST:Cache<(String,Ipv4Addr), Arc<RwLock<Multicast>>> = Cache::builder()
        .time_to_idle(Duration::from_secs(30*60)).build();
    // (token,group_address,member_ip)
    static ref MULTICAST_MEMBER:Cache<(String,Ipv4Addr,Ipv4Addr), ()> = Cache::builder()
        .time_to_idle(Duration::from_secs(20*60)).eviction_listener(|k:Arc<(String,Ipv4Addr,Ipv4Addr)>,_,cause|{
            if cause==moka::notification::RemovalCause::Replaced{
                return;
            }
            log::info!("MULTICAST_MEMBER eviction {:?}", k);
            if let Some(v) = MULTICAST.get(&(k.0.clone(),k.1)){
                let mut lock = v.write();
                lock.members.remove(&k.2);
                lock.map.remove(&k.2);
            }
         }).build();
}
#[derive(Clone, Debug)]
pub struct Multicast {
    //成员虚拟ip
    members: HashSet<Ipv4Addr>,
    //是否是过滤模式
    //成员过滤或包含的源ip
    map: HashMap<Ipv4Addr, (bool, HashSet<Ipv4Addr>)>,
}

impl Multicast {
    pub fn new() -> Self {
        Self {
            members: Default::default(),
            map: Default::default(),
        }
    }
    pub fn is_send(&self, ip: &Ipv4Addr) -> bool {
        if self.members.contains(ip) {
            if let Some((is_include, set)) = self.map.get(ip) {
                if *is_include {
                    set.contains(ip)
                } else {
                    !set.contains(ip)
                }
            } else {
                true
            }
        } else {
            false
        }
    }
}

pub fn load(token: &String, multicast_addr: Ipv4Addr) -> Option<Arc<RwLock<Multicast>>> {
    MULTICAST.get(&(token.clone(), multicast_addr))
}

pub fn handle(buf: &[u8], token: &String, source: Ipv4Addr) -> Result<()> {
    match IgmpType::from(buf[0]) {
        IgmpType::Query => {}
        IgmpType::ReportV1 | IgmpType::ReportV2 => {
            //加入组播，v1和v2差不多
            let report = IgmpV2Packet::new(buf)?;
            let multicast_addr = report.group_address();
            if !multicast_addr.is_multicast() {
                return Ok(());
            }
            let multi = MULTICAST.get_with((token.clone(), multicast_addr), || {
                Arc::new(RwLock::new(Multicast::new()))
            });
            let mut guard = multi.write();
            guard.members.insert(source);
            drop(guard);
            MULTICAST_MEMBER.insert((token.clone(), multicast_addr, source), ());
        }
        IgmpType::LeaveV2 => {
            //退出组播
            let leave = IgmpV2Packet::new(buf)?;
            let multicast_addr = leave.group_address();
            if !multicast_addr.is_multicast() {
                return Ok(());
            }
            MULTICAST_MEMBER.invalidate(&(token.clone(), multicast_addr, source));
        }
        IgmpType::ReportV3 => {
            let report = IgmpV3ReportPacket::new(buf)?;
            if let Some(group_records) = report.group_records() {
                for group_record in group_records {
                    let multicast_addr = group_record.multicast_address();
                    if !multicast_addr.is_multicast() {
                        return Ok(());
                    }
                    let multi = MULTICAST.get_with((token.clone(), multicast_addr), || {
                        Arc::new(RwLock::new(Multicast::new()))
                    });
                    let mut guard = multi.write();

                    match group_record.record_type() {
                        IgmpV3RecordType::ModeIsInclude | IgmpV3RecordType::ChangeToIncludeMode => {
                            match group_record.source_addresses() {
                                None => {
                                    //不接收所有
                                    guard.members.remove(&source);
                                    guard.map.remove(&source);
                                }
                                Some(src) => {
                                    guard.members.insert(source);
                                    guard.map.insert(source, (true, HashSet::from_iter(src)));
                                    drop(guard);
                                    MULTICAST_MEMBER
                                        .insert((token.clone(), multicast_addr, source), ());
                                }
                            }
                        }

                        IgmpV3RecordType::ModeIsExclude | IgmpV3RecordType::ChangeToExcludeMode => {
                            match group_record.source_addresses() {
                                None => {
                                    //接收所有
                                    guard.members.insert(source);
                                    guard.map.remove(&source);
                                }
                                Some(src) => {
                                    guard.members.insert(source);
                                    guard.map.insert(source, (false, HashSet::from_iter(src)));
                                }
                            }
                            drop(guard);
                            MULTICAST_MEMBER.insert((token.clone(), multicast_addr, source), ());
                        }
                        IgmpV3RecordType::AllowNewSources => {
                            //在已有源的基础上，接收目标源，如果是排除模式，则删除；是包含模式则添加
                            match group_record.source_addresses() {
                                None => {}
                                Some(src) => match guard.map.get_mut(&source) {
                                    None => {}
                                    Some((is_include, set)) => {
                                        for ip in src {
                                            if *is_include {
                                                set.insert(ip);
                                            } else {
                                                set.remove(&ip);
                                            }
                                        }
                                    }
                                },
                            }
                            drop(guard);
                            MULTICAST_MEMBER.insert((token.clone(), multicast_addr, source), ());
                        }
                        IgmpV3RecordType::BlockOldSources => {
                            //在已有源的基础上，不接收目标源
                            match group_record.source_addresses() {
                                None => {}
                                Some(src) => match guard.map.get_mut(&source) {
                                    None => {}
                                    Some((is_include, set)) => {
                                        for ip in src {
                                            if *is_include {
                                                set.remove(&ip);
                                            } else {
                                                set.insert(ip);
                                            }
                                        }
                                    }
                                },
                            }
                            drop(guard);
                            MULTICAST_MEMBER.insert((token.clone(), multicast_addr, source), ());
                        }
                        IgmpV3RecordType::Unknown(_) => {}
                    }
                }
            }
        }
        IgmpType::Unknown(_) => {}
    }
    Ok(())
}
