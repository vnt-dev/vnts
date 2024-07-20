#![allow(dead_code)]
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::RwLock;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[derive(Clone)]
pub struct ExpireMap<K, V> {
    base: Arc<RwLock<HashMap<K, Value<V>>>>,
    sender: Sender<DelayedTask<K>>,
}

struct Value<V> {
    val: V,
    deadline: AtomicCell<Instant>,
    expire: Duration,
}

impl<K, V> ExpireMap<K, V> {
    pub fn new<F>(call: F) -> ExpireMap<K, V>
    where
        F: Fn(&K, &V) -> Option<Duration> + Send + 'static,
        K: Eq + Hash + Clone + Sync + Send + 'static,
        V: Clone + Sync + Send + 'static,
    {
        let (sender, receiver) = channel(100);
        let map = ExpireMap {
            base: Arc::new(RwLock::new(HashMap::with_capacity(128))),
            sender,
        };
        let map1 = map.clone();
        tokio::spawn(async move { expire_task(receiver, map1, call).await });
        map
    }
}

impl<K, V> ExpireMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn size(&self) -> usize {
        self.base.read().len()
    }
    pub async fn insert(&self, k: K, val: V, expire: Duration) {
        let instant = Instant::now().add(expire);
        {
            let mut write_guard = self.base.write();
            let value = Value {
                val,
                deadline: AtomicCell::new(instant),
                expire,
            };
            write_guard.insert(k.clone(), value);
        }
        //投入过期监听
        self.sender
            .send(DelayedTask { k, time: instant })
            .await
            .unwrap();
    }
    /// remove出去的不会执行过期回调
    pub fn remove(&self, k: &K) -> Option<V> {
        if let Some(v) = self.base.write().remove(k) {
            Some(v.val)
        } else {
            None
        }
    }
    pub fn get(&self, k: &K) -> Option<V> {
        if let Some(v) = self.base.read().get(k) {
            // 延长过期时间
            v.deadline.store(Instant::now().add(v.expire));
            Some(v.val.clone())
        } else {
            None
        }
    }
    pub fn get_val(&self, k: &K) -> Option<V> {
        self.base.read().get(k).map(|v| v.val.clone())
    }
    fn expire_call<F>(&self, k: &K, f: &F) -> Op<K, V>
    where
        F: Fn(&K, &V) -> Option<Duration>,
    {
        let mut write_guard = self.base.write();
        if let Some(v) = write_guard.get(k) {
            let now = Instant::now();
            let instant = v.deadline.load();
            if instant >= now {
                // 过期时间更新了
                return Op::Reset(instant);
            } else {
                //执行过期回调
                if let Some(v) = f(k, &v.val) {
                    return Op::Reset(now.add(v));
                } else {
                    //删除key
                    if let Some((k, v)) = write_guard.remove_entry(k) {
                        return Op::Remove(k, v.val);
                    }
                }
            }
        }
        Op::None
    }
    pub async fn optionally_get_with<F>(&self, k: K, f: F) -> V
    where
        F: FnOnce() -> (Duration, V),
    {
        let (v, time) = {
            let mut write_guard = self.base.write();
            if let Some(v) = write_guard.get(&k) {
                // 延长过期时间
                v.deadline.store(Instant::now().add(v.expire));
                (v.val.clone(), None)
            } else {
                let (expire, val) = f();
                let instant = Instant::now().add(expire);
                let value = Value {
                    val: val.clone(),
                    deadline: AtomicCell::new(instant),
                    expire,
                };
                write_guard.insert(k.clone(), value);
                (val, Some(instant))
            }
        };
        if let Some(time) = time {
            self.sender.send(DelayedTask { k, time }).await.unwrap();
        }
        v
    }
    pub fn key_values(&self) -> Vec<(K, V)> {
        self.base
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.val.clone()))
            .collect()
    }
}

enum Op<K, V> {
    Reset(Instant),
    Remove(K, V),
    None,
}

async fn expire_task<K, V, F>(mut receiver: Receiver<DelayedTask<K>>, map: ExpireMap<K, V>, f: F)
where
    K: Eq + Hash + Clone,
    V: Clone,
    F: Fn(&K, &V) -> Option<Duration>,
{
    let mut binary_heap = BinaryHeap::<DelayedTask<K>>::with_capacity(32);
    loop {
        while let Some(task) = binary_heap.peek() {
            let now = Instant::now();
            if now < task.time {
                //需要等待对应时间
                let duration = task.time - now;
                match tokio::time::timeout(duration, receiver.recv()).await {
                    Ok(op) => {
                        if let Some(task) = op {
                            binary_heap.push(task);
                        } else {
                            return;
                        }
                    }
                    Err(_e) => {
                        continue;
                    }
                }
            } else if let Some(mut task) = binary_heap.pop() {
                //执行过期逻辑
                match map.expire_call(&task.k, &f) {
                    Op::Reset(time) => {
                        //没有过期，重新加入监听
                        task.time = time;
                        binary_heap.push(task);
                    }
                    Op::Remove(_, _) => {}
                    Op::None => {}
                }
            }
        }
        //取出所有任务
        loop {
            match receiver.try_recv() {
                Ok(task) => {
                    binary_heap.push(task);
                }
                Err(e) => match e {
                    TryRecvError::Empty => {
                        break;
                    }
                    TryRecvError::Disconnected => {
                        return;
                    }
                },
            }
        }

        if binary_heap.is_empty() {
            //任务队列为空时陷入等待
            if let Some(task) = receiver.recv().await {
                binary_heap.push(task);
            } else {
                return;
            }
        }
    }
}

struct DelayedTask<K> {
    k: K,
    time: Instant,
}

impl<K> Eq for DelayedTask<K> {}

impl<K> PartialEq for DelayedTask<K> {
    fn eq(&self, other: &Self) -> bool {
        self.time.eq(&other.time)
    }
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl<K> PartialOrd for DelayedTask<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.time.partial_cmp(&other.time).map(|ord| ord.reverse())
    }
}

impl<K> Ord for DelayedTask<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time.cmp(&other.time).reverse()
    }
}
