//! NUMA topology and placement-input model.
//!
//! 职责：表示节点、CPU 本地域、容量、在线状态和节点距离，提供确定性的本地优先
//! 候选顺序。边界：不实现页帧分配器、迁移或性能策略。
//! Responsibility: validated NUMA facts and deterministic locality ordering.

use crate::smp::CpuSet;

pub const LOCAL_DISTANCE: u8 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(pub u32);

impl NodeId {
    pub const NONE: Self = Self(u32::MAX);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumaNode {
    pub id: NodeId,
    pub cpus: CpuSet,
    pub memory_bytes: u64,
    pub online: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumaError {
    Capacity,
    Empty,
    InvalidNode,
    DuplicateNode,
    InvalidCpuSet,
    DuplicateCpu,
    InvalidDistance,
    UnknownNode,
    Offline,
    InsufficientMemory,
    GenerationExhausted,
}

impl NumaError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Capacity => "system.numa.error.capacity",
            Self::Empty => "system.numa.error.empty",
            Self::InvalidNode => "system.numa.error.node",
            Self::DuplicateNode => "system.numa.error.duplicate_node",
            Self::InvalidCpuSet => "system.numa.error.cpu_set",
            Self::DuplicateCpu => "system.numa.error.duplicate_cpu",
            Self::InvalidDistance => "system.numa.error.distance",
            Self::UnknownNode => "system.numa.error.unknown_node",
            Self::Offline => "system.numa.error.offline",
            Self::InsufficientMemory => "system.numa.error.memory",
            Self::GenerationExhausted => "system.numa.error.generation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementOrder<const N: usize> {
    nodes: [NodeId; N],
    len: usize,
}

impl<const N: usize> PlacementOrder<N> {
    const fn empty() -> Self {
        Self {
            nodes: [NodeId::NONE; N],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[NodeId] {
        &self.nodes[..self.len]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumaTopology<const N: usize> {
    nodes: [Option<NumaNode>; N],
    distances: [[u8; N]; N],
    count: usize,
    generation: u64,
}

impl<const N: usize> NumaTopology<N> {
    pub const fn new() -> Self {
        Self {
            nodes: [None; N],
            distances: [[0; N]; N],
            count: 0,
            generation: 1,
        }
    }

    pub fn configure(&mut self, nodes: &[NumaNode], distances: &[u8]) -> Result<(), NumaError> {
        if nodes.is_empty() {
            return Err(NumaError::Empty);
        }
        if nodes.len() > N {
            return Err(NumaError::Capacity);
        }
        let count = nodes.len();
        if distances.len() != count * count {
            return Err(NumaError::InvalidDistance);
        }
        let mut next = Self::new();
        for (index, node) in nodes.iter().copied().enumerate() {
            if node.cpus.is_empty() {
                return Err(NumaError::InvalidCpuSet);
            }
            if node.memory_bytes == 0 {
                return Err(NumaError::InvalidNode);
            }
            if nodes[..index].iter().any(|other| other.id == node.id) {
                return Err(NumaError::DuplicateNode);
            }
            for cpu in node.cpus.iter() {
                if nodes[..index].iter().any(|other| other.cpus.contains(cpu)) {
                    return Err(NumaError::DuplicateCpu);
                }
            }
            next.nodes[index] = Some(node);
        }
        for from in 0..count {
            for to in 0..count {
                let value = distances[from * count + to];
                if (from == to && value != LOCAL_DISTANCE)
                    || (from != to && value < LOCAL_DISTANCE + 1)
                    || distances[from * count + to] != distances[to * count + from]
                {
                    return Err(NumaError::InvalidDistance);
                }
                next.distances[from][to] = value;
            }
        }
        next.count = count;
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or(NumaError::GenerationExhausted)?;
        *self = next;
        Ok(())
    }

    pub const fn node_count(&self) -> usize {
        self.count
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn nodes(&self) -> impl Iterator<Item = NumaNode> + '_ {
        self.nodes[..self.count].iter().flatten().copied()
    }

    pub fn node(&self, id: NodeId) -> Option<NumaNode> {
        self.nodes().find(|node| node.id == id)
    }

    pub fn node_for_cpu(&self, cpu: usize) -> Option<NumaNode> {
        self.nodes().find(|node| node.cpus.contains(cpu))
    }

    pub fn distance(&self, from: NodeId, to: NodeId) -> Result<u8, NumaError> {
        let from = self.position(from).ok_or(NumaError::UnknownNode)?;
        let to = self.position(to).ok_or(NumaError::UnknownNode)?;
        Ok(self.distances[from][to])
    }

    /// Return online nodes ordered by distance from the CPU's local node.
    pub fn placement_order(&self, cpu: usize) -> Result<PlacementOrder<N>, NumaError> {
        let local = self.node_for_cpu(cpu).ok_or(NumaError::UnknownNode)?;
        let local_index = self.position(local.id).ok_or(NumaError::UnknownNode)?;
        let mut order = PlacementOrder::empty();
        for _ in 0..self.count {
            let mut best: Option<(usize, u8, NodeId)> = None;
            for (index, node) in self.nodes().enumerate() {
                if !node.online || order.nodes[..order.len].contains(&node.id) {
                    continue;
                }
                let candidate = (index, self.distances[local_index][index], node.id);
                if best.is_none_or(|current| (candidate.1, candidate.2) < (current.1, current.2)) {
                    best = Some(candidate);
                }
            }
            let Some((_, _, id)) = best else {
                break;
            };
            order.nodes[order.len] = id;
            order.len += 1;
        }
        Ok(order)
    }

    pub fn recommend(&self, cpu: usize, memory_bytes: u64) -> Result<NodeId, NumaError> {
        if memory_bytes == 0 {
            return Err(NumaError::InsufficientMemory);
        }
        for id in self.placement_order(cpu)?.as_slice() {
            if self
                .node(*id)
                .is_some_and(|node| node.online && node.memory_bytes >= memory_bytes)
            {
                return Ok(*id);
            }
        }
        Err(NumaError::InsufficientMemory)
    }

    pub fn set_online(&mut self, id: NodeId, online: bool) -> Result<(), NumaError> {
        let position = self.position(id).ok_or(NumaError::UnknownNode)?;
        if online && self.nodes[position].is_none_or(|node| node.memory_bytes == 0) {
            return Err(NumaError::InvalidNode);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(NumaError::GenerationExhausted)?;
        let node = self.nodes[position]
            .as_mut()
            .ok_or(NumaError::UnknownNode)?;
        if node.online != online {
            node.online = online;
            self.generation = next_generation;
        }
        Ok(())
    }

    fn position(&self, id: NodeId) -> Option<usize> {
        self.nodes().position(|node| node.id == id)
    }
}

impl<const N: usize> Default for NumaTopology<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpus(first: usize, second: usize) -> CpuSet {
        let mut set = CpuSet::EMPTY;
        for cpu in first..second {
            assert!(set.insert(cpu));
        }
        set
    }

    fn nodes() -> [NumaNode; 2] {
        [
            NumaNode {
                id: NodeId(0),
                cpus: cpus(0, 4),
                memory_bytes: 4 * 1024 * 1024,
                online: true,
            },
            NumaNode {
                id: NodeId(1),
                cpus: cpus(4, 8),
                memory_bytes: 8 * 1024 * 1024,
                online: true,
            },
        ]
    }

    fn topology() -> NumaTopology<4> {
        let mut topology = NumaTopology::<4>::new();
        topology.configure(&nodes(), &[10, 20, 20, 10]).unwrap();
        topology
    }

    #[test]
    fn cpu_locality_distance_and_remote_penalty_are_represented() {
        let topology = topology();
        assert_eq!(topology.node_for_cpu(1).unwrap().id, NodeId(0));
        assert_eq!(topology.node_for_cpu(5).unwrap().id, NodeId(1));
        assert_eq!(topology.distance(NodeId(0), NodeId(0)), Ok(10));
        assert_eq!(topology.distance(NodeId(0), NodeId(1)), Ok(20));
        assert_eq!(topology.distance(NodeId(1), NodeId(0)), Ok(20));
    }

    #[test]
    fn local_first_capacity_fallback_is_deterministic() {
        let topology = topology();
        assert_eq!(topology.recommend(0, 1024).unwrap(), NodeId(0));
        assert_eq!(topology.recommend(0, 6 * 1024 * 1024).unwrap(), NodeId(1));
        assert_eq!(
            topology.recommend(0, 9 * 1024 * 1024),
            Err(NumaError::InsufficientMemory)
        );
        assert_eq!(
            topology.placement_order(0).unwrap().as_slice(),
            &[NodeId(0), NodeId(1)]
        );
    }

    #[test]
    fn malformed_topologies_are_rejected_without_partial_state() {
        let mut topology = topology();
        let before = topology;
        assert_eq!(
            topology.configure(&nodes(), &[10, 20, 19, 10]),
            Err(NumaError::InvalidDistance)
        );
        assert_eq!(topology, before);
        let mut overlapping = nodes();
        overlapping[1].cpus.insert(3);
        assert_eq!(
            topology.configure(&overlapping, &[10, 20, 20, 10]),
            Err(NumaError::DuplicateCpu)
        );
        assert_eq!(topology, before);
        assert_eq!(
            topology.configure(&[nodes()[0]; 5], &[10; 25]),
            Err(NumaError::Capacity)
        );
    }

    #[test]
    fn offline_nodes_are_excluded_and_advance_generation() {
        let mut topology = topology();
        let generation = topology.generation();
        topology.set_online(NodeId(0), false).unwrap();
        assert_eq!(topology.generation(), generation + 1);
        assert_eq!(topology.recommend(0, 1024).unwrap(), NodeId(1));
        assert_eq!(
            topology.placement_order(0).unwrap().as_slice(),
            &[NodeId(1)]
        );
        topology.set_online(NodeId(0), true).unwrap();
        assert_eq!(topology.recommend(0, 1024).unwrap(), NodeId(0));
    }
}
