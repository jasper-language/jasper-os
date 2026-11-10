//! LC-3 P0 GPT 部署布局的纯计算模型。
//! Pure calculation model for the LC-3 P0 GPT deployment layout.
//!
//! 本模块不写 GPT、不格式化文件系统，也不执行安装。它冻结可在宿主安装器、
//! 启动管理器和验收工具之间共享的分区边界与不变量。
//! This module writes no GPT, formats no filesystem, and installs nothing. It freezes the
//! partition boundaries shared by the host installer, boot manager, and acceptance tools.

/// GPT 逻辑扇区大小。GPT logical sector size.
pub const SECTOR_BYTES: u64 = 512;
/// 1 MiB 对应的扇区数。Sectors in one MiB.
pub const MIB_SECTORS: u64 = (1024 * 1024) / SECTOR_BYTES;

/// P0 布局中的分区角色。
/// Partition roles in the P0 layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PartitionRole {
    /// UEFI 系统分区。UEFI system partition.
    Esp = 0,
    /// A 系统槽。System slot A.
    SystemA = 1,
    /// B 系统槽。System slot B.
    SystemB = 2,
    /// 控制记录副本 A。Control record copy A.
    ControlA = 3,
    /// 控制记录副本 B。Control record copy B.
    ControlB = 4,
    /// 独立救援系统。Independent rescue system.
    Rescue = 5,
    /// 共享用户数据，占用剩余空间。Shared user data, occupying remaining capacity.
    Data = 6,
}

impl PartitionRole {
    /// 全部角色，按布局顺序。All roles in layout order.
    pub const ALL: [Self; 7] = [
        Self::Esp,
        Self::SystemA,
        Self::SystemB,
        Self::ControlA,
        Self::ControlB,
        Self::Rescue,
        Self::Data,
    ];
}

/// 一个 GPT 分区范围，使用闭合起点和独占终点。
/// One GPT partition range with an inclusive start and exclusive end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    /// 分区角色。Partition role.
    pub role: PartitionRole,
    /// 首扇区。First sector.
    pub start_lba: u64,
    /// 扇区数。Sector count.
    pub sectors: u64,
}

impl Partition {
    /// 独占结束扇区。Exclusive end LBA.
    pub const fn end_lba(self) -> u64 {
        self.start_lba + self.sectors
    }

    /// 是否与另一分区重叠。Whether this partition overlaps another.
    pub const fn overlaps(self, other: Self) -> bool {
        self.start_lba < other.end_lba() && other.start_lba < self.end_lba()
    }
}

/// P0 布局拒绝原因。
/// P0 layout rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// 磁盘不足以容纳全部最低分区。The disk cannot hold every minimum partition.
    TooSmall,
    /// 总扇区数溢出。The total sector count overflowed.
    Overflow,
}

/// 已验证的 P0 部署布局。
/// Validated P0 deployment layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P0Layout {
    total_sectors: u64,
    partitions: [Partition; 7],
}

impl P0Layout {
    /// 按总磁盘扇区数生成首个 P0 布局。
    /// Builds the first P0 layout from the total disk sector count.
    ///
    /// GPT 头尾各保留 1 MiB。所有分区按 1 MiB 边界放置，共享数据区位于末尾并吸收剩余空间。
    /// One MiB is reserved at each end. Every partition starts on a 1 MiB boundary; the
    /// shared-data partition is last and absorbs all remaining capacity.
    pub fn new(total_sectors: u64) -> Result<Self, LayoutError> {
        let reserve = MIB_SECTORS;
        let esp = 512 * MIB_SECTORS;
        let system = 8 * 1024 * MIB_SECTORS;
        let data_min = 16 * 1024 * MIB_SECTORS;
        let control = 64 * MIB_SECTORS;
        let rescue = 2 * 1024 * MIB_SECTORS;
        let fixed = reserve
            .checked_add(esp)
            .and_then(|value| value.checked_add(system * 2))
            .and_then(|value| value.checked_add(control * 2))
            .and_then(|value| value.checked_add(rescue))
            .and_then(|value| value.checked_add(reserve))
            .ok_or(LayoutError::Overflow)?;
        if total_sectors < fixed.checked_add(data_min).ok_or(LayoutError::Overflow)? {
            return Err(LayoutError::TooSmall);
        }
        let data = total_sectors - fixed;
        let _ = data_min;
        let mut start = reserve;
        let mut partitions = [Partition {
            role: PartitionRole::Esp,
            start_lba: 0,
            sectors: 0,
        }; 7];
        for (slot, (role, sectors)) in PartitionRole::ALL
            .into_iter()
            .zip([esp, system, system, control, control, rescue, data])
            .enumerate()
        {
            partitions[slot] = Partition {
                role,
                start_lba: start,
                sectors,
            };
            start = start.checked_add(sectors).ok_or(LayoutError::Overflow)?;
        }
        if start
            .checked_add(reserve)
            .is_none_or(|end| end > total_sectors)
        {
            return Err(LayoutError::TooSmall);
        }
        let layout = Self {
            total_sectors,
            partitions,
        };
        if !layout.well_formed() {
            return Err(LayoutError::TooSmall);
        }
        Ok(layout)
    }

    /// 总磁盘扇区数。Total disk sectors.
    pub const fn total_sectors(self) -> u64 {
        self.total_sectors
    }

    /// 全部分区。All partitions.
    pub const fn partitions(self) -> [Partition; 7] {
        self.partitions
    }

    /// 按角色读取分区。Reads a partition by role.
    pub fn partition(self, role: PartitionRole) -> Partition {
        self.partitions[role as usize]
    }

    /// 判断某个扇区是否属于角色。Returns whether a sector belongs to a role.
    pub fn contains(self, role: PartitionRole, lba: u64) -> bool {
        let partition = self.partition(role);
        lba >= partition.start_lba && lba < partition.end_lba()
    }

    /// 校验布局不变量。Checks layout invariants.
    pub fn well_formed(self) -> bool {
        if self.total_sectors < 2 * MIB_SECTORS {
            return false;
        }
        let mut end = MIB_SECTORS;
        for (index, partition) in self.partitions.into_iter().enumerate() {
            if partition.role as usize != index
                || partition.sectors == 0
                || partition.start_lba % MIB_SECTORS != 0
                || partition.start_lba != end
            {
                return false;
            }
            end = match end.checked_add(partition.sectors) {
                Some(value) => value,
                None => return false,
            };
        }
        let a = self.partition(PartitionRole::SystemA);
        let b = self.partition(PartitionRole::SystemB);
        let control_a = self.partition(PartitionRole::ControlA);
        let control_b = self.partition(PartitionRole::ControlB);
        a.sectors == b.sectors
            && self.partition(PartitionRole::Data).sectors >= 16 * 1024 * MIB_SECTORS
            && control_a.end_lba() <= control_b.start_lba
            && end
                .checked_add(MIB_SECTORS)
                .is_some_and(|tail| tail <= self.total_sectors)
            && self.partitions.iter().enumerate().all(|(i, left)| {
                self.partitions
                    .iter()
                    .skip(i + 1)
                    .all(|right| !left.overlaps(*right))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sectors_gib(gib: u64) -> u64 {
        gib * 1024 * MIB_SECTORS
    }

    #[test]
    fn minimum_p0_layout_is_aligned_non_overlapping_and_uses_remaining_space_for_data() {
        let total = sectors_gib(36);
        let layout = P0Layout::new(total).unwrap();
        assert!(layout.well_formed());
        assert_eq!(layout.total_sectors(), total);
        assert_eq!(
            layout.partition(PartitionRole::SystemA).sectors,
            sectors_gib(8)
        );
        assert_eq!(
            layout.partition(PartitionRole::SystemB).sectors,
            sectors_gib(8)
        );
        assert!(layout.partition(PartitionRole::Data).sectors >= sectors_gib(16));
        let partitions = layout.partitions();
        for (index, left) in partitions.iter().enumerate() {
            assert_eq!(left.start_lba % MIB_SECTORS, 0);
            for right in partitions.iter().skip(index + 1) {
                assert!(!left.overlaps(*right));
            }
        }
    }

    #[test]
    fn layout_rejects_disk_below_declared_minimum() {
        assert_eq!(P0Layout::new(sectors_gib(34)), Err(LayoutError::TooSmall));
    }

    #[test]
    fn data_partition_absorbs_extra_capacity_without_moving_fixed_roles() {
        let small = sectors_gib(36);
        let large = sectors_gib(64);
        let a = P0Layout::new(small).unwrap();
        let b = P0Layout::new(large).unwrap();
        for role in PartitionRole::ALL {
            if role != PartitionRole::Data {
                assert_eq!(a.partition(role).start_lba, b.partition(role).start_lba);
                assert_eq!(a.partition(role).sectors, b.partition(role).sectors);
            }
        }
        assert!(
            b.partition(PartitionRole::Data).sectors > a.partition(PartitionRole::Data).sectors
        );
    }

    #[test]
    fn role_lookup_never_crosses_partition_boundaries() {
        let layout = P0Layout::new(sectors_gib(36)).unwrap();
        for role in PartitionRole::ALL {
            let partition = layout.partition(role);
            assert!(layout.contains(role, partition.start_lba));
            assert!(layout.contains(role, partition.end_lba() - 1));
            assert!(!layout.contains(role, partition.end_lba()));
            assert!(!layout.contains(role, partition.start_lba.saturating_sub(1)));
        }
    }
}
