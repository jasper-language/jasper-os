------------------------------- MODULE tlb_shootdown -------------------------------
\* 跨核 TLB 击落协议的抽象模型。
\*
\* 建模对象是一段被修改的页表范围（一个“页表版本”）。一次版本推进对应：
\*   修改页表 → 发起方本地作废 → 逐目标核投递击落 → 目标作废并应答 →
\*   全部应答后释放帧。超时只撤销公告板上的等待，不释放帧；并发发起者遇到在途
\*   请求时得到 Busy 并在重试前服务在途请求（模型里的 Busy 动作）。
\*
\* 模型只覆盖单个页表版本、单个范围；多个范围由同一公告板串行化，是更强的约束。
EXTENDS Naturals, FiniteSets

CONSTANTS
    CPUs,        \* 参与击落的处理器集合
    MAX_EPOCH    \* 模型检查推进的页表版本上限

ASSUME
    /\ CPUs # {}
    /\ 0 \in CPUs
    /\ MAX_EPOCH \in Nat
    /\ MAX_EPOCH > 0

VARIABLES
    tableVersion,      \* 当前页表版本（每推进一次代表一次范围内页表修改）
    tlbView,           \* 每核已经看到的版本；只会向前推进
    phase,             \* 每核在协议里的阶段
    request,           \* 在途击落请求：所有者、版本、目标集合、应答集合、撤销标记
    ackedVersion,      \* 每核最近一次完成应答的版本
    released,          \* 每核是否已经释放本轮帧
    releaseVersion,    \* 每核释放时对应的版本
    frees              \* 每个（发起核, 版本）对应的释放次数（用于检查重复释放）

vars == <<tableVersion, tlbView, phase, request,
          ackedVersion, released, releaseVersion, frees>>

Init ==
    /\ tableVersion = 0
    /\ tlbView = [c \in CPUs |-> 0]
    /\ phase = [c \in CPUs |-> "idle"]
    /\ request = [active |-> FALSE,
                  owner |-> 0,
                  version |-> 0,
                  targets |-> {},
                  acked |-> {},
                  revoked |-> FALSE]
    /\ ackedVersion = [c \in CPUs |-> 0]
    /\ released = [c \in CPUs |-> FALSE]
    /\ releaseVersion = [c \in CPUs |-> 0]
    /\ frees = [c \in CPUs |-> [v \in 0..MAX_EPOCH |-> 0]]

TypeOK ==
    /\ tableVersion \in 0..MAX_EPOCH
    /\ tlbView \in [CPUs -> 0..MAX_EPOCH]
    /\ phase \in [CPUs -> {"idle", "mutated", "shooting", "acked", "released"}]
    /\ request.active \in BOOLEAN
    /\ request.owner \in CPUs
    /\ request.version \in 0..MAX_EPOCH
    /\ request.targets \subseteq CPUs
    /\ request.acked \subseteq CPUs
    /\ request.acked \subseteq request.targets
    /\ request.revoked \in BOOLEAN
    /\ ackedVersion \in [CPUs -> 0..MAX_EPOCH]
    /\ released \in [CPUs -> BOOLEAN]
    /\ releaseVersion \in [CPUs -> 0..MAX_EPOCH]
    /\ frees \in [CPUs -> [0..MAX_EPOCH -> 0..3]]

\* 页表先改变；只有空闲写者能推进版本。并发写者必须在空闲后才发布。
Publish(c) ==
    /\ phase[c] = "idle"
    /\ ~request.active
    /\ tableVersion < MAX_EPOCH
    /\ tableVersion' = tableVersion + 1
    /\ phase' = [phase EXCEPT ![c] = "mutated"]
    /\ UNCHANGED <<tlbView, request, ackedVersion, released, releaseVersion, frees>>

\* 本地作废与登记公告板在同一动作中完成；目标集合按本次活跃核计算（不含自己）。
Begin(c) ==
    /\ phase[c] = "mutated"
    /\ ~request.active
    /\ tlbView' = [tlbView EXCEPT ![c] = tableVersion]
    /\ phase' = [phase EXCEPT ![c] = "shooting"]
    /\ request' = [active |-> TRUE,
                   owner |-> c,
                   version |-> tableVersion,
                   targets |-> (CPUs \ {c}),
                   acked |-> {},
                   revoked |-> FALSE]
    /\ UNCHANGED <<tableVersion, ackedVersion, released, releaseVersion, frees>>

\* 目标核在核间中断里作废本地项，然后加入应答集合；两步原子建模。
Respond(c) ==
    /\ request.active
    /\ c \in request.targets
    /\ c \notin request.acked
    /\ tlbView' = [tlbView EXCEPT ![c] = request.version]
    /\ request' = [request EXCEPT !.acked = request.acked \cup {c}]
    /\ UNCHANGED <<tableVersion, phase, ackedVersion, released, releaseVersion, frees>>

\* 应答集合覆盖目标集合后，发起方离开等待。
Complete(c) ==
    /\ request.active
    /\ request.owner = c
    /\ request.acked = request.targets
    /\ phase' = [phase EXCEPT ![c] = "acked"]
    /\ ackedVersion' = [ackedVersion EXCEPT ![c] = request.version]
    /\ request' = [request EXCEPT !.active = FALSE]
    /\ UNCHANGED <<tableVersion, tlbView, released, releaseVersion, frees>>

\* 超时撤销：只清掉在途请求并标记撤销，帧仍不释放；发起方回到可重试的已修改状态。
Timeout(c) ==
    /\ request.active
    /\ request.owner = c
    /\ request.acked /= request.targets
    /\ request' = [request EXCEPT !.active = FALSE, !.revoked = TRUE]
    /\ phase' = [phase EXCEPT ![c] = "mutated"]
    /\ UNCHANGED <<tableVersion, tlbView, ackedVersion, released, releaseVersion, frees>>

\* 释放帧的独立动作：仅当发起方已收集全部应答、且每个核的视图都不旧于该应答版本。
Release(c) ==
    /\ phase[c] = "acked"
    /\ \A d \in CPUs: tlbView[d] >= ackedVersion[c]
    /\ released' = [released EXCEPT ![c] = TRUE]
    /\ releaseVersion' = [releaseVersion EXCEPT ![c] = ackedVersion[c]]
    /\ frees' = [frees EXCEPT ![c][ackedVersion[c]]
                              = frees[c][ackedVersion[c]] + 1]
    /\ phase' = [phase EXCEPT ![c] = "released"]
    /\ UNCHANGED <<tableVersion, tlbView, request, ackedVersion>>

\* 释放完成后回到空闲，等待下一次页表修改。
Reset(c) ==
    /\ phase[c] = "released"
    /\ released' = [released EXCEPT ![c] = FALSE]
    /\ releaseVersion' = [releaseVersion EXCEPT ![c] = 0]
    /\ ackedVersion' = [ackedVersion EXCEPT ![c] = 0]
    /\ phase' = [phase EXCEPT ![c] = "idle"]
    /\ UNCHANGED <<tableVersion, tlbView, request, frees>>

\* 并发发起者遇到在途请求：登记板返回 Busy，动作不改变状态（实现里会先服务在途请求再重试）。
Busy(c) ==
    /\ phase[c] = "mutated"
    /\ request.active
    /\ request.owner /= c
    /\ UNCHANGED vars

\* 版本推进到上限且所有核回到空闲后，允许停止（fairness 之外不强制终止）。
Done ==
    /\ tableVersion = MAX_EPOCH
    /\ ~request.active
    /\ \A c \in CPUs: phase[c] = "idle"
    /\ UNCHANGED vars

Next ==
    \/ \E c \in CPUs:
           Publish(c) \/ Begin(c) \/ Respond(c) \/ Complete(c)
           \/ Timeout(c) \/ Release(c) \/ Reset(c) \/ Busy(c)
    \/ Done

Spec == Init /\ [][Next]_vars

\* 性质 1：已经应答的核，其视图等于请求版本；释放后所有核的视图不旧于释放版本。
\* 对应实现：service 里先 flush 再从 pending 移除；调用方只有全部应答后才归还帧。
AckedNoStale ==
    /\ \A c \in CPUs:
           (request.active /\ c \in request.acked) => tlbView[c] = request.version
    /\ \A c \in CPUs:
           phase[c] = "released" => tlbView[c] >= releaseVersion[c]

\* 性质 2：超时撤销后公告板没有在途请求，也没有核还停在等待阶段。
\* 对应实现：tlb_shootdown_on 超时调用 ShootdownBoard::abandon；发起方不再等待。
NoResidualWait ==
    /\ \A c \in CPUs:
           phase[c] = "shooting" => (request.active /\ request.owner = c)
    /\ request.revoked => ~request.active

\* 性质 3：同一发起核针对同一版本至多释放一次；超时撤销不会释放，重试也
\* 不会让同一次击落产生第二次释放。并发发起者各自拥有不同的请求记录。
\* 对应实现：公告板同一时刻至多一个请求，begin 在在途时返回 Busy。
NoDoubleRelease ==
    \A c \in CPUs, v \in 0..MAX_EPOCH: frees[c][v] <= 1

\* 释放前置条件：释放版本对应的所有核视图都不旧于该版本（被 AckedNoStale 强化）。
ReleasedNoStale ==
    \A c \in CPUs:
        released[c] => (\A d \in CPUs: tlbView[d] >= releaseVersion[c])

=============================================================================
