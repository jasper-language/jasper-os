//! 批处理作业队列的宿主测试。
//! Host tests for the batch job queue.

use super::*;

fn queue_with(ids: &[(u32, JobPriority, &[u32])]) -> JobQueue {
    let mut queue = JobQueue::new();
    for (id, priority, deps) in ids {
        queue.submit(*id, *priority, deps).expect("提交应成功");
    }
    queue
}

#[test]
fn picks_by_priority_then_submission_order() {
    let queue = queue_with(&[
        (1, JobPriority::Low, &[]),
        (2, JobPriority::High, &[]),
        (3, JobPriority::High, &[]),
    ]);
    // 两个 High 里先提交的 2 号先跑。
    assert_eq!(queue.pick(), Some(2));
}

#[test]
fn dependency_gates_runnable_state() {
    let mut queue = queue_with(&[(1, JobPriority::Normal, &[]), (2, JobPriority::High, &[1])]);
    assert_eq!(queue.get(2).unwrap().state, JobState::Submitted);
    assert_eq!(queue.pick(), Some(1), "依赖未完成的作业不能被选中");
    queue.start(1).unwrap();
    queue.finish(1, 0).unwrap();
    assert_eq!(queue.get(2).unwrap().state, JobState::Runnable);
    assert_eq!(queue.pick(), Some(2));
}

#[test]
fn failed_dependency_does_not_unblock() {
    let mut queue = queue_with(&[(1, JobPriority::Normal, &[]), (2, JobPriority::Normal, &[1])]);
    queue.start(1).unwrap();
    queue.finish(1, 7).unwrap();
    assert_eq!(queue.get(1).unwrap().state, JobState::Failed);
    assert_eq!(queue.get(2).unwrap().state, JobState::Submitted);
    assert_eq!(queue.pick(), None);
}

#[test]
fn cancel_works_before_and_during_run() {
    let mut queue = queue_with(&[(1, JobPriority::Normal, &[]), (2, JobPriority::Normal, &[1])]);
    assert_eq!(queue.cancel(1).unwrap(), JobState::Runnable);
    assert_eq!(queue.get(1).unwrap().state, JobState::Cancelled);
    // 取消的依赖不解除等待。
    assert_eq!(queue.get(2).unwrap().state, JobState::Submitted);

    let mut queue = queue_with(&[(3, JobPriority::Normal, &[])]);
    queue.start(3).unwrap();
    assert_eq!(queue.cancel(3).unwrap(), JobState::Running);
    assert_eq!(queue.get(3).unwrap().state, JobState::Cancelled);
}

#[test]
fn terminal_jobs_cannot_be_cancelled_again() {
    let mut queue = queue_with(&[(1, JobPriority::Normal, &[])]);
    queue.start(1).unwrap();
    queue.finish(1, 0).unwrap();
    assert_eq!(queue.cancel(1), Err(JobError::NotCancellable));
}

#[test]
fn submit_rejects_duplicates_unknown_deps_and_self_deps() {
    let mut queue = queue_with(&[(1, JobPriority::Normal, &[])]);
    assert_eq!(queue.submit(1, JobPriority::Normal, &[]), Err(JobError::Duplicate));
    assert_eq!(queue.submit(2, JobPriority::Normal, &[9]), Err(JobError::Unknown));
    assert_eq!(queue.submit(3, JobPriority::Normal, &[3]), Err(JobError::SelfDependency));
}

#[test]
fn queue_full_is_reported() {
    let mut queue = JobQueue::new();
    for index in 0..MAX_JOBS {
        queue.submit(index as u32 + 1, JobPriority::Normal, &[]).unwrap();
    }
    assert_eq!(queue.submit(99, JobPriority::Normal, &[]), Err(JobError::Full));
}

#[test]
fn too_many_dependencies_are_rejected() {
    let mut queue = JobQueue::new();
    queue.submit(1, JobPriority::Normal, &[]).unwrap();
    let deps = [1u32; MAX_DEPS + 1];
    assert_eq!(queue.submit(2, JobPriority::Normal, &deps), Err(JobError::Full));
}

#[test]
fn finish_requires_running() {
    let mut queue = queue_with(&[(1, JobPriority::Normal, &[])]);
    assert_eq!(queue.finish(1, 0), Err(JobError::NotRunning));
    assert_eq!(queue.start(9), Err(JobError::Unknown));
}

#[test]
fn stats_track_every_state() {
    let mut queue = queue_with(&[
        (1, JobPriority::Normal, &[]),
        (2, JobPriority::Normal, &[]),
        (3, JobPriority::Normal, &[1]),
    ]);
    queue.start(1).unwrap();
    queue.finish(1, 0).unwrap();
    queue.start(2).unwrap();
    let stats = queue.stats();
    assert_eq!(stats.total, 3);
    assert_eq!(stats.completed, 1);
    assert_eq!(stats.running, 1);
    assert_eq!(stats.runnable, 1); // 3 号依赖已满足
    assert_eq!(stats.failed, 0);
    assert_eq!(stats.cancelled, 0);
}
