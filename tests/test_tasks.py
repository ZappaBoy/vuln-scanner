"""TaskQueue: posting, atomic claim, completion, and the delegation guardrails."""

import threading

from vuln_scanner.agents.tasks import Task, TaskQueue, TaskStatus


def test_post_and_claim_roundtrip():
    queue = TaskQueue()
    task = queue.post("web", "test /login for XSS", target="https://t.lab", created_by="lead")
    assert task is not None
    assert task.status == TaskStatus.PENDING
    assert task.depth == 1

    claimed = queue.claim(role="web", claimed_by="web-1")
    assert claimed is not None and claimed.id == task.id
    assert claimed.status == TaskStatus.CLAIMED
    assert claimed.claimed_by == "web-1"
    # Nothing pending for that role now.
    assert queue.claim(role="web") is None


def test_empty_objective_rejected():
    queue = TaskQueue()
    assert queue.post("web", "   ") is None


def test_claim_matches_role_or_any():
    queue = TaskQueue()
    queue.post("web", "a")
    queue.post("", "b")  # any-role task
    # A network worker can claim the any-role task but not the web one.
    claimed = queue.claim(role="network")
    assert claimed is not None and claimed.objective == "b"


def test_claim_is_fifo_by_timestamp():
    queue = TaskQueue()
    first = queue.post("web", "first")
    second = queue.post("web", "second")
    assert queue.claim(role="web").id == first.id
    assert queue.claim(role="web").id == second.id


def test_max_tasks_cap():
    queue = TaskQueue(max_tasks=2)
    assert queue.post("web", "1") is not None
    assert queue.post("web", "2") is not None
    assert queue.post("web", "3") is None


def test_max_depth_blocks_deep_delegation():
    queue = TaskQueue(max_depth=2)
    root = queue.post("web", "root")  # depth 1
    assert root.depth == 1
    child = queue.post("web", "child", parent=root)  # depth 2
    assert child is not None and child.depth == 2
    grandchild = queue.post("web", "grandchild", parent=child)  # depth 3 > max
    assert grandchild is None


def test_complete_and_fail_are_terminal():
    queue = TaskQueue()
    task = queue.post("web", "work")
    assert queue.complete(task.id, "done") is True
    # Cannot re-finish a terminal task.
    assert queue.complete(task.id, "again") is False
    assert queue.fail(task.id, "nope") is False


def test_has_open_work_tracks_lifecycle():
    queue = TaskQueue()
    assert queue.has_open_work() is False
    task = queue.post("web", "work")
    assert queue.has_open_work() is True
    queue.claim(role="web")
    assert queue.has_open_work() is True
    queue.complete(task.id, "done")
    assert queue.has_open_work() is False


def test_concurrent_claim_never_double_assigns():
    queue = TaskQueue(max_tasks=500)
    for i in range(200):
        queue.post("web", f"task {i}")

    claimed: list[Task] = []
    lock = threading.Lock()

    def worker():
        while True:
            task = queue.claim(role="web", claimed_by="w")
            if task is None:
                return
            with lock:
                claimed.append(task)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ids = [t.id for t in claimed]
    assert len(ids) == 200
    assert len(set(ids)) == 200  # no task claimed twice
