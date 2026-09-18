#!/usr/bin/env python3
"""
JOB QUEUE  -  bounded, per-chat-serialised scan scheduling.
Credits: @Poriot_ke

Before this, every /mpx run spawned its own `ThreadPoolExecutor(150)`. Ten
concurrent users meant 1,500 threads and a box that fell over — and a user could
start three scans in a row and starve everyone else.

Rules here:

  * **one scan at a time per chat** — extra submissions queue, and the user is
    told their position instead of silently racing;
  * **a global cap on concurrent jobs** — the box cannot be flooded;
  * **a shared thread budget** — each job's worker count is derived from the
    budget divided by the jobs in flight, so total threads stay bounded.

`submit()` returns immediately; work runs on daemon threads, so a crash in one
scan can never take the bot down with it.
"""
from __future__ import annotations

import threading


class JobQueue:
    def __init__(self, max_jobs: int = 4, global_threads: int = 300,
                 min_threads: int = 16):
        self.max_jobs = max(1, max_jobs)
        self.global_threads = max(1, global_threads)
        self.min_threads = max(1, min_threads)
        # RLock: _spawn() holds it while calling threads_for_job(), which locks too
        self._lock = threading.RLock()
        self._state: dict = {}          # chat -> {"active": job_id|None, "waiting": [job_id]}
        self._pending: dict = {}        # job_id -> (fn, on_start)
        self._slots = threading.Semaphore(self.max_jobs)
        self._running = 0
        self._allocated = 0            # threads handed out to in-flight jobs

    # ------------------------------------------------------------- inspect --
    def active_jobs(self) -> int:
        with self._lock:
            return self._running

    def queue_depth(self) -> int:
        with self._lock:
            return sum(len(st.get("waiting") or []) for st in self._state.values())

    def is_busy(self, chat_id) -> bool:
        with self._lock:
            st = self._state.get(str(chat_id)) or {}
            return bool(st.get("active")) or bool(st.get("waiting"))

    def position(self, chat_id, job_id) -> int:
        """1-based queue position for a job, or 0 if it is not waiting."""
        with self._lock:
            st = self._state.get(str(chat_id)) or {}
            waiting = st.get("waiting") or []
            return waiting.index(job_id) + 1 if job_id in waiting else 0

    def threads_for_job(self) -> int:
        """Advisory share of the thread budget for a job starting now."""
        with self._lock:
            return self._grant_locked()

    def _grant_locked(self) -> int:
        """Threads to hand this job, never exceeding the global budget by more
        than `min_threads` per job (caller must hold the lock)."""
        remaining = self.global_threads - self._allocated
        fair = self.global_threads // max(1, self._running)
        if remaining < self.min_threads:
            return self.min_threads
        return max(self.min_threads, min(fair, remaining))

    # -------------------------------------------------------------- submit --
    def submit(self, chat_id, job_id: str, fn, on_start=None) -> str:
        """Queue `fn(threads)` for a chat. Returns 'started' or 'queued'."""
        chat = str(chat_id)
        with self._lock:
            st = self._state.setdefault(chat, {"active": None, "waiting": []})
            self._pending[job_id] = (fn, on_start)
            if st["active"] is None:
                st["active"] = job_id
                start_now = True
            else:
                st["waiting"].append(job_id)
                start_now = False
        if start_now:
            self._spawn(chat, job_id)
            return "started"
        return "queued"

    def cancel_waiting(self, chat_id) -> int:
        """Drop a chat's queued (not running) jobs, e.g. on /cancel."""
        chat = str(chat_id)
        with self._lock:
            st = self._state.get(chat) or {}
            dropped = list(st.get("waiting") or [])
            st["waiting"] = []
            for job_id in dropped:
                self._pending.pop(job_id, None)
        return len(dropped)

    # ------------------------------------------------------------ plumbing --
    def _spawn(self, chat: str, job_id: str):
        entry = self._pending.pop(job_id, None)
        if entry is None:
            self._finish(chat, job_id)
            return
        fn, on_start = entry

        def wrapper():
            self._slots.acquire()          # global cap on concurrent jobs
            with self._lock:
                self._running += 1
                # derive the share *after* taking the slot, and debit it from the
                # budget — otherwise concurrent spawns each read the same near-zero
                # `_running` and every job grabs the whole budget
                threads = self._grant_locked()
                self._allocated += threads
            try:
                if on_start:
                    try:
                        on_start()
                    except Exception:
                        pass
                fn(threads)
            except Exception as e:         # a job must never kill the dispatcher
                print("job error", job_id, type(e).__name__, e)
            finally:
                with self._lock:
                    self._running -= 1
                    self._allocated = max(0, self._allocated - threads)
                self._slots.release()
                self._finish(chat, job_id)

        try:
            threading.Thread(target=wrapper, name=f"job-{job_id}", daemon=True).start()
        except Exception as e:             # thread exhaustion must not wedge the chat
            print("job spawn failed", job_id, type(e).__name__, e)
            with self._lock:
                self._pending[job_id] = (fn, on_start)
            self._finish(chat, job_id)

    def _finish(self, chat: str, job_id: str) -> None:
        """Free the chat's slot and start whatever was queued behind it."""
        nxt = None
        with self._lock:
            st = self._state.get(chat)
            if not st:
                return
            if st.get("active") != job_id:
                return
            if st.get("waiting"):
                nxt = st["waiting"].pop(0)
                st["active"] = nxt
            else:
                st["active"] = None
        if nxt:
            self._spawn(chat, nxt)
