"""Test-only lifecycle failure snapshot: frame locations, never locals/source."""
import asyncio
import os
import re
import sys
import threading

import android_bridge as bridge


def location(frame):
    return {'file': os.path.basename(frame.f_code.co_filename),
            'line': frame.f_lineno, 'function': frame.f_code.co_name}


def capture():
    worker = bridge._thread
    loop = bridge._loop
    error = bridge._error or ''
    fixed = {
        'Network engine startup timed out', 'Network engine shutdown timed out',
        'Previous network engine is still running', 'Network engine did not start',
        'Telegram listener stopped', 'Telegram listener startup timed out',
    }
    kind, _, message = error.partition(': ')
    result = {
        'worker_alive': bool(worker and worker.is_alive()),
        'worker_ident': worker.ident if worker else None,
        'active': bridge._active, 'ready': bridge._ready.is_set(),
        'loop_present': loop is not None,
        'loop_running': bool(loop and loop.is_running()),
        'loop_closed': bool(loop and loop.is_closed()),
        'stop_requested': bool(bridge._stop_event and bridge._stop_event.is_set()),
        'error_type': kind if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,80}', kind) else ('redacted' if error else ''),
        'error_message': message if message in fixed else '',
        'threads': [],
    }
    for ident, frame in list(sys._current_frames().items())[:48]:
        frames = []
        while frame is not None and len(frames) < 36:
            frames.append(location(frame))
            frame = frame.f_back
        result['threads'].append({'ident': ident, 'frames': frames})
    done = threading.Event()
    task_result = {}
    def tasks_snapshot():
        try:
            tasks = []
            for task in list(asyncio.all_tasks(loop))[:64]:
                current = task.get_coro()
                chain = []
                seen = set()
                while current is not None and id(current) not in seen and len(chain) < 40:
                    seen.add(id(current))
                    frame = getattr(current, 'cr_frame', None) or getattr(current, 'gi_frame', None)
                    if frame is not None:
                        chain.append(location(frame))
                    current = getattr(current, 'cr_await', None) or getattr(current, 'gi_yieldfrom', None)
                tasks.append({'done': task.done(), 'cancelled': task.cancelled(),
                              'cancelling': task.cancelling(), 'await_chain': chain})
            task_result['tasks'] = tasks
            task_result['task_snapshot'] = 'captured'
        except BaseException as error:
            task_result['task_snapshot'] = type(error).__name__
        finally:
            done.set()
    if loop is not None and loop.is_running() and not loop.is_closed():
        try:
            loop.call_soon_threadsafe(tasks_snapshot)
            if done.wait(2):
                result.update(task_result)
            else:
                result['task_snapshot'] = 'loop did not respond within two seconds'
        except RuntimeError:
            result['task_snapshot'] = 'loop closed during capture'
    else:
        result['task_snapshot'] = 'no running loop'
    return result
