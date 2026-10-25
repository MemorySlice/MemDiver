"""Linux saved queries over the ``vol3__linux_*`` case tables.

Column names are the snake_cased vol3 2.27 columns (``Offset (V)`` ->
``offset_v``): ``pslist`` offset_v,pid,tid,ppid,comm,uid,...; ``psscan``
offset_p,pid,tid,ppid,comm,exit_state; ``sockstat`` process_name,pid,fd,
sock_offset,family,type,proto,source_addr,...,state; ``proc`` (``proc.Maps``)
pid,process,start,end,flags,pgoff,major,minor,inode,file_path; ``lsmod``
offset,module_name,code_size,taints,load_arguments. Every table also carries
``capture_id`` and ``image_sha256``; results are DISTINCT so re-running a plugin
into the same case does not double rows.
"""

from __future__ import annotations

from memdiver.analysis.queries import SavedQuery

PSLIST = "vol3__linux_pslist"
PSSCAN = "vol3__linux_psscan"
SOCKSTAT = "vol3__linux_sockstat"
PROC = "vol3__linux_proc"
LSMOD = "vol3__linux_lsmod"

_PLUGIN = {PSLIST: "linux.pslist.PsList", PSSCAN: "linux.psscan.PsScan",
           SOCKSTAT: "linux.sockstat.Sockstat", PROC: "linux.proc.Maps",
           LSMOD: "linux.lsmod.Lsmod"}


def _needs(*tables: str) -> dict:
    return {t: _PLUGIN[t] for t in tables}


HIDDEN_PROCESSES = SavedQuery(
    "hidden_processes",
    "Tasks found by psscan whose pid is absent from pslist (same capture).",
    f"""SELECT DISTINCT s.capture_id, s.image_sha256, s.pid, s.tid, s.ppid, s.comm,
       s.exit_state, s.offset_p
FROM {PSSCAN} s
WHERE NOT EXISTS (SELECT 1 FROM {PSLIST} l
                  WHERE l.capture_id = s.capture_id AND l.pid = s.pid)
ORDER BY s.capture_id, s.pid""",
    _needs(PSSCAN, PSLIST))

PROCESSES_WITH_SOCKETS = SavedQuery(
    "processes_with_sockets",
    "pslist processes joined to their sockets (sockstat) on capture and pid.",
    f"""SELECT DISTINCT l.capture_id, l.pid, l.ppid, l.comm, k.fd, k.family, k.type,
       k.proto, k.source_addr, k.source_port, k.destination_addr,
       k.destination_port, k.state
FROM {PSLIST} l
JOIN {SOCKSTAT} k ON k.capture_id = l.capture_id AND k.pid = l.pid
ORDER BY l.capture_id, l.pid, k.fd""",
    _needs(PSLIST, SOCKSTAT))

RWX_MAPPINGS = SavedQuery(
    "rwx_mappings",
    "Mappings that are readable+writable+executable, or executable with no "
    "backing file (anonymous executable).",
    f"""SELECT DISTINCT capture_id, pid, process, start, "end", flags, file_path
FROM {PROC}
WHERE flags LIKE '%r%w%x%'
   OR (flags LIKE '%x%' AND (file_path IS NULL OR file_path = ''
                             OR file_path = 'Anonymous Mapping'))
ORDER BY capture_id, pid, start""",
    _needs(PROC))

MODULES_PER_PROCESS = SavedQuery(
    "modules_per_process",
    "Distinct file-backed mappings (libraries/binaries) per process.",
    f"""SELECT capture_id, pid, process, file_path
FROM {PROC}
WHERE file_path IS NOT NULL AND file_path <> '' AND file_path NOT LIKE '[%'
  AND file_path <> 'Anonymous Mapping'
GROUP BY capture_id, pid, process, file_path
ORDER BY capture_id, pid, file_path""",
    _needs(PROC))

PROCESS_DIFF = SavedQuery(
    "process_diff",
    "Process names (comm) not present in every image of the case.",
    f"""SELECT comm, count(DISTINCT image_sha256) AS images,
       list(DISTINCT image_sha256) AS present_in
FROM {PSLIST}
GROUP BY comm
HAVING count(DISTINCT image_sha256) < (SELECT count(DISTINCT image_sha256) FROM {PSLIST})
ORDER BY comm""",
    _needs(PSLIST))

QUERIES = (HIDDEN_PROCESSES, PROCESSES_WITH_SOCKETS, RWX_MAPPINGS,
           MODULES_PER_PROCESS, PROCESS_DIFF)
