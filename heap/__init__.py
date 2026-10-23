"""Heap allocator awareness: chunk layouts, free lists and byte roles.

Public data model (:mod:`.model`), platform / memory-map discovery
(:mod:`.platform`), VA-addressed reads over any dump source
(:mod:`.memory`), the allocator registry (:mod:`.registry`), allocator
detection (:mod:`.detect`) and the one analysis facade every caller uses
(:func:`.analyze.analyze_heap`).
"""

from .analyze import (analyze_heap, clear_heap_cache, heap_cache_size,
                      parse_allocator_hint)
from .detect import DetectionResult, detect_allocator
from .memory import VaMemory, strip_tag
from .model import (AllocatorKind, ChunkState, Evidence, FreeList, HeapChunk,
                    HeapLayout, HeapRegion, HeapRole)
from .platform import (ASSUMED_PLATFORM, MappedRegion, TargetPlatform,
                       memory_map_of, module_paths, platform_of)
from .registry import (AllocatorDescriptor, DetectContext, DetectScore,
                       ParseOptions, get_allocator, register_allocator,
                       registered_allocators, unregister_allocator)

__all__ = [
    "AllocatorKind", "ChunkState", "HeapRole", "HeapChunk", "HeapRegion",
    "FreeList", "Evidence", "HeapLayout",
    "TargetPlatform", "ASSUMED_PLATFORM", "MappedRegion", "platform_of",
    "memory_map_of", "module_paths",
    "VaMemory", "strip_tag",
    "AllocatorDescriptor", "DetectContext", "DetectScore", "ParseOptions",
    "register_allocator", "unregister_allocator", "registered_allocators",
    "get_allocator",
    "DetectionResult", "detect_allocator",
    "analyze_heap", "clear_heap_cache", "heap_cache_size",
    "parse_allocator_hint",
]
