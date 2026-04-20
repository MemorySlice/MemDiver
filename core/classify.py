"""ByteClassifier - classify bytes in comparison regions."""

from typing import List

from .models import ComparisonRegion


class ByteClassifier:
    """Classify each byte position as 'key', 'same', or 'different'."""

    @staticmethod
    def classify(region: ComparisonRegion) -> List[str]:
        if not region.run_data:
            return []

        ref_before, ref_key, ref_after = region.run_data[0]
        ref_full = ref_before + ref_key + ref_after
        total_len = len(ref_full)
        key_start = len(ref_before)
        key_end = key_start + region.key_length

        other_runs = [
            before + key + after
            for before, key, after in region.run_data[1:]
        ]

        classes = []
        for pos in range(total_len):
            if key_start <= pos < key_end:
                classes.append("key")
                continue

            ref_byte = ref_full[pos]
            same = all(
                (full[pos] if pos < len(full) else 0) == ref_byte
                for full in other_runs
            )
            classes.append("same" if same else "different")

        return classes
