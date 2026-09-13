import { describe, expect, it } from "vitest";

import {
  weightedPlurality,
  weightedPluralityByte,
  type ByteVote,
} from "@/utils/plurality";

/**
 * The reducer behind the byte the analyst actually reads.
 *
 * Every case here is one that would be invisible on screen if it were wrong: a
 * plurality that quietly counted an absent dump, a tie broken by selection
 * order, or a weight that failed to move the winner all produce a perfectly
 * plausible hex grid. The arithmetic is therefore pinned here rather than
 * inferred from a rendered cell.
 */

function votes(...pairs: [number | undefined, number][]): ByteVote[] {
  return pairs.map(([byte, weight]) => ({ byte, weight }));
}

describe("weightedPlurality unanimity", () => {
  it("returns the agreed byte when every dump holds it", () => {
    const result = weightedPlurality(votes([0xa3, 1], [0xa3, 1], [0xa3, 1]));

    expect(result.byte).toBe(0xa3);
    expect(result.agreeing).toBe(3);
    expect(result.present).toBe(3);
    expect(result.unanimous).toBe(true);
  });

  /**
   * The compatibility promise: with nothing touched and every dump included,
   * wherever the dumps agree the painted byte is the byte the overlay always
   * painted. A single present dump is the degenerate case of that.
   */
  it("returns the only present dump's byte unchanged", () => {
    expect(weightedPluralityByte(votes([0x7f, 1]))).toBe(0x7f);
  });
});

describe("weightedPlurality majorities", () => {
  it("gives a 2/1 split to the majority", () => {
    const result = weightedPlurality(votes([0xaa, 1], [0xbb, 1], [0xbb, 1]));

    expect(result.byte).toBe(0xbb);
    expect(result.agreeing).toBe(2);
    expect(result.present).toBe(3);
    expect(result.unanimous).toBe(false);
  });

  it("reports the winner's weight, not its head count", () => {
    const result = weightedPlurality(votes([0xbb, 1.5], [0xbb, 1.5], [0xaa, 1]));

    expect(result.byte).toBe(0xbb);
    expect(result.weight).toBe(3);
    expect(result.agreeing).toBe(2);
  });
});

describe("weightedPlurality weights", () => {
  /**
   * The arithmetic, pinned rather than assumed. `1.5 < 2.0`, so ONE dump at
   * 1.5x does NOT out-vote two dumps at 1.0x — the heavy weight is a thumb on
   * the scale, not a veto. Getting this backwards would let a single dump the
   * analyst merely found interesting rewrite the whole grid.
   */
  it("does not let one 1.5x vote beat two 1.0x votes", () => {
    expect(weightedPluralityByte(votes([0xaa, 1.5], [0xbb, 1], [0xbb, 1]))).toBe(0xbb);
  });

  /** It DOES beat one 1.0x vote, which is the whole point of the control. */
  it("lets a 1.5x vote beat a single 1.0x vote", () => {
    // Equal weights would tie here and the tie-break would pick 0xAA (lower),
    // so a winner of 0xBB can only have come from the weight.
    expect(weightedPluralityByte(votes([0xbb, 1.5], [0xaa, 1]))).toBe(0xbb);
  });

  /** And it beats two HALVED votes: 1.5 > 0.5 + 0.5. */
  it("lets one 1.5x vote beat two 0.5x votes", () => {
    expect(weightedPluralityByte(votes([0xbb, 1.5], [0xaa, 0.5], [0xaa, 0.5]))).toBe(0xbb);
  });

  it("ignores a zero or negative weight entirely", () => {
    const result = weightedPlurality(votes([0xaa, 0], [0xbb, 1]));

    expect(result.byte).toBe(0xbb);
    expect(result.present).toBe(1);
  });
});

describe("weightedPlurality absence", () => {
  /**
   * An absent dump is not a vote for `0x00`. `multi-hex-store.getByteAt` hands
   * back the stored `0` for a byte no dump holds, so a tally that skipped the
   * presence mask would count phantom zeroes — and paint a confident `00` over
   * a hole in the address space.
   */
  it("keeps an absent dump out of the tally", () => {
    const result = weightedPlurality(votes([undefined, 1], [0xaa, 1], [undefined, 1]));

    expect(result.byte).toBe(0xaa);
    expect(result.agreeing).toBe(1);
    expect(result.present).toBe(1);
    expect(result.unanimous).toBe(true);
  });

  it("cannot let absence out-vote a byte, however many dumps are absent", () => {
    expect(
      weightedPluralityByte(votes([undefined, 1.5], [undefined, 1.5], [0xaa, 0.5])),
    ).toBe(0xaa);
  });

  it("returns undefined when nobody is present", () => {
    const result = weightedPlurality(votes([undefined, 1], [undefined, 1.5]));

    expect(result.byte).toBeUndefined();
    expect(result.present).toBe(0);
    expect(result.agreeing).toBe(0);
    // Unanimity among nobody is not a finding: a void offset must never read
    // as perfect agreement.
    expect(result.unanimous).toBe(false);
  });

  it("returns undefined for no votes at all", () => {
    expect(weightedPluralityByte([])).toBeUndefined();
  });
});

describe("weightedPlurality tie-break", () => {
  /**
   * Lowest byte value wins. The alternatives — first voter, or the anchor —
   * both make the painted byte depend on something that is not a fact about
   * memory (the order of the rail, or which pane has focus), so re-ordering the
   * selection would silently repaint the grid.
   */
  it("breaks an even tie towards the lower byte value", () => {
    expect(weightedPluralityByte(votes([0xbb, 1], [0xaa, 1]))).toBe(0xaa);
  });

  it("breaks the tie the same way whatever order the votes arrive in", () => {
    expect(weightedPluralityByte(votes([0xaa, 1], [0xbb, 1]))).toBe(0xaa);
    expect(weightedPluralityByte(votes([0xbb, 1], [0xaa, 1]))).toBe(0xaa);
    expect(weightedPluralityByte(votes([0x00, 1], [0xff, 1]))).toBe(0x00);
    expect(weightedPluralityByte(votes([0xff, 1], [0x00, 1]))).toBe(0x00);
  });

  it("breaks a three-way tie towards the lowest of the three", () => {
    expect(weightedPluralityByte(votes([0x10, 1], [0x02, 1], [0x40, 1]))).toBe(0x02);
  });

  /** A weighted tie breaks the same way: the rule is on the SUM, not the count. */
  it("breaks a tie made of unequal weights towards the lower byte", () => {
    // 0xBB: 0.5 + 0.5 = 1.0; 0xAA: 1.0. Tie, so the lower value takes it.
    expect(weightedPluralityByte(votes([0xbb, 0.5], [0xbb, 0.5], [0xaa, 1]))).toBe(0xaa);
  });
});

/**
 * The tally is a pair of REUSED module-level scratch arrays rather than two
 * freshly allocated `Map`s — 2,080 fewer objects per rendered frame. Reuse is
 * only safe while every slot a call touches is cleared again afterwards, so
 * these pin the two ways that could go wrong: state surviving into the next
 * call, and a caller stepping outside the byte domain the arrays index.
 */
describe("weightedPlurality scratch reuse", () => {
  it("leaves no tally behind for the next call", () => {
    // 0xAA wins three votes here...
    expect(weightedPluralityByte(votes([0xaa, 1], [0xaa, 1], [0xaa, 1]))).toBe(0xaa);
    // ...and must carry none of that weight into a call it does not appear in.
    const next = weightedPlurality(votes([0xbb, 1], [0xaa, 1]));
    expect(next.byte).toBe(0xaa); // the tie-break, not three stale votes
    expect(next.weight).toBe(1);
    expect(next.agreeing).toBe(1);
    expect(next.present).toBe(2);
    expect(next.unanimous).toBe(false);
  });

  it("reports the same result when the same votes are reduced twice", () => {
    const same = votes([0xbb, 1.5], [0xaa, 1], [0xbb, 0.5]);
    expect(weightedPlurality(same)).toEqual(weightedPlurality(same));
  });

  it("still answers for a value outside the byte domain", () => {
    // Not a byte, and therefore not an index into the scratch arrays. The
    // general reducer takes it rather than writing out of bounds.
    const result = weightedPlurality(votes([300, 1], [300, 1], [0x05, 1]));
    expect(result.byte).toBe(300);
    expect(result.agreeing).toBe(2);
    expect(result.present).toBe(3);
  });

  it("accepts a one-shot iterable as well as an array", () => {
    function* stream(): Generator<ByteVote> {
      yield { byte: 0xaa, weight: 1 };
      yield { byte: 0xbb, weight: 1.5 };
    }
    expect(weightedPlurality(stream()).byte).toBe(0xbb);
  });
});
