// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Minice — https://minice.ai
//
// ROW-CARRY: a withdrawn row leaves a kind's document only through a lift.
//
// The service states the rows of a kind afresh in every answer. If the signer
// simply signed what it was given, an answer that left a row out (a fault, or
// a service that no longer behaves) would restore a withdrawn item for every
// client that had not seen the row yet. So the signer compares each answer
// with the withdrawn document it signed last: a row of that document that the
// answer omits is kept, unless the answer carries a lift for it. The run that
// kept a row publishes it and then ends failed, so that somebody looks.
//
// A lift names its row by three members, compared as they are written
// (common-v1.md §6, §6.5): `id` and `versions` as strings, and `lifts_at`
// against the row's `at`. A range is canonical, so two ranges that cover the
// same versions and are spelt differently are different, and the row stays.

/** Whether `lift` is the lift of `row`: equal on id, versions and the row's second. */
export function lifts(lift, row) {
  return lift.id === row.id && lift.versions === row.versions && lift.lifts_at === row.at;
}

/** Whether two rows are the same row: equal on id, versions and at. */
export function sameRow(a, b) {
  return a.id === b.id && a.versions === b.versions && a.at === b.at;
}

/**
 * The rows to sign: the answer's rows, then every earlier row the answer
 * dropped without lifting it, in the order the earlier document had them.
 *
 * @param {{previousRows: object[], rows: object[], lifts: object[]}} o
 * @returns {{rows: object[], carried: object[]}}
 */
export function carryRows({ previousRows, rows, lifts: liftList }) {
  const carried = previousRows.filter((p) => !rows.some((r) => sameRow(r, p)) && !liftList.some((l) => lifts(l, p)));
  return { rows: [...rows, ...carried], carried };
}
