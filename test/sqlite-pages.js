// Reads rows straight out of a SQLite file, in the order they sit on disk, the way someone holding a copy of the database could.
// Inside a page SQLite places each new cell below the previous one, so for a table with a random primary key (our ballots) the physical offset
// of a cell still tells you WHEN it was inserted. The tests use this to check that nothing about the order people voted in survives on disk.
import fs from 'node:fs';
import path from 'node:path';

function varint(buf, off) {
  let v = 0n;
  for (let i = 0; i < 9; i++) {
    const b = buf[off + i];
    if (i === 8) return [(v << 8n) | BigInt(b), off + 9];
    v = (v << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) return [v, off + i + 1];
  }
}

function record(buf, off) {
  let [headerSize, p] = varint(buf, off);
  const end = off + Number(headerSize), types = [];
  while (p < end) { let t; [t, p] = varint(buf, p); types.push(Number(t)); }
  let q = end;
  const vals = [];
  for (const t of types) {
    if (t >= 13 && t % 2 === 1) { const n = (t - 13) / 2; vals.push(buf.subarray(q, q + n).toString('utf8')); q += n; } // text
    else if (t === 8) vals.push(0);
    else if (t === 9) vals.push(1);
    else if (t === 1) { vals.push(buf.readInt8(q)); q += 1; }
    else if (t === 0) vals.push(null);
    else { vals.push('int/' + t); q += [0, 1, 2, 3, 4, 6, 8, 8][t] ?? 0; }
  }
  return vals;
}

// Every leaf cell of an index b-tree (a WITHOUT ROWID table), with the page it is on and its offset within that page.
function leafCells(file, pageSize, root) {
  const out = [];
  const walk = (pg) => {
    const base = (pg - 1) * pageSize, hdr = pg === 1 ? base + 100 : base;
    const type = file[hdr], n = file.readUInt16BE(hdr + 3);
    const ptrs = hdr + (type === 0x02 || type === 0x05 ? 12 : 8);
    for (let i = 0; i < n; i++) {
      const off = file.readUInt16BE(ptrs + 2 * i), c = base + off;
      if (type === 0x0a) { const [, p] = varint(file, c); out.push({ page: pg, off, vals: record(file, p) }); }
      else if (type === 0x02) { walk(file.readUInt32BE(c)); }
    }
    if (type === 0x02 || type === 0x05) walk(file.readUInt32BE(hdr + 8));
  };
  walk(root);
  return out;
}

// The rows of a WITHOUT ROWID table that match `where`, one list per page, each oldest first by physical position (newest cell = lowest offset).
export function physicalOrder(h, table, where = () => true) {
  const file = fs.readFileSync(path.join(h.dir, 'test.db'));
  const pageSize = file.readUInt16BE(16) === 1 ? 65536 : file.readUInt16BE(16);
  const root = h.app.db.prepare('SELECT rootpage r FROM sqlite_master WHERE name=?').get(table).r;
  const byPage = new Map();
  for (const c of leafCells(file, pageSize, root).filter((x) => where(x.vals))) {
    if (!byPage.has(c.page)) byPage.set(c.page, []);
    byPage.get(c.page).push(c);
  }
  return [...byPage.values()].map((cs) => cs.sort((a, b) => b.off - a.off).map((c) => c.vals));
}
