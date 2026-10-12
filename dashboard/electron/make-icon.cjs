// Renders the SentinelAI app/tray icons as PNGs with no external tools.
// Run: node electron/make-icon.cjs
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, rgba) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const lerp = (a, b, t) => a + (b - a) * t;
const mix = (c1, c2, t) => c1.map((v, i) => lerp(v, c2[i], t));

function insideRoundedRect(x, y, r) {
  const qx = Math.max(Math.abs(x - 0.5) - (0.5 - r), 0);
  const qy = Math.max(Math.abs(y - 0.5) - (0.5 - r), 0);
  return qx * qx + qy * qy <= r * r;
}

function insideShield(x, y) {
  const top = 0.2, mid = 0.5, bottom = 0.8, half = 0.24;
  if (y < top || y > bottom) return false;
  const dip = 0.035 * (1 - Math.pow((x - 0.5) / half, 2));
  if (y < top + dip) return false;
  let w = half;
  if (y > mid) w = half * Math.sqrt(Math.max(0, 1 - Math.pow((y - mid) / (bottom - mid), 2)));
  return Math.abs(x - 0.5) <= w;
}

function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

function insideCheck(x, y) {
  const th = 0.035;
  return distToSegment(x, y, 0.39, 0.49, 0.47, 0.57) < th || distToSegment(x, y, 0.47, 0.57, 0.62, 0.41) < th;
}

function render(size) {
  const ss = 4;
  const buf = Buffer.alloc(size * size * 4);
  const top = [196, 181, 253], midC = [139, 92, 246], bot = [91, 63, 209], check = [109, 74, 224];
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const x = (px + (sx + 0.5) / ss) / size;
          const y = (py + (sy + 0.5) / ss) / size;
          if (!insideRoundedRect(x, y, 0.24)) continue;
          const t = (x + y) / 2;
          let c = t < 0.55 ? mix(top, midC, t / 0.55) : mix(midC, bot, (t - 0.55) / 0.45);
          if (insideShield(x, y)) c = insideCheck(x, y) ? check : [250, 250, 255];
          r += c[0]; g += c[1]; b += c[2]; a += 255;
        }
      }
      const n = ss * ss;
      const i = (py * size + px) * 4;
      const cov = a / 255;
      buf[i] = cov ? Math.round(r / cov) : 0;
      buf[i + 1] = cov ? Math.round(g / cov) : 0;
      buf[i + 2] = cov ? Math.round(b / cov) : 0;
      buf[i + 3] = Math.round(a / n);
    }
  }
  return encodePng(size, buf);
}

const out = path.join(__dirname, 'assets');
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, 'icon.png'), render(256));
fs.writeFileSync(path.join(out, 'tray.png'), render(32));
console.log('Wrote electron/assets/icon.png and tray.png');
