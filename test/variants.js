'use strict';

const LETTERS = {
  A: ['\u0410', '\u0391', 'a'], B: ['\u0412', '\u0392', 'b'], C: ['\u0421', 'c'], E: ['\u0415', '\u0395', 'e'], H: ['\u041d', '\u0397', 'h'], I: ['\u0406', '\u0399', 'i', 'l', '1'], J: ['\u0408', 'j'],
  K: ['\u041a', '\u039a', 'k'], M: ['\u041c', '\u039c', 'm'], N: ['\u039d', 'n'], O: ['\u041e', '\u039f', 'o', '0'], P: ['\u0420', '\u03a1', 'p'], S: ['\u0405', 's'], T: ['\u0422', '\u03a4', 't'], X: ['\u0425', '\u03a7', 'x'],
  a: ['\u0430', 'A'], c: ['\u0441', 'C'], e: ['\u0435', 'E'], i: ['\u0456', 'I', 'l', '1'], j: ['\u0458', 'J'], o: ['\u043e', 'O', '0'], p: ['\u0440', 'P'], s: ['\u0455', 'S'], x: ['\u0445', 'X'],
  0: ['O', 'o', '\u043e', '\u041e'], 1: ['I', 'l', 'i'],
};
const SEPARATORS = ['-', '\u2010', '\u2011', '\u2013', '\u2212', ' ', '.', '/', '_', ''];
const fullwidth = (c) => (c >= '!' && c <= '~' ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c);

function variantOf(rng, text) {
  const pick = (a) => a[Math.floor(rng() * a.length)];
  let out = '';
  const chars = [...text];
  for (let i = 0; i < chars.length; i += 1) {
    const ch = chars[i];
    const r = rng();
    if (/[-\s./_]/.test(ch)) out += pick(SEPARATORS);
    else if (r < 0.3 && LETTERS[ch]) out += pick(LETTERS[ch]);
    else if (r < 0.45) out += fullwidth(ch);
    else if (r < 0.6) out += ch.toLowerCase() === ch ? ch.toUpperCase() : ch.toLowerCase();
    else out += ch;
    if (rng() < 0.1 && !(/[0-9]/.test(ch) && /[0-9]/.test(chars[i + 1] || ''))) out += pick(SEPARATORS);
  }
  return out;
}

function atSeam(F, text) {
  const shape = (ch) => {
    if (ch === '0' || ch === '1') return 'A';
    if (/[0-9]/.test(ch)) return 'N';
    if (!/\p{L}/u.test(ch)) return 'S';
    const c = F.canonicalIdentifier(ch, 'a', 64);
    return c === 'o' || c === 'l' ? 'A' : 'L';
  };
  const all = [...text.normalize('NFKC')].filter((ch) => shape(ch) !== 'S');
  const kinds = all.map(shape);
  for (let i = 0; i < kinds.length;) {
    if (kinds[i] !== 'A') {
      i += 1;
      continue;
    }
    let j = i;
    while (j < kinds.length && kinds[j] === 'A') j += 1;
    const sides = [i > 0 ? kinds[i - 1] : 'S', j < kinds.length ? kinds[j] : 'S'];
    const real = all.slice(i, j).some((ch) => /[01]/.test(ch));
    if (sides.includes('L') && (sides.includes('N') || real)) return true;
    i = j;
  }
  return false;
}

function variantAwayFromSeam(F, rng, text) {
  for (let k = 0; k < 64; k += 1) {
    const v = variantOf(rng, text);
    if (!atSeam(F, v)) return v;
  }
  return text;
}

module.exports = { variantOf, atSeam, variantAwayFromSeam };
