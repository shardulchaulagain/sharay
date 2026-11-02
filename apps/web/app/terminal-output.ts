/** Bounded plain-text terminal rendering with incremental ANSI/control handling. */
export function terminalText(previous: string, chunk: string, pending = ""): { text: string; pending: string } {
  let text = previous;
  const source = pending + chunk;
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    if (char === "\x1b") {
      const rest = source.slice(index);
      if (rest.length === 1) return { text: text.slice(-524288), pending: rest };
      if (rest[1] === "[") {
        const end = rest.slice(2).search(/[@-~]/);
        if (end < 0) {
          if (rest.length > 4096) { index += rest.length; continue; }
          return { text: text.slice(-524288), pending: rest };
        }
        const sequence = rest.slice(0, end + 3);
        if (sequence === "\x1b[2J" || sequence === "\x1b[3J") text = "";
        index += sequence.length;
        continue;
      }
      if (rest[1] === "]") {
        const end = rest.slice(2).search(/\x07|\x1b\\/); // eslint-disable-line no-control-regex
        if (end < 0) {
          return { text: text.slice(-524288), pending: "\x1b]" + (rest.endsWith("\x1b") ? "\x1b" : "") };
        }
        index += end + (rest[end + 2] === "\x07" ? 3 : 4);
        continue;
      }
      if (rest[1] === "(" && rest.length < 3) return { text: text.slice(-524288), pending: rest };
      index += rest[1] === "(" ? 3 : 2;
      continue;
    }
    if (char === "\r") {
      if (source[index + 1] === "\n") { text += "\n"; index += 2; continue; }
      if (index === source.length - 1) return { text: text.slice(-524288), pending: "\r" };
      text = text.slice(0, text.lastIndexOf("\n") + 1);
    } else if (char === "\b" || char === "\x7f") {
      if (text && !text.endsWith("\n")) {
        text = text.slice(0, /[\uD800-\uDBFF][\uDC00-\uDFFF]$/.test(text) ? -2 : -1);
      }
    } else if (char === "\n" || char === "\t" || char.charCodeAt(0) >= 32) text += char;
    index++;
  }
  return { text: text.slice(-524288), pending: "" };
}
