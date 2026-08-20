interface ProxyEntry {
  address: string;
  port: number;
  country: string;
  org: string;
}

const KV_PAIR_PROXY_FILE = "./kvProxyList.json";
const RAW_PROXY_LIST_FILE = "./rawProxyList.txt";
const PROXY_LIST_FILE = "./proxyList.txt";

function parseLine(line: string): ProxyEntry | null {
  const clean = line.trim();
  if (!clean) return null;

  const parts = clean.split(",").map((p) => p.trim());
  if (parts.length >= 2 && /^\d+$/.test(parts[1])) {
    return {
      address: parts[0],
      port: parseInt(parts[1], 10),
      country: parts[2] ?? "",
      org: parts[3] ?? "",
    };
  }

  return null;
}

function keyOf(entry: ProxyEntry): string {
  return `${entry.address.toLowerCase()}:${entry.port}`;
}

function addressOf(entry: ProxyEntry): string {
  return entry.address.toLowerCase();
}

function orgKeyOf(entry: ProxyEntry): string {
  return entry.org.trim().toLowerCase();
}

async function readEntryFile(path: string): Promise<ProxyEntry[]> {
  const file = Bun.file(path);
  if (!(await file.exists())) return [];

  const text = await file.text();
  const entries: ProxyEntry[] = [];

  for (const line of text.split("\n")) {
    const parsed = parseLine(line);
    if (parsed && parsed.address && parsed.port) {
      entries.push(parsed);
    }
  }

  return entries;
}

async function readKvPair(): Promise<Record<string, string[]>> {
  const file = Bun.file(KV_PAIR_PROXY_FILE);
  if (!(await file.exists())) return {};

  try {
    return JSON.parse(await file.text());
  } catch {
    return {};
  }
}

// Buang entri dengan address:port yang sama, ATAU org (nama penyedia) yang sama
// dari address yang berbeda. IP yang sama dengan port beda TETAP dipertahankan
// walau org-nya sama (dianggap satu host yang buka banyak port, bukan duplikat).
function dedupeEntries(entries: ProxyEntry[]): { unique: ProxyEntry[]; removed: number } {
  const seenKeys = new Set<string>();
  const seenAddresses = new Set<string>();
  const seenOrgs = new Set<string>();
  const unique: ProxyEntry[] = [];

  for (const entry of entries) {
    const key = keyOf(entry);
    if (seenKeys.has(key)) continue;

    const address = addressOf(entry);
    const orgKey = orgKeyOf(entry);
    const sameHostDifferentPort = seenAddresses.has(address);

    // Org duplikat cuma dianggap duplikat kalau address-nya juga baru
    if (!sameHostDifferentPort && orgKey && seenOrgs.has(orgKey)) continue;

    seenKeys.add(key);
    seenAddresses.add(address);
    if (orgKey) seenOrgs.add(orgKey);
    unique.push(entry);
  }

  return { unique, removed: entries.length - unique.length };
}

function sortByCountry(a: ProxyEntry, b: ProxyEntry) {
  return (a.country || "").localeCompare(b.country || "");
}

(async () => {
  console.log("Mengecek duplikat proxy di rawProxyList.txt, proxyList.txt, dan kvProxyList.json...");

  const rawEntries = await readEntryFile(RAW_PROXY_LIST_FILE);
  const activeEntries = await readEntryFile(PROXY_LIST_FILE);
  const kvPair = await readKvPair();

  const { unique: uniqueRaw, removed: rawRemoved } = dedupeEntries(rawEntries);
  const { unique: uniqueActive, removed: activeRemoved } = dedupeEntries(activeEntries);

  // kvProxyList.json gak nyimpen field org, jadi acuannya adalah key (address:port)
  // yang masih valid di proxyList.txt setelah dedupe org+key di atas
  const validActiveKeys = new Set(uniqueActive.map((e) => keyOf(e)));

  // Dedupe kvProxyList.json: dalam satu negara sekaligus lintas negara,
  // key yang sudah dipakai negara sebelumnya (urutan file) tidak dipakai lagi,
  // dan key yang udah kebuang dari proxyList.txt (karena org duplikat) juga dibuang
  const seenKvKeys = new Set<string>();
  let kvRemoved = 0;
  for (const country of Object.keys(kvPair)) {
    const uniqueList: string[] = [];
    for (const key of kvPair[country]) {
      const normalized = key.toLowerCase();
      if (seenKvKeys.has(normalized) || !validActiveKeys.has(normalized)) {
        kvRemoved += 1;
        continue;
      }
      seenKvKeys.add(normalized);
      uniqueList.push(key);
    }
    kvPair[country] = uniqueList;
  }

  uniqueRaw.sort(sortByCountry);
  uniqueActive.sort(sortByCountry);

  const rawOutput = uniqueRaw.map((e) => `${e.address},${e.port},${e.country},${e.org}`).join("\n");
  const activeOutput = uniqueActive.map((e) => `${e.address},${e.port},${e.country},${e.org}`).join("\n");

  await Bun.write(RAW_PROXY_LIST_FILE, rawOutput);
  await Bun.write(PROXY_LIST_FILE, activeOutput);
  await Bun.write(KV_PAIR_PROXY_FILE, JSON.stringify(kvPair, null, "  "));

  console.log(`Duplikat dibuang dari rawProxyList.txt: ${rawRemoved}`);
  console.log(`Duplikat dibuang dari proxyList.txt: ${activeRemoved}`);
  console.log(`Duplikat dibuang dari kvProxyList.json: ${kvRemoved}`);
  console.log("Selesai.");
})();
