interface ProxyEntry {
  address: string;
  port: number;
  country: string;
  org: string;
}

const SOURCE_URL = "https://raw.githubusercontent.com/papapapapdelesia/Emilia/refs/heads/main/Data/Country-ALIVE.txt";
const KV_PAIR_PROXY_FILE = "./kvProxyList.json";
const RAW_PROXY_LIST_FILE = "./rawProxyList.txt";
const PROXY_LIST_FILE = "./proxyList.txt";
const KV_MAX_PER_COUNTRY = 10;

function parseLine(line: string): ProxyEntry | null {
  const clean = line.trim();
  if (!clean) return null;

  // Format utama yang diharapkan: address,port,country,org (sama seperti rawProxyList.txt)
  const parts = clean.split(",").map((p) => p.trim());
  if (parts.length >= 2 && /^\d+$/.test(parts[1])) {
    return {
      address: parts[0],
      port: parseInt(parts[1], 10),
      country: parts[2] ?? "",
      org: parts[3] ?? "",
    };
  }

  // Fallback: format "IP:PORT" atau "IP:PORT#COUNTRY" / "IP:PORT,COUNTRY"
  const match = clean.match(/^([a-zA-Z0-9.\-]+):(\d+)\s*[,#]?\s*([A-Za-z]{2,})?/);
  if (match) {
    return {
      address: match[1],
      port: parseInt(match[2], 10),
      country: match[3] ?? "",
      org: "",
    };
  }

  return null;
}

async function fetchSourceList(): Promise<ProxyEntry[]> {
  const res = await fetch(SOURCE_URL);
  if (!res.ok) {
    throw new Error(`Gagal mengambil source list: ${res.status} ${res.statusText}`);
  }

  const text = await res.text();
  const entries: ProxyEntry[] = [];

  for (const line of text.split("\n")) {
    const parsed = parseLine(line);
    if (parsed && parsed.address && parsed.port) {
      entries.push(parsed);
    }
  }

  return entries;
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

function sortByCountry(a: ProxyEntry, b: ProxyEntry) {
  return (a.country || "").localeCompare(b.country || "");
}

(async () => {
  console.log("Mengambil data IP dari Country-ALIVE.txt...");

  const existingRaw = await readEntryFile(RAW_PROXY_LIST_FILE);
  const existingActive = await readEntryFile(PROXY_LIST_FILE);
  const kvPair = await readKvPair();

  const rawKeys = new Set(existingRaw.map((e) => `${e.address}:${e.port}`));
  const activeKeys = new Set(existingActive.map((e) => `${e.address}:${e.port}`));

  let fetched: ProxyEntry[] = [];
  try {
    fetched = await fetchSourceList();
  } catch (error: any) {
    console.error("Gagal fetch source list:", error.message);
    process.exit(1);
  }

  console.log(`Total entri di source: ${fetched.length}`);

  let newRawCount = 0;
  let newActiveCount = 0;

  for (const entry of fetched) {
    const key = `${entry.address}:${entry.port}`;

    if (!rawKeys.has(key)) {
      rawKeys.add(key);
      existingRaw.push(entry);
      newRawCount += 1;
    }

    if (!activeKeys.has(key)) {
      activeKeys.add(key);
      existingActive.push(entry);
      newActiveCount += 1;
    }

    const country = entry.country || "XX";
    if (kvPair[country] === undefined) kvPair[country] = [];
    if (kvPair[country].length < KV_MAX_PER_COUNTRY && !kvPair[country].includes(key)) {
      kvPair[country].push(key);
    }
  }

  console.log(`Entri baru di rawProxyList.txt: ${newRawCount}`);
  console.log(`Entri baru di proxyList.txt: ${newActiveCount}`);

  existingRaw.sort(sortByCountry);
  existingActive.sort(sortByCountry);

  const rawOutput = existingRaw.map((e) => `${e.address},${e.port},${e.country},${e.org}`).join("\n");
  const activeOutput = existingActive.map((e) => `${e.address},${e.port},${e.country},${e.org}`).join("\n");

  await Bun.write(KV_PAIR_PROXY_FILE, JSON.stringify(kvPair, null, "  "));
  await Bun.write(RAW_PROXY_LIST_FILE, rawOutput);
  await Bun.write(PROXY_LIST_FILE, activeOutput);

  console.log("Selesai. kvProxyList.json, rawProxyList.txt, dan proxyList.txt sudah diperbarui.");
})();
