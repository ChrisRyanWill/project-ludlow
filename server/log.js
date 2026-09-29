// Allowlist logger (rule 3). The ONLY things that can ever be logged are the fields named below:
// HTTP method, the ROUTE PATTERN (never the raw path), status code and duration. No bodies, query
// strings, headers, tokens or IP addresses — there is no code path that accepts them.
let sink = (line) => process.stdout.write(line + '\n');
export const setLogSink = (fn) => { sink = fn; };
const stamp = () => new Date().toISOString();
export const logRequest = ({ method, route, status, ms }) =>
  sink(JSON.stringify({ t: stamp(), m: method, r: route, s: status, ms }));
export const logError = ({ route, kind }) => sink(JSON.stringify({ t: stamp(), r: route, err: String(kind).slice(0, 40) }));
export const logInfo = (msg) => sink(JSON.stringify({ t: stamp(), msg: String(msg).slice(0, 100) })); // static strings only
