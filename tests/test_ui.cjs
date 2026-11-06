// Exercise the existing browser script without launching a browser/profile.
// Only the DOM methods needed by the controls and SVG renderer are simulated.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor() {
    this.value = ''; this.textContent = ''; this.style = {}; this.children = [];
    this.attributes = {}; this.listeners = {}; this.disabled = false; this.dataset = {};
    this.classList = {add() {}, remove() {}, toggle() {}};
  }
  set innerHTML(value) { this.children = []; }
  get innerHTML() { return ''; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  removeEventListener() {}
  getBoundingClientRect() { return {left: 0, width: 1000}; }
  setPointerCapture() {}
  releasePointerCapture() {}
  focus() {}
  click() {}
  remove() {}
}

const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
let exported;
const context = vm.createContext({
  document: { getElementById: element, createElement: () => new Element(),
    createElementNS: () => new Element(), body: new Element(),
    addEventListener() {}, removeEventListener() {} },
  localStorage: {getItem: () => null, setItem() {}},
  Blob, URL: {createObjectURL(blob) { exported = blob; return 'blob:test'; }, revokeObjectURL() {}},
  console, Date, Intl, setTimeout, clearTimeout,
});
const source = fs.readFileSync(path.join(__dirname, '..', 'elitech-webui.py'), 'utf8');
const script = source.split('<script>')[1].split('</script>')[0]
  .replace('__IS_WINDOWS__', 'true').replace(/\nstart\(\);\s*$/, '\n');
vm.runInContext(script, context);

const htmlIds = new Set([...source.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
for (const id of elements.keys()) assert(htmlIds.has(id), `Missing HTML control: ${id}`);
context.renderConfig({capacity: 64000, record_count: 0, interval_seconds: 10,
  temperature_unit: 'F', probe: 'external', alarm_high: 140, alarm_low: -22});
assert.equal(element('probeSelection').value, 'external');
element('temperatureUnit').value = 'C';
element('temperatureUnit').listeners.change();
assert.equal(Number(element('alarmHigh').value), 60);
assert.equal(Number(element('alarmLow').value), -30);

element('sampleInterval').value = '5'; element('intervalUnit').value = '60';
assert.equal(context.intervalSeconds(), 300);
vm.runInContext('devices = [{serial_number: "TEST-A", name: "Freezer", connected: true, path: "hid-test", saved_count: 2, metadata: {capacity: 64000}}]; selectedSerial = "TEST-A"; configLoaded = true;', context);
context.updateConfigSaveState();
assert.equal(element('saveConfigButton').disabled, false);
element('sampleInterval').value = '15'; element('intervalUnit').value = '1';
context.updateConfigSaveState();
assert.equal(element('saveConfigButton').disabled, true);
element('sampleInterval').value = '10'; context.updateConfigSaveState();
assert.equal(element('saveConfigButton').disabled, false);

element('displayUnit').value = 'C';
assert.equal(context.formatTemperature(26), '26.0 °C');
element('displayUnit').value = 'F';
assert.equal(context.formatTemperature(26), '78.8 °F');
assert.equal(context.formatTemperature(null), '—');

const data = {stored_count: 2, loaded_count: 2, records: [
  {index: 1, timestamp: '2026-11-03 13:47:59', temperature: 26, status: 'Measurement', flags: []},
  {index: 2, timestamp: '2026-11-03 13:48:09', temperature: 27, status: 'Measurement', flags: []},
]};
context.renderMeasurements(data);
assert.equal(element('measurementMin').textContent, '78.8 °F');
assert.equal(element('measurementMax').textContent, '80.6 °F');
const walkText = node => [node.textContent, ...node.children.flatMap(walkText)];
assert(walkText(element('measurementChart')).some(text => text.includes('°F')));
context.exportMeasurementsCsv();
exported.text().then(async csv => {
  assert(csv.includes('Temperature (°F)'));
  assert(csv.includes('78.8'));
  assert(csv.includes('80.6'));
  let requestPayload;
  context.showSafetyConfirm = async () => true;
  context.loadDeviceConfig = async () => {};
  context.fetch = async (url, options) => {
    requestPayload = JSON.parse(options.body);
    return {ok: true, json: async () => ({record_count_before_save: 1831, message: 'Saved', device_time: 'now'})};
  };
  vm.runInContext('selectedSerial = "TEST-A"; currentRecordCount = 1828; currentSessionId = "session-a"; configLoaded = true; configBusy = false;', context);
  await context.saveDeviceConfig();
  assert.equal(requestPayload.path, 'hid-test');
  assert.equal(requestPayload.expected_record_count, 1828);
  assert.equal(requestPayload.expected_session_id, 'session-a');
  assert.equal(requestPayload.allow_data_loss, true);
  assert(element('configSuccessBox').textContent.includes('1,831'));
  vm.runInContext('activeTab = "measurements"; devices[0].connected = false; devices[0].path = null;', context);
  context.fetch = async url => ({ok: true, json: async () => ({...data, source: 'local-db', serial_number: 'TEST-A',
       records: data.records.map((record, i) => ({...record, session_id: 'session-' + i, probe: i ? 'external' : 'internal'}))})});
  context.updateDeviceHeaders();
  assert.equal(element('measurementsContent').style.display, 'block');
  await context.loadDeviceMeasurements();
  assert.equal(element('measurementTableBody').children[0].children[4].textContent, 'internal');
  assert.equal(element('measurementTableBody').children[1].children[4].textContent, 'external');
  assert.equal(element('measurementTableBody').children[1].children[4].style.color, '#ea580c');
  const walk = node => [node, ...node.children.flatMap(walk)];
  const colors = walk(element('measurementChart')).map(node => node.attributes.stroke || node.attributes.fill);
  assert(colors.includes('#2563eb') && colors.includes('#ea580c'));
  context.exportMeasurementsCsv();
  const historyCsv = await exported.text();
  assert(historyCsv.includes('Logger serial') && historyCsv.includes('TEST-A'));
  assert(historyCsv.includes('internal') && historyCsv.includes('external'));
  vm.runInContext('currentCapacity = 64000', context);
  element('sampleInterval').value = '10'; element('intervalUnit').value = '1';
  context.updateConfigPreview();
  assert.equal(element('durationDays').textContent, '7.41');
  assert.equal(element('durationMonths').textContent, '0.24');
  assert.equal(element('durationYears').textContent, '0.02');
  // Date bounds, navigation and chart selection work without launching a browser.
  context.useMeasurementPreset('today', false);
  const today = new Date(); today.setHours(0,0,0,0);
  const tomorrow = new Date(today); tomorrow.setDate(tomorrow.getDate() + 1);
  assert.equal(vm.runInContext('measurementRange.start', context), today.getTime());
  assert.equal(vm.runInContext('measurementRange.end', context), tomorrow.getTime());
  assert.equal(element('measurementRangePreset').value, 'today');
  let rangeUrl;
  context.fetch = async url => {
    rangeUrl = url;
    return {ok:true, json:async () => ({records:[], loaded_count:0, stored_count:2, serial_number:'TEST-A'})};
  };
  await context.loadDeviceMeasurements();
  const query = new URL(rangeUrl, 'http://localhost').searchParams;
  assert.equal(query.get('start'), context.localDateTime(today.getTime()).replace('T',' '));
  assert.equal(query.get('end'), context.localDateTime(tomorrow.getTime()).replace('T',' '));
  assert(!query.has('limit'));
  assert.equal(element('measurementChartWrap').style.display, 'block'); // empty ranges retain navigation
  const realLoad = context.loadDeviceMeasurements;
  context.loadDeviceMeasurements = async () => {};
  context.zoomMeasurementTime(0.5);
  const halfSpan = vm.runInContext('measurementRange.end-measurementRange.start', context);
  assert(Math.abs(halfSpan - (tomorrow-today)/2) <= 1000);
  context.zoomMeasurementTime(2);
  assert(Math.abs(vm.runInContext('measurementRange.end-measurementRange.start', context) - (tomorrow-today)) <= 2000);
  element('measurementStart').value = '2026-11-03T12:00';
  element('measurementEnd').value = '2026-11-03T14:00';
  context.applyMeasurementRange();
  assert.equal(vm.runInContext('measurementRange.end-measurementRange.start', context), 7200000);
  context.renderMeasurements(data);
  const overlay = element('measurementChart').children[0].children.at(-1);
  const event = x => ({clientX:x,button:0,pointerId:1,preventDefault(){}});
  overlay.listeners.pointerdown(event(68 + 910*0.75)); // reverse-direction selection
  overlay.listeners.pointermove(event(68 + 910*0.25));
  overlay.listeners.pointerup(event(68 + 910*0.25));
  assert.equal(element('measurementStart').value, '2026-11-03T12:30:00');
  assert.equal(element('measurementEnd').value, '2026-11-03T13:30:00');
  const preserved = vm.runInContext('measurementRange.start', context);
  assert.equal(context.setMeasurementRange(NaN, NaN), false);
  assert.equal(vm.runInContext('measurementRange.start', context), preserved);
  context.useMeasurementPreset('all');
  assert.equal(vm.runInContext('measurementRange', context), null);
  context.loadDeviceMeasurements = realLoad;
  await context.loadDeviceMeasurements();
  assert(!new URL(rangeUrl, 'http://localhost').searchParams.has('start'));

  // An old response must not populate the view after selecting another logger.
  let release;
  context.fetch = () => new Promise(resolve => { release = resolve; });
  const pending = context.loadDeviceMeasurements();
  vm.runInContext('selectedSerial = "TEST-B"', context);
  context.resetMeasurementView();
  release({ok: true, json: async () => ({...data, serial_number:'TEST-A'})});
  await pending;
  assert.equal(element('measurementTableBody').children.length, 1); // empty state
  console.log('UI checks passed: time ranges, zoom, drag selection, empty ranges, sensor isolation, configuration, chart and export.');
}).catch(error => { console.error(error); process.exitCode = 1; });
