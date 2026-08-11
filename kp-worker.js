/*
 * Web Worker wrapper around kp-verify.js.
 *
 * Verifying a 4096-bit certificate is roughly a minute of solid BigInt
 * arithmetic. On the main thread that freezes the tab: typing lags, the
 * progress bar does not move, results appear late. Running it here keeps the
 * page responsive while the work happens on a separate thread.
 *
 * Copyright (c) 2026 RECHECK Piotr Burylo. MIT License.
 */
/* global importScripts, KPVerify */
importScripts("kp-verify.js");

self.onmessage = async (ev) => {
  const { text, strict } = ev.data;
  try {
    const cert = KPVerify.parseJSON(text);
    let lastSent = 0;
    const onProgress = (done, total) => {
      const now = Date.now();
      if (now - lastSent > 100 || done === total) {
        lastSent = now;
        self.postMessage({ type: "progress", done, total });
      }
    };
    const started = Date.now();
    const [ok, why] = await KPVerify.verify(cert, { strict, onProgress });
    self.postMessage({
      type: "done",
      ok,
      why,
      seconds: (Date.now() - started) / 1000,
      claim: cert.claim || cert.format,
      links: cert.ecpp_chain ? cert.ecpp_chain.length : 0,
      bits: cert.N ? BigInt(cert.N).toString(2).length
          : (cert.p ? BigInt(cert.p).toString(2).length : null)
    });
  } catch (e) {
    self.postMessage({ type: "error", message: String((e && e.message) || e) });
  }
};
