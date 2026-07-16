(ns viber.async-signature
  "Cloudflare Workers / browser counterpart to `viber.signature` — see that
  ns's docstring for the bot-token-as-HMAC-key scheme this verifies, and
  `line-messaging.async-signature` for why this is a plain `.cljs`
  namespace (Web Crypto's `SubtleCrypto.sign` is Promise-based).

  `raw-body` MUST be the exact bytes Viber sent (pre-JSON-parse) — on a
  Cloudflare Worker that means reading `request.text()` BEFORE any
  `request.json()` call (a Request body stream can only be consumed
  once)."
  )

(defn- ->key [bot-token]
  (.importKey js/crypto.subtle
              "raw"
              (.encode (js/TextEncoder.) bot-token)
              #js {:name "HMAC" :hash "SHA-256"}
              false
              #js ["sign"]))

(defn- bytes->hex [^js buf]
  (let [arr (js/Uint8Array. buf)]
    (apply str (map (fn [b] (let [h (.toString b 16)]
                              (if (= 1 (.-length h)) (str "0" h) h)))
                     (array-seq arr)))))

(defn hmac-sha256-hex
  "hex(HMAC-SHA256(bot-token, raw-body)) -- returns a `js/Promise<string>`."
  [bot-token raw-body]
  (-> (->key bot-token)
      (.then (fn [key] (.sign js/crypto.subtle "HMAC" key (.encode (js/TextEncoder.) raw-body))))
      (.then bytes->hex)))

(defn valid-signature?
  "Same contract as `viber.signature/valid-signature?`, async: returns a
  `js/Promise<boolean>`."
  [bot-token raw-body x-viber-content-signature]
  (-> (hmac-sha256-hex bot-token raw-body)
      (.then (fn [hex] (= hex (str x-viber-content-signature))))))
