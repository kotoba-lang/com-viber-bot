(ns viber.signature
  "JVM-only (see `viber.async-signature` for the Cloudflare Workers/browser
  counterpart — same sync-vs-async platform split `meta-webhook.signature`/
  `async-signature` and `line-messaging.signature`/`async-signature`
  document).

  Verifies the `X-Viber-Content-Signature` header Viber sends on every
  webhook POST: hex(HMAC-SHA256(bot-auth-token, raw-body)). **The HMAC key
  is the bot's own auth token** — unlike every Meta product (WhatsApp/
  Messenger/Instagram), which use a SEPARATE app secret distinct from the
  send-side access token, Viber has no separate webhook-signing secret; the
  same token that authenticates `send_message!`/`set-webhook!` calls also
  signs inbound webhooks. Do not go looking for a `VIBER_APP_SECRET` — it
  doesn't exist, `:creds {:bot-token}` is the only credential this whole
  library needs. The raw body bytes (pre-JSON-parse) are required for
  verification, same as every other webhook signature in this workspace."
  #?(:clj (:import [javax.crypto Mac]
                    [javax.crypto.spec SecretKeySpec])))

#?(:clj
   (defn- bytes->hex [bs]
     (apply str (map (fn [b]
                        (let [h (Integer/toHexString (bit-and (int b) 0xff))]
                          (if (= 1 (count h)) (str "0" h) h)))
                      bs))))

#?(:clj
   (defn hmac-sha256-hex
     "hex(HMAC-SHA256(bot-token, raw-body)) -- the exact value Viber puts
     in `X-Viber-Content-Signature` (no `sha256=` prefix, unlike Meta's
     scheme). `raw-body` is the request body as a String (UTF-8)."
     [bot-token raw-body]
     (let [mac (Mac/getInstance "HmacSHA256")]
       (.init mac (SecretKeySpec. (.getBytes (str bot-token) "UTF-8") "HmacSHA256"))
       (bytes->hex (.doFinal mac (.getBytes (str raw-body) "UTF-8"))))))

#?(:clj
   (defn valid-signature?
     "`bot-token` (same token used for `send_message!`/`set-webhook!` --
     see ns docstring, this is NOT a separate app secret) + the raw webhook
     request body + the `X-Viber-Content-Signature` header value -- true
     iff they match. Plain equality, not constant-time (same posture/
     rationale as `line-messaging.signature/valid-signature?`'s
     docstring)."
     [bot-token raw-body x-viber-content-signature]
     (= (hmac-sha256-hex bot-token raw-body) (str x-viber-content-signature))))
