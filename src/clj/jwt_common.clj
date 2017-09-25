(ns jwt-common
  (:require [cheshire.core :as json]
            [clojure.data.codec.base64 :as b64]
            [clojure.set :refer [superset?]]
            [clojure.walk :refer [keywordize-keys]]
            [pandect.algo.sha256 :as sha256])
  (:import java.util.Base64))

(defn str->base64
  "Base64 encodes the specified string. (Note that the resulting string
  is NOT URL-safe but typically should be for a JWT as the token may
  be transmitted in a query string.)"
  [x]
  {:pre [(string? x)]}
  (-> x
      (.getBytes "utf8")
      (b64/encode)
      (String. "utf8")))

(defn base64->str
  "Base64 decodes the specified string into a plain string."
  [x]
  {:pre [(string? x)]}
  (-> x
      (.getBytes "utf8")
      (b64/decode)
      (String. "utf8")))

(defn create-signature
  "Creates a JWS signature as a hash of the given header, payload and secret."
  [header-b64str payload-b64str secret]
  {:pre [(string? header-b64str) (string? payload-b64str) (string? secret)]}
  (-> (str header-b64str payload-b64str)
      (sha256/sha256-hmac secret)))

(defn token-corrupted?
  "Verifies that the specified token has not been corrupted or tampered with by
  by recreating the signature from the given header and payload and comparing with
  the given signature."
  [{:keys [header payload signature] :as token} secret]
  (not= (create-signature header payload secret)
        (base64->str signature)))

(defn header-keys-valid?
  [header]
  {:pre [(string? header)]}
  (superset? #{:alg :typ}
             (keys (-> header
                       (base64->str)
                       (json/parse-string)
                       (keywordize-keys)))))
