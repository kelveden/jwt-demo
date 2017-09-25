(ns conversion
  (:require [cheshire.core :as json]
            [clojure.data.codec.base64 :as b64]
            [clojure.walk :refer [keywordize-keys]]))

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

(defn base64->map
  [header]
  (-> header
      (base64->str)
      (json/parse-string)
      (keywordize-keys)))
