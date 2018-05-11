(ns conversion
  (:require [cheshire.core :as json]
            [clojure.walk :refer [keywordize-keys]])
  (:import (org.apache.commons.codec.binary Base64)
           (org.apache.commons.codec Charsets)))

(defn str->base64
  "Base64 encodes the specified string. (Note that the resulting string
  is NOT URL-safe but typically should be for a JWT as the token may
  be transmitted in a query string.)"
  [x]
  {:pre [(string? x)]}
  (-> x
      (.getBytes Charsets/UTF_8)
      (Base64/encodeBase64)
      (String. Charsets/UTF_8)))

(defn base64->str
  "Base64 decodes the specified string into a plain string."
  [x]
  {:pre [(string? x)]}
  (-> x
      (.getBytes Charsets/UTF_8)
      (Base64/decodeBase64)
      (String. Charsets/UTF_8)))

(defn base64->map
  [base64-str]
  (-> base64-str
      (base64->str)
      (json/parse-string)
      (keywordize-keys)))
