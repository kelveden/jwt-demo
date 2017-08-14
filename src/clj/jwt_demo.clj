(ns jwt-demo
  (:require [cheshire.core :as json]
            [clojure.data.codec.base64 :as b64]
            [clojure.set :refer [superset?]]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [clojure.walk :refer [keywordize-keys]]
            [pandect.algo.sha256 :as sha256])
  (:import java.util.Base64))

(defn to-base64
  "Base64 encodes the specified string. (Note that the resulting string
  is NOT URL-safe but typically should be for a JWT as the token may
  be transmitted in a query string.)"
  [x]
  {:pre [(string? x)]}
  (-> x
      (.getBytes "utf8")
      (b64/encode)
      (String. "utf8")))

(defn from-base64
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

(defn token-valid?
  "Verifies that the specified signature is valid for the given header and payload
  by recreating the signature and comparing."
  [header-b64str payload-b64str signature-b64str secret]
  {:pre [(string? header-b64str) (string? payload-b64str) (string? signature-b64str)]}
  (= (create-signature header-b64str payload-b64str secret)
     (from-base64 signature-b64str)))

(defn header-valid?
  [header]
  {:pre [(string? header)]}
  (superset? #{:alg :typ}
             (keys (-> header
                       (from-base64)
                       (json/parse-string)
                       (keywordize-keys)))))

(defn sign
  "Creates a JWS flavoured JSON web token."
  [claims secret]
  {:pre [(map? claims) (string? secret)]}

  (let [header (-> {:alg "HS256"}
                   (json/generate-string)
                   (to-base64))
        payload (-> claims
                    (json/generate-string)
                    (to-base64))
        signature (-> (create-signature header payload secret)
                      (to-base64))]
    (str header "." payload "." signature)))

(defn unsign
  "Unpacks the payload from a JWS flavoured JSON web token including verifying that the signature is valid."
  [token secret]
  {:pre [(string? token)]}
  (let [[header payload signature] (split token #"\.")]
    (if (and (header-valid? header)
             (token-valid? header payload signature secret))
      (-> payload
          (from-base64)
          (json/parse-string)
          (keywordize-keys))
      (throw (ex-info "Token has been tampered with." {})))))










(def dummy-payload {:some "data"})

(deftest can-unsign-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        secret "mysecret"
        token (sign payload secret)]
    (is (= (unsign token secret)
           payload))))

(deftest cannot-unsign-token-signed-with-different-secret
  (let [token (sign dummy-payload "mysecret")]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (unsign token "someothersecret")))))

(deftest cannot-unsign-token-with-tampered-header
  (let [secret "mysecret"
        token (sign dummy-payload "mysecret")
        [header payload signature] (split token #"\.")
        tampered-header (to-base64 (json/generate-string {:a 1}))
        tampered-token (join "." [tampered-header payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (unsign tampered-token secret)))))

(deftest cannot-unsign-token-with-tampered-payload
  (let [secret "mysecret"
        token (sign dummy-payload "mysecret")
        [header payload signature] (split token #"\.")
        tampered-payload (to-base64 (json/generate-string {:a 1}))
        tampered-token (join "." [header tampered-payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (unsign tampered-token secret)))))