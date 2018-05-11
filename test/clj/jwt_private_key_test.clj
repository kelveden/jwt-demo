(ns clj.jwt-private-key-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [conversion :refer :all]
            [jwt])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException JWTDecodeException)
           (java.security KeyPairGenerator)))

(def dummy-payload {:some "data"})
(def dummy-algorithm "RS256")

(defn- generate-key-pair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "RSA")
                    (.initialize 1024))
        key-pair (.generateKeyPair generator)]
    [(.getPrivate key-pair) (.getPublic key-pair)]))

(deftest can-unsign-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        [private-key public-key] (generate-key-pair)
        token   (jwt/encode-token payload private-key dummy-algorithm)]
    (is (= (jwt/decode-token token public-key)
           payload))))

(deftest cannot-unsign-token-signed-with-non-matching-key
  (let [[private-key] (generate-key-pair)
        [_ public-key] (generate-key-pair)
        token (jwt/encode-token dummy-payload private-key dummy-algorithm)]
    (is (thrown? SignatureVerificationException
                 (jwt/decode-token token public-key)))))

(deftest cannot-unsign-token-with-tampered-header
  (let [[private-key public-key] (generate-key-pair)
        token           (jwt/encode-token dummy-payload private-key dummy-algorithm)
        [_ payload signature] (split token #"\.")
        tampered-header (str->base64 (json/generate-string {:a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? JWTDecodeException
                 (jwt/decode-token tampered-token public-key)))))

(deftest cannot-unsign-token-with-tampered-payload
  (let [[private-key public-key] (generate-key-pair)
        token            (jwt/encode-token dummy-payload private-key dummy-algorithm)
        [header _ signature] (split token #"\.")
        tampered-payload (str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (jwt/decode-token tampered-token public-key)))))