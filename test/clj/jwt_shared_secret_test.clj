(ns clj.jwt-shared-secret-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [conversion :refer :all]
            [jwt])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException JWTDecodeException)))

(def dummy-payload {:some "data"})
(def dummy-algorithm "HS256")

(deftest can-unsign-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        secret  "mysecret"
        token   (jwt/encode-token payload secret dummy-algorithm)]
    (is (= (jwt/decode-token token secret)
           payload))))

(deftest cannot-unsign-token-signed-with-different-secret
  (let [token (jwt/encode-token dummy-payload "mysecret" dummy-algorithm)]
    (is (thrown? SignatureVerificationException
                 (jwt/decode-token token "someothersecret")))))

(deftest cannot-unsign-token-with-tampered-header
  (let [secret          "mysecret"
        token           (jwt/encode-token dummy-payload "mysecret" dummy-algorithm)
        [_ payload signature] (split token #"\.")
        tampered-header (str->base64 (json/generate-string {:a 1}))
        tampered-token  (join "." [tampered-header payload signature])]
    (is (thrown? JWTDecodeException
                 (jwt/decode-token tampered-token secret)))))

(deftest cannot-unsign-token-with-tampered-payload
  (let [secret           "mysecret"
        token            (jwt/encode-token dummy-payload "mysecret" dummy-algorithm)
        [header _ signature] (split token #"\.")
        tampered-payload (str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])]
    (is (thrown? SignatureVerificationException
                 (jwt/decode-token tampered-token secret)))))