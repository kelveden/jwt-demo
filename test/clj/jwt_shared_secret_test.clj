(ns clj.jwt-shared-secret-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [conversion :refer :all]
            [jwt]))

(def dummy-payload {:some "data"})
(def dummy-algorithm "HS256")

(deftest can-unsign-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        secret "mysecret"
        token (jwt/sign payload secret dummy-algorithm)]
    (is (= (jwt/unsign token secret)
           payload))))

(deftest cannot-unsign-token-signed-with-different-secret
  (let [token (jwt/sign dummy-payload "mysecret" dummy-algorithm)]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt/unsign token "someothersecret")))))

(deftest cannot-unsign-token-with-tampered-header
  (let [secret "mysecret"
        token (jwt/sign dummy-payload "mysecret" dummy-algorithm)
        [header payload signature] (split token #"\.")
        tampered-header (str->base64 (json/generate-string {:a 1}))
        tampered-token (join "." [tampered-header payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt/unsign tampered-token secret)))))

(deftest cannot-unsign-token-with-tampered-payload
  (let [secret "mysecret"
        token (jwt/sign dummy-payload "mysecret" dummy-algorithm)
        [header payload signature] (split token #"\.")
        tampered-payload (str->base64 (json/generate-string {:a 1}))
        tampered-token (join "." [header tampered-payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt/unsign tampered-token secret)))))