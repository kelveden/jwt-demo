(ns clj.jwt-private-key-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [conversion :refer :all]
            [jwt]
            [keys]))

(def dummy-payload {:some "data"})
(def dummy-algorithm "RS256")

(deftest can-unsign-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        [private-key public-key] (keys/generate-key-pair)
        token (jwt/sign payload private-key dummy-algorithm)]
    (is (= (jwt/unsign token public-key)
           payload))))

(deftest cannot-unsign-token-signed-with-non-matching-key
  (let [[private-key] (keys/generate-key-pair)
        [_ public-key] (keys/generate-key-pair)
        token (jwt/sign dummy-payload private-key dummy-algorithm)]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt/unsign token public-key)))))

(deftest cannot-unsign-token-with-tampered-header
  (let [[private-key public-key] (keys/generate-key-pair)
        token (jwt/sign dummy-payload private-key dummy-algorithm)
        [header payload signature] (split token #"\.")
        tampered-header (str->base64 (json/generate-string {:a 1}))
        tampered-token (join "." [tampered-header payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt/unsign tampered-token public-key)))))

(deftest cannot-unsign-token-with-tampered-payload
  (let [[private-key public-key] (keys/generate-key-pair)
        token (jwt/sign dummy-payload private-key dummy-algorithm)
        [header payload signature] (split token #"\.")
        tampered-payload (str->base64 (json/generate-string {:a 1}))
        tampered-token (join "." [header tampered-payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt/unsign tampered-token public-key)))))