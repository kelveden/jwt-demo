(ns jwt-shared-secret-test
  (:require [clojure.string :refer [split join]]
            [clojure.test :refer :all]
z2            [jwt-common :refer :all]
            [jwt-shared-secret :as shared-secret]
            [cheshire.core :as json]))

(def dummy-payload {:some "data"})

(deftest can-unsign-validly-signed-token
  (let [payload {:field1 "whatever" :field2 "something else"}
        secret "mysecret"
        token (jwt-shared-secret/sign-shared-secret payload secret)]
    (is (= (jwt-shared-secret/unsign-shared-secret token secret)
           payload))))

(deftest cannot-unsign-token-signed-with-different-secret
  (let [token (jwt-shared-secret/sign-shared-secret dummy-payload "mysecret")]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt-shared-secret/unsign-shared-secret token "someothersecret")))))

(deftest cannot-unsign-token-with-tampered-header
  (let [secret "mysecret"
        token (jwt-shared-secret/sign-shared-secret dummy-payload "mysecret")
        [header payload signature] (split token #"\.")
        tampered-header (str->base64 (json/generate-string {:a 1}))
        tampered-token (join "." [tampered-header payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt-shared-secret/unsign-shared-secret tampered-token secret)))))

(deftest cannot-unsign-token-with-tampered-payload
  (let [secret "mysecret"
        token (jwt-shared-secret/sign-shared-secret dummy-payload "mysecret")
        [header payload signature] (split token #"\.")
        tampered-payload (str->base64 (json/generate-string {:a 1}))
        tampered-token (join "." [header tampered-payload signature])]
    (is (thrown-with-msg? Exception #"Token has been tampered with."
                          (jwt-shared-secret/unsign-shared-secret tampered-token secret)))))