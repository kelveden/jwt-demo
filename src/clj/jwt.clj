(ns jwt
  (:require [conversion :refer [base64->map]])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           (com.auth0.jwt.exceptions JWTDecodeException)))

(defn- encode-token*
  [algorithm claims]
  (-> (reduce (fn [acc [k v]]
                (.withClaim acc k v))
              (JWT/create)
              (clojure.walk/stringify-keys claims))
      (.sign algorithm)))

(defmulti encode-token
          "Encodes the given claims as a JWT using the given arguments as a basis."
          (fn [_ _ alg] alg))

(defmethod encode-token "HS256"
  [claims secret _]
  (-> (Algorithm/HMAC256 secret)
      (encode-token* claims)))

(defmethod encode-token "RS256"
  [claims private-key _]
  (-> (Algorithm/RSA256 private-key)
      (encode-token* claims)))


(defn- decode-token*
  [algorithm token]
  (-> algorithm
      (JWT/require)
      (.build)
      (.verify token)
      (.getPayload)
      (base64->map)))

(defmulti decode-token
          "Decodes and verifies the signature of the given JWT token. The decoded claims from the token are returned."
          (fn [token & _] (-> token
                              (clojure.string/split #"\.")
                              first
                              base64->map
                              :alg)))
(defmethod decode-token nil
  [& _]
  (throw (JWTDecodeException. "Could not parse algorithm.")))

(defmethod decode-token "HS256"
  [token secret]
  (let [algorithm (Algorithm/HMAC256 secret)]
    (decode-token* algorithm token)))

(defmethod decode-token "RS256"
  [token public-key]
  (let [algorithm (Algorithm/RSA256 public-key)]
    (decode-token* algorithm token)))
