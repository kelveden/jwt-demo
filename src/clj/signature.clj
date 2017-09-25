(ns signature
  (:require [conversion :refer [base64->str]]
            [pandect.algo.sha256 :as sha256]))

(defmulti create-signature (fn [alg & _] alg))
(defmethod create-signature "HS256"
  [_ header payload secret]
  (-> (str header payload)
      (sha256/sha256-hmac secret)))

(defmethod create-signature "RS256"
  [_ header payload secret]
  (-> (str header payload)
      (sha256/sha256-rsa secret)))

(defmulti verify-signature (fn [alg & _] alg))
(defmethod verify-signature "HS256"
  [_ {:keys [header payload signature]} secret]
  (-> (str header payload)
      (sha256/sha256-hmac secret)
      (= (base64->str signature))))

(defmethod verify-signature "RS256"
  [_ {:keys [header payload signature]} public-key]
  (-> (str header payload)
      (sha256/sha256-rsa-verify (base64->str signature) public-key)))
