(ns jwt
  (:require [cheshire.core :as json]
            [clojure.set :refer [superset?]]
            [clojure.string :refer [split join]]
            [clojure.walk :refer [keywordize-keys]]
            [conversion :refer :all]
            [signature :refer :all]))

(defn token-corrupted?
  "Verifies that the specified token has not been corrupted or tampered with by
  by recreating the signature from the given header and payload and comparing with
  the given signature."
  [token-map secret]
  (let [algorithm (-> token-map :header (base64->map) :alg)
        signature-verified? (verify-signature algorithm token-map secret)]
    (not signature-verified?)))

(defn header-keys-valid?
  [header]
  {:pre [(string? header)]}
  (superset? #{:alg :typ}
             (keys (base64->map header))))

(defn sign
  "Creates a JWS flavoured JSON web token."
  [claims secret signing-algorithm]
  {:pre [(map? claims) (string? signing-algorithm)]}

  (let [header (-> {:alg signing-algorithm}
                   (json/generate-string)
                   (str->base64))
        payload (-> claims
                    (json/generate-string)
                    (str->base64))
        signature (-> (create-signature signing-algorithm header payload secret)
                      (str->base64))]
    (str header "." payload "." signature)))

(defn unsign
  "Unpacks the payload from a JWS flavoured JSON web token including verifying that the signature is valid."
  [token secret]
  {:pre [(string? token)]}
  (let [[header payload signature] (split token #"\.")
        token-map {:header header
                   :payload payload
                   :signature signature}]
    (if (and (header-keys-valid? header)
             (not (token-corrupted? token-map secret)))
      (base64->map payload)
      (throw (ex-info "Token has been tampered with." {})))))

