(ns jwt-shared-secret
  (:require [jwt-common :refer :all]
            [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.walk :refer [keywordize-keys]]))

(defn sign-shared-secret
  "Creates a JWS flavoured JSON web token."
  [claims secret]
  {:pre [(map? claims) (string? secret)]}

  (let [header (-> {:alg "HS256"}
                   (json/generate-string)
                   (str->base64))
        payload (-> claims
                    (json/generate-string)
                    (str->base64))
        signature (-> (create-signature header payload secret)
                      (str->base64))]
    (str header "." payload "." signature)))

(defn unsign-shared-secret
  "Unpacks the payload from a JWS flavoured JSON web token including verifying that the signature is valid."
  [token secret]
  {:pre [(string? token)]}
  (let [[header payload signature] (split token #"\.")
        token-map {:header header :payload payload :signature signature}]
    (if (and (header-keys-valid? header)
             (not (token-corrupted? token-map secret)))
      (-> payload
          (base64->str)
          (json/parse-string)
          (keywordize-keys))
      (throw (ex-info "Token has been tampered with." {})))))

