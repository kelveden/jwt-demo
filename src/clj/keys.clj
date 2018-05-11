(ns keys
  (:require [jwt :refer :all]
            [clojure.string :refer [split join]]
            [clojure.walk :refer [keywordize-keys]])
  (:import (java.security KeyPairGenerator)))

(defn generate-key-pair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "RSA")
                    (.initialize 1024))
        key-pair (.generateKeyPair generator)]
    [(.getPrivate key-pair) (.getPublic key-pair)]))
