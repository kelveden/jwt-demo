(defproject jwt-demo "0.0.1-SNAPSHOT"
  :description "JWT Demo"
  :dependencies [[pandect "0.6.1"]
                 [cheshire "5.8.0"]
                 [commons-codec "1.11"]
                 [org.clojure/clojure "1.9.0"]
                 [com.auth0/java-jwt "3.3.0"]]
  :source-paths ["src/clj"]
  :profiles {:dev {:source-paths ["dev/clj"]
                   :repl-options {:init-ns jwt}}})
