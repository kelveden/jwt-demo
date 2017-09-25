(defproject jwt-demo "0.0.1-SNAPSHOT"
  :description "JWT Demo"
  :dependencies [[pandect "0.6.1"]
                 [cheshire "5.7.1"]
                 [org.clojure/clojure "1.8.0"]]
  :source-paths ["src/clj"]
  :profiles {:dev {:source-paths ["dev/clj"]
                   :repl-options {:init-ns jwt-shared-secret}}})
