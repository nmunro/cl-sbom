(defsystem "cl-sbom"
  :version "0.0.1"
  :author "nmunro"
  :license "BSD3-Clause"
  :description "A Common Lisp library for parsing Software Bill of Materials (SBOM) formats."
  :depends-on (:com.inuoe.jzon
               :alexandria)
  :components ((:module "src"
                :serial t
                :components
                ((:module "cyclonedx-1.7"
                  :serial t
                  :components
                  ((:file "enums")
                   (:file "main")))
                 (:file "main"))))
  :in-order-to ((test-op (test-op "cl-sbom/tests"))))

(defsystem "cl-sbom/tests"
  :author "nmunro"
  :license "BSD3-Clause"
  :depends-on ("cl-sbom"
               :rove)
  :components ((:module "tests"
                :components
                ((:file "main"))))
  :description "Test system for cl-sbom"
  :perform (test-op (op c) (symbol-call :rove :run c)))
