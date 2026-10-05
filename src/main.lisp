(defpackage cl-sbom
  (:use :cl)
  (:import-from :cl-sbom/cyclonedx-1.7
                #:build-sbom
                #:build-metadata)
  (:export #:parse))

(in-package :cl-sbom)

(defun parse (path)
  (let ((data (com.inuoe.jzon:parse (uiop:read-file-string path))))
    (build-sbom data)))
