(defpackage cl-sbom/cyclonedx-1.7
  (:use :cl)
  (:import-from :cl-sbom/cyclonedx-1.7/enums
                #:component-type
                #:scope-type
                #:algorithm-type
                #:acknowledgement-type
                #:encoding-type
                #:license-type)
  (:export #:build-sbom
           #:build-metadata
           #:sbom
           #:sbom-metadata
           #:address
           #:contact
           #:supplier
           #:manufacturer
           #:author
           #:hash
           #:component))

(in-package :cl-sbom/cyclonedx-1.7)


(defclass sbom-metadata ()
  ())

(defclass sbom ()
  ((schema :initarg :schema :initform "" :accessor schema)
   (bom-format :initarg :bom-format :initform "" :accessor bom-format)
   (spec-version :initarg :spec-version :initform "" :accessor spec-version)
   (serial-number :initarg :serial-number :initform "" :accessor serial-number)
   (version :initarg :version :initform "" :accessor version)))

(defclass address ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (country :initarg :country :initform "" :accessor country :type string)
   (region :initarg :region :initform "" :accessor region :type string)
   (locality :initarg :locality :initform "" :accessor locality :type string)
   (post-office-box-number :initarg :post-office-box-number :initform "" :accessor post-office-box-number :type string)
   (postal-code :initarg :postal-code :initform "" :accessor postal-code :type string)
   (street-address :initarg :street-address :initform "" :accessor street-address :type string)))

(defclass contact ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (name :initarg :name :initform "" :accessor name :type string)
   (email :initarg :email :initform "" :accessor email :type string)
   (phone :initarg :phone :initform "" :accessor phone :type string)))

(defclass supplier ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (name :initarg :name :initform "" :accessor name :type string)
   (address :initarg :address :initform nil :accessor address :type (or null address))
   (url :initarg :url :initform #() :accessor url :type (vector string))
   (contact :initarg :contact :initform nil :accessor contact :type (or null contact))))

(defclass manufacturer ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (name :initarg :name :initform "" :accessor name :type string)
   (address :initarg :address :initform nil :accessor address :type (or null address))
   (url :initarg :url :initform #() :accessor url :type (vector string))
   (contact :initarg :contact :initform nil :accessor contact :type (or null contact))))

(defclass author ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (name :initarg :name :initform "" :accessor name :type string)
   (email :initarg :email :initform "" :accessor email :type string)
   (phone :initarg :phone :initform "" :accessor phone :type string)))

(defclass hash ()
  ((alg :initarg :alg :initform (error "alg is required") :accessor alg :type algorithm-type)
   (content :initarg :content :initform (error "Content is required") :accessor content :type string)))

(defclass property ()
  ((name :initarg :name :initform (error "Name is required") :accessor name :type string)
   (value :initarg :value :initform "" :accessor value :type string)))

(defclass object ()
  ((content-type :initarg :content-type :initform "text/plain" :accessor content-type :type string)
   (encoding :initarg :encoding :initform "" :accessor encoding :type string)
   (content :initarg :content :initform (error "Content is required") :accessor content :type string)))

(defclass individual ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (name :initarg :name :initform "" :accessor name :type string)
   (email :initarg :email :initform "" :accessor email :type string)
   (phone :initarg :phone :initform "" :accessor phone :type string)))

(defclass organization ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (name :initarg :name :initform "" :accessor name :type string)
   (address :initarg :address :initform nil :accessor address :type (or null address))
   (url :initarg :url :initform #() :accessor url :type (vector string))
   (contact :initarg :contact :initform nil :accessor contact :type (or null individual))))

(defclass licensing ()
  ((alt-ids :initarg :alt-ids :initform #() :accessor alt-ids :type (vector string))
   (licensor :initarg :licensor :initform nil :accessor licensor :type (or null organization individual))
   (licensee :initarg :licensee :initform nil :accessor licensee :type (or null organization individual))
   (purchaser :initarg :purchaser :initform nil :accessor purchaser :type (or null organization individual))
   (purchase-order :initarg :purchase-order :initform "" :accessor purchase-order :type string)
   (license-types :initarg :license-types :initform #() :accessor license-types :type (vector license-type))
   (last-renewal :initarg :last-renewal :initform "" :accessor last-renewal :type string)
   (expiration :initarg :expiration :initform "" :accessor expiration :type string)))

;; @TODO: Stopped Here
(defclass license ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (id :initarg :id :initform #() :accessor id :type (vector license-type))))

(defclass expression ()
  ((license-identifier :initarg :license-identifier :initform (error "License Identifier is required") :accessor license-identifier :type string)
   (bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (text :initarg :text :initform nil :accessor text :type (or null object))
   (url :initarg :url :initform "" :accessor url :type string)))

(defclass license-expression ()
  ((expression :initarg :expression :initform "" :accessor expression :type string)
   (expression-details :initarg :expression-details :initform nil :accessor expression-details :type (or null expression))
   (acknowledgement :initarg :acknowledgement :initform nil :accessor acknowledge :type (or null acknowledgement-type))
   (bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (licensing :initarg :licensing :initform nil :accessor licensing :type (or null licensing) )
   (properties :initarg :properties :initform #() :accessor properties :type (vector property))))

(defclass component ()
  ((component-type :initarg :type :initform (error "A component-type is required") :accessor component-type :type component-type)
   (mime-type :initarg :mime-type :initform "" :accessor mime-type :type string)
   (bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)
   (supplier :initarg :supplier :initform nil :accessor supplier :type (or null supplier))
   (manufacturer :initarg :manufacturer :initform nil :accessor manufacturer :type (or null manufacturer))
   (authors :initarg :authors :initform #() :accessor authors :type (vector author))
   (author :initarg :author :initform "" :accessor author :type string)
   (publisher :initarg :publisher :initform "" :accessor publisher :type string)
   (group :initarg :group :initform "" :accessor group :type string)
   (name :initarg :name :initform (error "Name is required") :accessor name :type string)
   (version :initarg :version :initform "" :accessor version :type string)
   (version-range :initarg :version-range :initform "" :accessor version-range :type string)
   (is-external :initarg :is-external :initform nil :accessor is-external :type boolean)
   (description :initarg :description :initform "" :accessor description :type string)
   (scope :initarg :scope :initform nil :accessor scope :type (or null scope-type))
   (hashes :initarg :hashes :initform #() :accessor hashes :type (vector hash))))

(defmethod print-object ((obj sbom) stream)
  (print-unreadable-object (obj stream :type t :identity t)
    (format stream "Schema: ~A, Bom Version: ~A, Spec Version: ~A, Serial Number: ~A, Version: ~A"
          (schema obj)
          (bom-format obj)
          (spec-version obj)
          (serial-number obj)
          (version obj))))

(defun build-sbom (sbom)
  (let ((obj (make-instance 'sbom)))
    (setf (schema obj) (gethash "$schema" sbom))
    (setf (bom-format obj) (gethash "bomFormat" sbom))
    (setf (spec-version obj) (gethash "specVersion" sbom))
    (setf (serial-number obj) (gethash "serialNumber" sbom))
    (setf (version obj) (gethash "version" sbom))
    obj))
