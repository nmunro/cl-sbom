(defpackage cl-sbom/cyclonedx-1.7
  (:use :cl)
  (:import-from :alexandria
                #:make-keyword)
  (:import-from :cl-sbom/cyclonedx-1.7/enums
                #:bom-format-type
                #:component-type
                #:scope-type
                #:algorithm-type
                #:acknowledgement-type
                #:encoding-type
                #:license-type
                #:licence-id-type)
  (:export #:build-sbom
           #:build-metadata
           #:build-tools
           #:build-component
           #:build-components
           #:build-property
           #:build-properties
           #:build-hash
           #:build-hashes
           #:build-address
           #:build-contact
           #:build-contacts
           #:build-entity
           #:build-attachment
           #:build-licensing
           #:build-license
           #:build-licenses
           #:build-expression
           #:sbom
           #:sbom-metadata
           #:tools
           #:tool-components
           #:tool-services
           #:components
           #:services
           #:has-bom-ref
           #:bom-ref
           #:has-properties
           #:properties
           #:address
           #:organizational-contact
           #:organizational-entity
           #:hash
           #:property
           #:attachment
           #:licensing
           #:license
           #:expression
           #:license-expression
           #:component
           #:schema
           #:bom-format
           #:spec-version
           #:serial-number
           #:version
           #:metadata
           #:timestamp
           #:author
           #:authors
           #:publisher
           #:group
           #:name
           #:version-range
           #:is-external
           #:description
           #:scope
           #:hashes
           #:copyright
           #:cpe
           #:purl
           #:component
           #:manufacturer
           #:supplier
           #:licenses
           #:country
           #:region
           #:locality
           #:post-office-box-number
           #:postal-code
           #:street-address
           #:email
           #:phone
           #:url
           #:contact
           #:alg
           #:content
           #:value
           #:content-type
           #:encoding
           #:alt-ids
           #:licensor
           #:licensee
           #:purchaser
           #:purchase-order
           #:license-types
           #:last-renewal
           #:expiration
           #:id
           #:acknowledgement
           #:text
           #:expression-details
           #:license-identifier
           #:component-type
           #:mime-type
           #:sbom-error
           #:unsupported-bom-format
           #:unsupported-spec-version))

(in-package :cl-sbom/cyclonedx-1.7)


(define-condition sbom-error (error)
  ()
  (:documentation "Base error condition for cl-sbom."))

(define-condition unsupported-bom-format (sbom-error)
  ((bom-format :initarg :bom-format :initarg :format :reader bom-format))
  (:report (lambda (condition stream)
             (format stream "Unsupported or missing bomFormat: ~S (expected \"CycloneDX\")"
                     (slot-value condition 'bom-format))))
  (:documentation "Signaled when the BOM format is not supported or missing."))

(define-condition unsupported-spec-version (sbom-error)
  ((spec-version :initarg :spec-version :initarg :version :reader spec-version))
  (:report (lambda (condition stream)
             (format stream "Unsupported or missing specVersion: ~S (expected \"1.7\")"
                     (slot-value condition 'spec-version))))
  (:documentation "Signaled when the specification version is not supported or missing."))


(defclass has-bom-ref ()
  ((bom-ref :initarg :bom-ref :initform "" :accessor bom-ref :type string)))

(defclass has-properties ()
  ((properties :initarg :properties :initform #() :accessor properties :type (vector property))))

(defclass address (has-bom-ref)
  ((country :initarg :country :initform "" :accessor country :type string)
   (region :initarg :region :initform "" :accessor region :type string)
   (locality :initarg :locality :initform "" :accessor locality :type string)
   (post-office-box-number :initarg :post-office-box-number :initform "" :accessor post-office-box-number :type string)
   (postal-code :initarg :postal-code :initform "" :accessor postal-code :type string)
   (street-address :initarg :street-address :initform "" :accessor street-address :type string)))

(defclass organizational-contact (has-bom-ref)
  ((name :initarg :name :initform "" :accessor name :type string)
   (email :initarg :email :initform "" :accessor email :type string)
   (phone :initarg :phone :initform "" :accessor phone :type string)))

(defclass organizational-entity (has-bom-ref)
  ((name :initarg :name :initform "" :accessor name :type string)
   (address :initarg :address :initform nil :accessor address :type (or null address))
   (url :initarg :url :initform #() :accessor url :type (vector string))
   (contact :initarg :contact :initform #() :accessor contact :type (vector organizational-contact))))

(defclass hash ()
  ((alg :initarg :alg :initform (error "alg is required") :accessor alg :type algorithm-type)
   (content :initarg :content :initform (error "Content is required") :accessor content :type string)))

(defclass property ()
  ((name :initarg :name :initform (error "Name is required") :accessor name :type string)
   (value :initarg :value :initform "" :accessor value :type string)))

(defclass attachment ()
  ((content-type :initarg :content-type :initform "text/plain" :accessor content-type :type string)
   (encoding :initarg :encoding :initform nil :accessor encoding :type (or null encoding-type string))
   (content :initarg :content :initform (error "Content is required") :accessor content :type string)))

(defclass licensing ()
  ((alt-ids :initarg :alt-ids :initform #() :accessor alt-ids :type (vector string))
   (licensor :initarg :licensor :initform nil :accessor licensor :type (or null organizational-entity organizational-contact))
   (licensee :initarg :licensee :initform nil :accessor licensee :type (or null organizational-entity organizational-contact))
   (purchaser :initarg :purchaser :initform nil :accessor purchaser :type (or null organizational-entity organizational-contact))
   (purchase-order :initarg :purchase-order :initform "" :accessor purchase-order :type string)
   (license-types :initarg :license-types :initform #() :accessor license-types :type (vector license-type))
   (last-renewal :initarg :last-renewal :initform "" :accessor last-renewal :type string)
   (expiration :initarg :expiration :initform "" :accessor expiration :type string)))

(defclass license (has-bom-ref has-properties)
  ((id :initarg :id :initform nil :accessor id :type (or null licence-id-type string))
   (name :initarg :name :initform "" :accessor name :type string)
   (acknowledgement :initarg :acknowledgement :initform nil :accessor acknowledgement :type (or null acknowledgement-type))
   (text :initarg :text :initform nil :accessor text :type (or null attachment))
   (url :initarg :url :initform "" :accessor url :type string)
   (licensing :initarg :licensing :initform nil :accessor licensing :type (or null licensing))))

(defclass expression (has-bom-ref)
  ((license-identifier :initarg :license-identifier :initform (error "License Identifier is required") :accessor license-identifier :type string)
   (text :initarg :text :initform nil :accessor text :type (or null attachment))
   (url :initarg :url :initform "" :accessor url :type string)))

(defclass license-expression (has-bom-ref has-properties)
  ((expression :initarg :expression :initform "" :accessor expression :type string)
   (expression-details :initarg :expression-details :initform #() :accessor expression-details :type (vector expression))
   (acknowledgement :initarg :acknowledgement :initform nil :accessor acknowledgement :type (or null acknowledgement-type))
   (licensing :initarg :licensing :initform nil :accessor licensing :type (or null licensing))))

(defgeneric acknowledge (object)
  (:documentation "Convenience accessor for acknowledgement."))

(defmethod acknowledge ((lic license))
  (acknowledgement lic))

(defmethod acknowledge ((expr license-expression))
  (acknowledgement expr))

(defclass component (has-bom-ref has-properties)
  ((component-type :initarg :type :initform (error "A component-type is required") :accessor component-type :type component-type)
   (mime-type :initarg :mime-type :initform "" :accessor mime-type :type string)
   (supplier :initarg :supplier :initform nil :accessor supplier :type (or null organizational-entity))
   (manufacturer :initarg :manufacturer :initform nil :accessor manufacturer :type (or null organizational-entity))
   (authors :initarg :authors :initform #() :accessor authors :type (vector organizational-contact))
   (author :initarg :author :initform "" :accessor author :type string)
   (publisher :initarg :publisher :initform "" :accessor publisher :type string)
   (group :initarg :group :initform "" :accessor group :type string)
   (name :initarg :name :initform (error "Name is required") :accessor name :type string)
   (version :initarg :version :initform "" :accessor version :type string)
   (version-range :initarg :version-range :initform "" :accessor version-range :type string)
   (is-external :initarg :is-external :initform nil :accessor is-external :type boolean)
   (description :initarg :description :initform "" :accessor description :type string)
   (scope :initarg :scope :initform nil :accessor scope :type (or null scope-type))
   (hashes :initarg :hashes :initform #() :accessor hashes :type (vector hash))
   (licenses :initarg :licenses :initform #() :accessor licenses :type (vector (or license license-expression)))
   (copyright :initarg :copyright :initform "" :accessor copyright :type string)
   (cpe :initarg :cpe :initform "" :accessor cpe :type string)
   (purl :initarg :purl :initform "" :accessor purl :type string)
   (components :initarg :components :initform #() :accessor components :type (vector component))))

(defclass tools ()
  ((components :initarg :components :initform #() :accessor components :type (vector component))
   (services   :initarg :services   :initform #() :accessor services   :type vector)))

(defclass sbom-metadata (has-properties)
  ((timestamp    :initarg :timestamp    :initform ""  :accessor timestamp    :type string)
   (tools        :initarg :tools        :initform nil :accessor tools        :type (or null tools))
   (authors      :initarg :authors      :initform #() :accessor authors      :type (vector organizational-contact))
   (component    :initarg :component    :initform nil :accessor component    :type (or null component))
   (manufacturer :initarg :manufacturer :initform nil :accessor manufacturer :type (or null organizational-entity))
   (supplier     :initarg :supplier     :initform nil :accessor supplier     :type (or null organizational-entity))
   (licenses     :initarg :licenses     :initform #() :accessor licenses     :type (vector (or license license-expression)))))

(defclass sbom ()
  ((schema :initarg :schema :initform "" :accessor schema)
   (bom-format :initarg :bom-format :initform :cyclonedx :accessor bom-format :type bom-format-type)
   (spec-version :initarg :spec-version :initform "" :accessor spec-version :type string)
   (serial-number :initarg :serial-number :initform "" :accessor serial-number :type string)
   (version :initarg :version :initform 1 :accessor version :type integer)
   (metadata :initarg :metadata :initform nil :accessor metadata :type (or null sbom-metadata))
   (components :initarg :components :initform #() :accessor components :type (vector component))))

(defgeneric tool-components (object)
  (:documentation "Returns the vector of tool components from OBJECT (TOOLS, SBOM-METADATA, or SBOM)."))

(defgeneric tool-services (object)
  (:documentation "Returns the vector of tool services from OBJECT (TOOLS, SBOM-METADATA, or SBOM)."))

(defmethod tool-components ((tools tools))
  (components tools))

(defmethod tool-services ((tools tools))
  (services tools))

(defmethod tool-components ((meta sbom-metadata))
  (if (tools meta)
      (tool-components (tools meta))
      #()))

(defmethod tool-services ((meta sbom-metadata))
  (if (tools meta)
      (tool-services (tools meta))
      #()))

(defmethod tool-components ((sbom sbom))
  (if (metadata sbom)
      (tool-components (metadata sbom))
      #()))

(defmethod tool-services ((sbom sbom))
  (if (metadata sbom)
      (tool-services (metadata sbom))
      #()))

(defmethod tool-components ((obj null))
  #())

(defmethod tool-services ((obj null))
  #())

(defmethod print-object ((obj sbom) stream)
  (print-unreadable-object (obj stream :type t :identity t)
    (format stream "Schema: ~A, Bom Version: ~A, Spec Version: ~A, Serial Number: ~A, Version: ~A"
            (schema obj)
            (bom-format obj)
            (spec-version obj)
            (serial-number obj)
            (version obj))))

(defun to-keyword (str)
  (when str
    (make-keyword (string-upcase str))))

(defun build-property (data)
  (make-instance 'property
                 :name (gethash "name" data)
                 :value (gethash "value" data "")))

(defun build-properties (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-property vec)))

(defun build-hash (data)
  (make-instance 'hash
                 :alg (to-keyword (gethash "alg" data))
                 :content (gethash "content" data)))

(defun build-hashes (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-hash vec)))

(defun build-address (data)
  (when data
    (make-instance 'address
                   :bom-ref (gethash "bom-ref" data "")
                   :country (gethash "country" data "")
                   :region (gethash "region" data "")
                   :locality (gethash "locality" data "")
                   :post-office-box-number (gethash "postOfficeBoxNumber" data "")
                   :postal-code (gethash "postalCode" data "")
                   :street-address (gethash "streetAddress" data ""))))

(defun build-contact (data)
  (make-instance 'organizational-contact
                 :bom-ref (gethash "bom-ref" data "")
                 :name (gethash "name" data "")
                 :email (gethash "email" data "")
                 :phone (gethash "phone" data "")))

(defun build-contacts (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-contact vec)))

(defun build-entity (data)
  (when data
    (make-instance 'organizational-entity
                   :bom-ref (gethash "bom-ref" data "")
                   :name (gethash "name" data "")
                   :address (build-address (gethash "address" data))
                   :url (let ((u (gethash "url" data)))
                          (cond ((null u) #())
                                ((stringp u) (vector u))
                                ((vectorp u) u)
                                (t #())))
                   :contact (build-contacts (gethash "contact" data #())))))

(defun build-entity-or-contact (data)
  (when data
    (cond
      ((gethash "organization" data)
       (build-entity (gethash "organization" data)))
      ((gethash "individual" data)
       (build-contact (gethash "individual" data)))
      (t nil))))

(defun build-attachment (data)
  (when data
    (make-instance 'attachment
                   :content-type (gethash "contentType" data "text/plain")
                   :encoding (let ((enc (gethash "encoding" data)))
                               (if enc (to-keyword enc) nil))
                   :content (gethash "content" data))))

(defun build-licensing (data)
  (when data
    (make-instance 'licensing
                   :alt-ids (gethash "altIds" data #())
                   :licensor (build-entity-or-contact (gethash "licensor" data))
                   :licensee (build-entity-or-contact (gethash "licensee" data))
                   :purchaser (build-entity-or-contact (gethash "purchaser" data))
                   :purchase-order (gethash "purchaseOrder" data "")
                   :license-types (map 'vector #'to-keyword (gethash "licenseTypes" data #()))
                   :last-renewal (gethash "lastRenewal" data "")
                   :expiration (gethash "expiration" data ""))))

(defun build-expression (data)
  (make-instance 'expression
                 :bom-ref (gethash "bom-ref" data "")
                 :license-identifier (gethash "licenseIdentifier" data)
                 :text (build-attachment (gethash "text" data))
                 :url (gethash "url" data "")))

(defun build-license (data)
  (when data
    (let* ((id-str (gethash "id" data))
           (id-val (when id-str
                     (let ((kw (to-keyword id-str)))
                       (if (typep kw 'licence-id-type)
                           kw
                           id-str))))
           (ack (gethash "acknowledgement" data)))
      (make-instance 'license
                     :bom-ref (gethash "bom-ref" data "")
                     :id id-val
                     :name (gethash "name" data "")
                     :acknowledgement (if ack (to-keyword ack) nil)
                     :text (build-attachment (gethash "text" data))
                     :url (gethash "url" data "")
                     :licensing (build-licensing (gethash "licensing" data))
                     :properties (build-properties (gethash "properties" data #()))))))

(defun build-license-choice (item)
  (cond
    ((gethash "license" item)
     (build-license (gethash "license" item)))
    ((gethash "expression" item)
     (let ((ack (gethash "acknowledgement" item))
           (expr-details (gethash "expressionDetails" item #())))
       (make-instance 'license-expression
                      :bom-ref (gethash "bom-ref" item "")
                      :expression (gethash "expression" item "")
                      :expression-details (map 'vector #'build-expression expr-details)
                      :acknowledgement (if ack (to-keyword ack) nil)
                      :licensing (build-licensing (gethash "licensing" item))
                      :properties (build-properties (gethash "properties" item #())))))
    (t (error "Unknown license choice structure: ~A" item))))

(defun build-licenses (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-license-choice vec)))

(defun build-components (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-component vec)))

(defun build-component (data)
  (let* ((ctype (to-keyword (gethash "type" data)))
         (scope-str (gethash "scope" data))
         (scope-val (if scope-str (to-keyword scope-str) nil))
         (comp (make-instance 'component :type ctype :name (gethash "name" data))))
    (setf (bom-ref comp) (gethash "bom-ref" data ""))
    (setf (mime-type comp) (gethash "mime-type" data ""))

    (when (gethash "supplier" data)
      (setf (supplier comp) (build-entity (gethash "supplier" data))))

    (when (gethash "manufacturer" data)
      (setf (manufacturer comp) (build-entity (gethash "manufacturer" data))))

    (setf (authors comp) (build-contacts (gethash "authors" data #())))
    (setf (author comp) (gethash "author" data ""))
    (setf (publisher comp) (gethash "publisher" data ""))
    (setf (group comp) (gethash "group" data ""))
    (setf (version comp) (gethash "version" data ""))
    (setf (version-range comp) (gethash "versionRange" data ""))
    (setf (is-external comp) (gethash "isExternal" data nil))
    (setf (description comp) (gethash "description" data ""))
    (setf (scope comp) scope-val)
    (setf (hashes comp) (build-hashes (gethash "hashes" data #())))
    (setf (licenses comp) (build-licenses (gethash "licenses" data #())))
    (setf (copyright comp) (gethash "copyright" data ""))
    (setf (cpe comp) (gethash "cpe" data ""))
    (setf (purl comp) (gethash "purl" data ""))
    (setf (properties comp) (build-properties (gethash "properties" data #())))
    (setf (components comp) (build-components (gethash "components" data #())))
    comp))


(defun build-tools (data)
  (when data
    (make-instance 'tools
                   :components (build-components (gethash "components" data #()))
                   :services (gethash "services" data #()))))

(defun build-metadata (data)
  (when data
    (let ((meta (make-instance 'sbom-metadata)))
      (setf (timestamp meta) (gethash "timestamp" data ""))
      (setf (tools meta) (build-tools (gethash "tools" data)))
      (setf (authors meta) (build-contacts (gethash "authors" data #())))

      (when (gethash "component" data)
        (setf (component meta) (build-component (gethash "component" data))))

      (let ((mfg (or (gethash "manufacturer" data) (gethash "manufacture" data))))
        (when mfg
          (setf (manufacturer meta) (build-entity mfg))))

      (when (gethash "supplier" data)
        (setf (supplier meta) (build-entity (gethash "supplier" data))))

      (setf (licenses meta) (build-licenses (gethash "licenses" data #())))
      (setf (properties meta) (build-properties (gethash "properties" data #())))
      meta)))

(defun build-sbom (sbom)
  (let ((fmt (gethash "bomFormat" sbom))
        (spec (gethash "specVersion" sbom)))
    (unless (and (stringp fmt) (string= fmt "CycloneDX"))
      (error 'unsupported-bom-format :format fmt))
    (unless (and (stringp spec) (string= spec "1.7"))
      (error 'unsupported-spec-version :spec-version spec))
    (let ((obj (make-instance 'sbom)))
      (setf (schema obj) (gethash "$schema" sbom ""))
      (setf (bom-format obj) :CycloneDX)
      (setf (spec-version obj) spec)
      (setf (serial-number obj) (gethash "serialNumber" sbom ""))
      (setf (version obj) (gethash "version" sbom 1))
      (setf (metadata obj) (build-metadata (gethash "metadata" sbom)))
      (setf (components obj) (build-components (gethash "components" sbom #())))
      obj)))
