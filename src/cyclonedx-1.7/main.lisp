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
                #:licence-id-type
                #:external-reference-type
                #:severity-type
                #:score-method-type
                #:impact-analysis-state
                #:impact-analysis-justification)
  (:export #:all-components
           #:find-component
           #:dependencies-of
           #:dependents-of
           #:relationships-of
           #:root-p
           #:leaf-p
           #:isolated-p
           #:build-sbom
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
           #:build-external-reference
           #:build-external-references
           #:build-dependency
           #:build-dependencies
           #:build-service
           #:build-services
           #:build-vulnerability
           #:build-vulnerabilities
           #:build-vulnerability-source
           #:build-vulnerability-reference
           #:build-vulnerability-rating
           #:build-vulnerability-advisory
           #:build-vulnerability-analysis
           #:build-vulnerability-target
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
           #:acknowledge
           #:component
           #:external-reference
           #:dependency
           #:service
           #:vulnerability
           #:vulnerability-source
           #:vulnerability-reference
           #:vulnerability-rating
           #:vulnerability-advisory
           #:vulnerability-analysis
           #:vulnerability-target
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
           #:external-references
           #:dependencies
           #:vulnerabilities
           #:reference-type
           #:comment
           #:ref
           #:depends-on
           #:provides
           #:provider
           #:endpoints
           #:authenticated
           #:x-trust-boundary
           #:trust-zone
           #:score
           #:severity
           #:score-method
           #:score-vector
           #:justification
           #:title
           #:state
           #:response
           #:detail
           #:first-issued
           #:last-updated
           #:created
           #:published
           #:updated
           #:rejected
           #:recommendation
           #:workaround
           #:cwes
           #:ratings
           #:advisories
           #:analysis
           #:affects
           #:references
           #:versions
           #:source
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

(defclass external-reference (has-properties)
  ((url :initarg :url :initform (error "url is required") :accessor url :type string)
   (reference-type :initarg :type :initform (error "type is required") :accessor reference-type :type (or external-reference-type string))
   (comment :initarg :comment :initform "" :accessor comment :type string)
   (hashes :initarg :hashes :initform #() :accessor hashes :type (vector hash))))

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
   (external-references :initarg :external-references :initform #() :accessor external-references :type (vector external-reference))
   (components :initarg :components :initform #() :accessor components :type (vector component))))

(defclass dependency ()
  ((ref :initarg :ref :initform (error "ref is required") :accessor ref :type string)
   (depends-on :initarg :depends-on :initform #() :accessor depends-on :type (vector string))
   (provides :initarg :provides :initform #() :accessor provides :type (vector string))))

(defclass service (has-bom-ref has-properties)
  ((provider :initarg :provider :initform nil :accessor provider :type (or null organizational-entity))
   (group :initarg :group :initform "" :accessor group :type string)
   (name :initarg :name :initform (error "name is required") :accessor name :type string)
   (version :initarg :version :initform "" :accessor version :type string)
   (description :initarg :description :initform "" :accessor description :type string)
   (endpoints :initarg :endpoints :initform #() :accessor endpoints :type (vector string))
   (authenticated :initarg :authenticated :initform nil :accessor authenticated :type (or null boolean))
   (x-trust-boundary :initarg :x-trust-boundary :initform nil :accessor x-trust-boundary :type (or null boolean))
   (trust-zone :initarg :trust-zone :initform "" :accessor trust-zone :type string)
   (licenses :initarg :licenses :initform #() :accessor licenses :type (vector (or license license-expression)))
   (external-references :initarg :external-references :initform #() :accessor external-references :type (vector external-reference))
   (services :initarg :services :initform #() :accessor services :type (vector service))))

(defclass vulnerability-source ()
  ((name :initarg :name :initform "" :accessor name :type string)
   (url :initarg :url :initform "" :accessor url :type string)))

(defclass vulnerability-reference ()
  ((id :initarg :id :initform "" :accessor id :type string)
   (source :initarg :source :initform nil :accessor source :type (or null vulnerability-source))))

(defclass vulnerability-rating ()
  ((source :initarg :source :initform nil :accessor source :type (or null vulnerability-source))
   (score :initarg :score :initform nil :accessor score :type (or null number))
   (severity :initarg :severity :initform nil :accessor severity :type (or null severity-type string))
   (score-method :initarg :method :initform nil :accessor score-method :type (or null score-method-type string))
   (score-vector :initarg :vector :initform "" :accessor score-vector :type string)
   (justification :initarg :justification :initform "" :accessor justification :type string)))

(defclass vulnerability-advisory ()
  ((title :initarg :title :initform "" :accessor title :type string)
   (url :initarg :url :initform "" :accessor url :type string)))

(defclass vulnerability-analysis ()
  ((state :initarg :state :initform nil :accessor state :type (or null impact-analysis-state string))
   (justification :initarg :justification :initform nil :accessor justification :type (or null impact-analysis-justification string))
   (response :initarg :response :initform #() :accessor response :type (vector string))
   (detail :initarg :detail :initform "" :accessor detail :type string)
   (first-issued :initarg :first-issued :initform "" :accessor first-issued :type string)
   (last-updated :initarg :last-updated :initform "" :accessor last-updated :type string)))

(defclass vulnerability-target ()
  ((ref :initarg :ref :initform (error "ref is required") :accessor ref :type string)
   (versions :initarg :versions :initform #() :accessor versions :type vector)))

(defclass vulnerability (has-bom-ref has-properties)
  ((id :initarg :id :initform "" :accessor id :type string)
   (source :initarg :source :initform nil :accessor source :type (or null vulnerability-source))
   (references :initarg :references :initform #() :accessor references :type (vector vulnerability-reference))
   (ratings :initarg :ratings :initform #() :accessor ratings :type (vector vulnerability-rating))
   (cwes :initarg :cwes :initform #() :accessor cwes :type (vector integer))
   (description :initarg :description :initform "" :accessor description :type string)
   (detail :initarg :detail :initform "" :accessor detail :type string)
   (recommendation :initarg :recommendation :initform "" :accessor recommendation :type string)
   (workaround :initarg :workaround :initform "" :accessor workaround :type string)
   (advisories :initarg :advisories :initform #() :accessor advisories :type (vector vulnerability-advisory))
   (created :initarg :created :initform "" :accessor created :type string)
   (published :initarg :published :initform "" :accessor published :type string)
   (updated :initarg :updated :initform "" :accessor updated :type string)
   (rejected :initarg :rejected :initform "" :accessor rejected :type string)
   (analysis :initarg :analysis :initform nil :accessor analysis :type (or null vulnerability-analysis))
   (affects :initarg :affects :initform #() :accessor affects :type (vector vulnerability-target))))

(defclass tools ()
  ((components :initarg :components :initform #() :accessor components :type (vector component))
   (services   :initarg :services   :initform #() :accessor services   :type (vector service))))

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
   (components :initarg :components :initform #() :accessor components :type (vector component))
   (services :initarg :services :initform #() :accessor services :type (vector service))
   (external-references :initarg :external-references :initform #() :accessor external-references :type (vector external-reference))
   (dependencies :initarg :dependencies :initform #() :accessor dependencies :type (vector dependency))
   (vulnerabilities :initarg :vulnerabilities :initform #() :accessor vulnerabilities :type (vector vulnerability))
   (%component-index :initform nil :accessor %component-index)
   (%dependency-index :initform nil :accessor %dependency-index)
   (%dependents-index :initform nil :accessor %dependents-index)))

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
  (print-unreadable-object (obj stream :type t :identity nil)
    (format stream "Schema: ~A, Bom Version: ~A, Spec Version: ~A, Serial Number: ~A, Version: ~A"
            (schema obj)
            (bom-format obj)
            (spec-version obj)
            (serial-number obj)
            (version obj))))

(defmethod describe-object ((obj sbom) stream)
  (format stream "~&CycloneDX SBOM (~A v~A)~%" (bom-format obj) (spec-version obj))
  (format stream "  Serial Number:   ~A~%" (serial-number obj))
  (format stream "  Version:         ~D~%" (version obj))
  (when (metadata obj)
    (format stream "  Timestamp:       ~A~%" (timestamp (metadata obj))))
  (format stream "  Components:      ~D~%" (length (components obj)))
  (format stream "  Dependencies:    ~D entries~%" (length (dependencies obj)))
  (format stream "  Services:        ~D~%" (length (services obj)))
  (format stream "  Vulnerabilities: ~D~%" (length (vulnerabilities obj))))

(defmethod print-object ((obj component) stream)
  (print-unreadable-object (obj stream :type t :identity nil)
    (let ((name (if (slot-boundp obj 'name) (name obj) ""))
          (ver (if (slot-boundp obj 'version) (version obj) ""))
          (type (if (slot-boundp obj 'component-type) (component-type obj) "")))
      (if (and ver (plusp (length ver)))
          (format stream "Name: ~A, Version: ~A, Type: ~A" name ver type)
          (format stream "Name: ~A, Type: ~A" name type)))))

(defmethod describe-object ((obj component) stream)
  (format stream "~&Component: ~A~@[@~A~] (~A)~%"
          (name obj)
          (when (plusp (length (version obj))) (version obj))
          (component-type obj))
  (when (plusp (length (group obj)))
    (format stream "  Group:       ~A~%" (group obj)))

  (when (plusp (length (bom-ref obj)))
    (format stream "  BOM-Ref:     ~A~%" (bom-ref obj)))

  (when (plusp (length (purl obj)))
    (format stream "  PURL:        ~A~%" (purl obj)))

  (when (plusp (length (cpe obj)))
    (format stream "  CPE:         ~A~%" (cpe obj)))

  (when (scope obj)
    (format stream "  Scope:       ~A~%" (scope obj)))

  (when (plusp (length (description obj)))
    (format stream "  Description: ~A~%" (description obj)))

  (when (plusp (length (licenses obj)))
    (format stream "  Licenses:    ~{~A~^, ~}~%"
            (map 'list (lambda (lic)
                         (cond
                           ((typep lic 'license)
                            (or (id lic) (name lic) "unknown"))
                           ((typep lic 'license-expression)
                            (expression lic))
                           (t "unknown")))
                 (licenses obj))))

  (when (plusp (length (components obj)))
    (format stream "  Subcomponents: ~D~%" (length (components obj))))

  (when (plusp (length (properties obj)))
    (format stream "  Properties:  ~D~%" (length (properties obj)))))

(defmethod print-object ((obj dependency) stream)
  (print-unreadable-object (obj stream :type t :identity nil)
    (format stream "Ref: ~A, Depends-On: ~D, Provides: ~D"
            (if (slot-boundp obj 'ref) (ref obj) "")
            (if (slot-boundp obj 'depends-on) (length (depends-on obj)) 0)
            (if (slot-boundp obj 'provides) (length (provides obj)) 0))))

(defun all-components (sbom)
  "Returns a flat list of all components in SBOM, including root metadata component, tool components, and recursively nested sub-components."
  (let ((result nil)
        (visited (make-hash-table :test 'eq)))
    (labels ((collect (comp)
               (when (and comp (not (gethash comp visited)))
                 (setf (gethash comp visited) t)
                 (push comp result)
                 (when (and (slot-boundp comp 'components)
                            (plusp (length (components comp))))
                   (loop for sub across (components comp)
                         do (collect sub))))))
      ;; 1. Root component in metadata
      (let ((meta (metadata sbom)))
        (when meta
          (when (and (slot-boundp meta 'component) (component meta))
            (collect (component meta)))
          (when (and (slot-boundp meta 'tools) (tools meta))
            (let ((t-inst (tools meta)))
              (when (slot-boundp t-inst 'components)
                (loop for tc across (components t-inst)
                      do (collect tc)))))))
      ;; 2. Top-level components and nested sub-components
      (when (slot-boundp sbom 'components)
        (loop for c across (components sbom)
              do (collect c))))
    (nreverse result)))

(defun ensure-component-index (sbom)
  "Ensures and returns the cached hash table mapping bom-ref to component for SBOM."
  (or (%component-index sbom)
      (let ((table (make-hash-table :test 'equal)))
        (dolist (c (all-components sbom))
          (when (and (slot-boundp c 'bom-ref)
                     (plusp (length (bom-ref c))))
            (setf (gethash (bom-ref c) table) c)))
        (setf (%component-index sbom) table))))

(defun find-component (sbom target &key (key #'bom-ref) (test #'string=))
  "Finds components in SBOM matching TARGET according to KEY and TEST.
Returns:
  1. The primary (first) matching COMPONENT, or NIL if none found.
  2. A list of any additional matching COMPONENT instances (or NIL if unique/none).
  3. The total count of matching components."
  (if (and (eq key #'bom-ref) (eq test #'string=))
      (let* ((index (ensure-component-index sbom))
             (match (gethash target index)))
        (if match
            (values match nil 1)
            (values nil nil 0)))
      (let ((matches nil))
        (dolist (comp (all-components sbom))
          (let ((val (funcall key comp)))
            (when (funcall test target val)
              (push comp matches))))
        (let ((ordered (nreverse matches)))
          (if ordered
              (values (first ordered) (rest ordered) (length ordered))
              (values nil nil 0))))))

(defun ensure-dependency-index (sbom)
  "Ensures and returns the cached hash table mapping ref string to dependency object for SBOM."
  (or (%dependency-index sbom)
      (let ((table (make-hash-table :test 'equal)))
        (when (slot-boundp sbom 'dependencies)
          (loop for dep across (dependencies sbom)
                when (and (slot-boundp dep 'ref) (ref dep))
                do (setf (gethash (ref dep) table) dep)))
        (setf (%dependency-index sbom) table))))

(defun dependencies-of (sbom comp-or-ref &key transitive)
  "Returns a list of components that COMP-OR-REF depends on in SBOM.
COMP-OR-REF can be a COMPONENT instance or a bom-ref string.
If TRANSITIVE is T, transitively resolves dependencies via breadth-first search.
If a dependency ref is not present as a component in SBOM, the bom-ref string is returned."
  (when (null comp-or-ref)
    (return-from dependencies-of nil))
  (let ((target-ref (etypecase comp-or-ref
                      (string comp-or-ref)
                      (has-bom-ref (if (slot-boundp comp-or-ref 'bom-ref)
                                       (bom-ref comp-or-ref)
                                       "")))))
    (when (or (null target-ref) (zerop (length target-ref)))
      (return-from dependencies-of nil))
    (let ((dep-index (ensure-dependency-index sbom)))
      (if (not transitive)
          ;; Direct dependencies
          (let ((dep-entry (gethash target-ref dep-index)))
            (when (and dep-entry
                       (slot-boundp dep-entry 'depends-on)
                       (vectorp (depends-on dep-entry)))
              (let ((visited (make-hash-table :test 'equal))
                    (result nil))
                (loop for ref across (depends-on dep-entry)
                      unless (gethash ref visited)
                        do (setf (gethash ref visited) t)
                           (push (or (find-component sbom ref) ref) result))
                (nreverse result))))
          ;; Transitive dependencies (breadth-first search)
          (let* ((visited (make-hash-table :test 'equal))
                 (result nil)
                 (queue (list target-ref))
                 (queue-tail queue))
            (setf (gethash target-ref visited) t)
            (loop while queue
                  for current-ref = (pop queue)
                  for dep-entry = (gethash current-ref dep-index)
                  when (and dep-entry
                             (slot-boundp dep-entry 'depends-on)
                             (vectorp (depends-on dep-entry)))
                    do (loop for dep-ref across (depends-on dep-entry)
                             unless (gethash dep-ref visited)
                               do (setf (gethash dep-ref visited) t)
                                  (push (or (find-component sbom dep-ref) dep-ref) result)
                                  (let ((new-node (list dep-ref)))
                                    (if queue
                                        (setf (cdr queue-tail) new-node
                                              queue-tail new-node)
                                        (setf queue new-node
                                              queue-tail new-node)))))
            (nreverse result))))))

(defun ensure-dependents-index (sbom)
  "Ensures and returns the cached hash table mapping ref string to a list of refs that depend on it for SBOM."
  (or (%dependents-index sbom)
      (let ((table (make-hash-table :test 'equal)))
        (when (slot-boundp sbom 'dependencies)
          (loop for dep across (dependencies sbom)
                when (and (slot-boundp dep 'ref)
                          (ref dep)
                          (slot-boundp dep 'depends-on)
                          (vectorp (depends-on dep)))
                do (let ((parent-ref (ref dep))
                         (seen-in-dep (make-hash-table :test 'equal)))
                     (loop for child-ref across (depends-on dep)
                           unless (gethash child-ref seen-in-dep)
                             do (setf (gethash child-ref seen-in-dep) t)
                                (push parent-ref (gethash child-ref table nil))))))
        (setf (%dependents-index sbom) table))))

(defun dependents-of (sbom comp-or-ref &key transitive)
  "Returns a list of components that depend on COMP-OR-REF in SBOM (reverse dependencies / blast radius).
COMP-OR-REF can be a COMPONENT instance or a bom-ref string.
If TRANSITIVE is T, transitively resolves all upstream dependents via breadth-first search.
If a dependent ref is not present as a component in SBOM, the bom-ref string is returned."
  (when (null comp-or-ref)
    (return-from dependents-of nil))
  (let ((target-ref (etypecase comp-or-ref
                      (string comp-or-ref)
                      (has-bom-ref (if (slot-boundp comp-or-ref 'bom-ref)
                                       (bom-ref comp-or-ref)
                                       "")))))
    (when (or (null target-ref) (zerop (length target-ref)))
      (return-from dependents-of nil))
    (let ((rev-index (ensure-dependents-index sbom)))
      (if (not transitive)
          ;; Direct dependents
          (let ((parent-refs (gethash target-ref rev-index)))
            (when parent-refs
              (let ((visited (make-hash-table :test 'equal))
                    (result nil))
                (dolist (ref parent-refs)
                  (unless (gethash ref visited)
                    (setf (gethash ref visited) t)
                    (push (or (find-component sbom ref) ref) result)))
                (nreverse result))))
          ;; Transitive dependents (breadth-first search)
          (let* ((visited (make-hash-table :test 'equal))
                 (result nil)
                 (queue (list target-ref))
                 (queue-tail queue))
            (setf (gethash target-ref visited) t)
            (loop while queue
                  for current-ref = (pop queue)
                  for parent-refs = (gethash current-ref rev-index)
                  do (dolist (parent-ref parent-refs)
                       (unless (gethash parent-ref visited)
                         (setf (gethash parent-ref visited) t)
                         (push (or (find-component sbom parent-ref) parent-ref) result)
                         (let ((new-node (list parent-ref)))
                           (if queue
                               (setf (cdr queue-tail) new-node
                                     queue-tail new-node)
                               (setf queue new-node
                                     queue-tail new-node))))))
            (nreverse result))))))

(defun relationships-of (sbom comp-or-ref &key transitive)
  "Returns the dependencies (outgoing) and dependents (incoming) of COMP-OR-REF in SBOM.
Returns multiple values:
  1. The list of dependencies (what COMP-OR-REF depends on).
  2. The list of dependents (what depends on COMP-OR-REF).
If TRANSITIVE is T, recursively resolves both downstream dependencies and upstream dependents."
  (if (null comp-or-ref)
      (values nil nil)
      (values (dependencies-of sbom comp-or-ref :transitive transitive)
              (dependents-of sbom comp-or-ref :transitive transitive))))

(defun %has-dependencies-p (sbom target-ref)
  "Returns T if TARGET-REF has at least one dependency in SBOM."
  (when (and target-ref (plusp (length target-ref)))
    (let* ((dep-index (ensure-dependency-index sbom))
           (dep-entry (gethash target-ref dep-index)))
      (and dep-entry
           (slot-boundp dep-entry 'depends-on)
           (vectorp (depends-on dep-entry))
           (plusp (length (depends-on dep-entry)))))))

(defun %has-dependents-p (sbom target-ref)
  "Returns T if TARGET-REF is depended on by at least one component in SBOM."
  (when (and target-ref (plusp (length target-ref)))
    (let* ((rev-index (ensure-dependents-index sbom))
           (parents (gethash target-ref rev-index)))
      (and parents (plusp (length parents))))))

(defun root-p (sbom comp-or-ref)
  "Returns T if COMP-OR-REF is a root component in SBOM (has dependencies, but no dependents)."
  (when comp-or-ref
    (let ((target-ref (etypecase comp-or-ref
                        (string comp-or-ref)
                        (has-bom-ref (if (slot-boundp comp-or-ref 'bom-ref)
                                         (bom-ref comp-or-ref)
                                         "")))))
      (and (plusp (length target-ref))
           (%has-dependencies-p sbom target-ref)
           (not (%has-dependents-p sbom target-ref))))))

(defun leaf-p (sbom comp-or-ref)
  "Returns T if COMP-OR-REF is a leaf component in SBOM (is depended upon, but has no dependencies)."
  (when comp-or-ref
    (let ((target-ref (etypecase comp-or-ref
                        (string comp-or-ref)
                        (has-bom-ref (if (slot-boundp comp-or-ref 'bom-ref)
                                         (bom-ref comp-or-ref)
                                         "")))))
      (and (plusp (length target-ref))
           (%has-dependents-p sbom target-ref)
           (not (%has-dependencies-p sbom target-ref))))))

(defun isolated-p (sbom comp-or-ref)
  "Returns T if COMP-OR-REF is an isolated component in SBOM (has neither dependencies nor dependents)."
  (when comp-or-ref
    (let ((comp (if (stringp comp-or-ref)
                    (find-component sbom comp-or-ref)
                    comp-or-ref)))
      (when comp
        (let ((target-ref (if (slot-boundp comp 'bom-ref)
                              (bom-ref comp)
                              "")))
          (and (not (%has-dependencies-p sbom target-ref))
               (not (%has-dependents-p sbom target-ref))))))))

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

(defun build-external-reference (data)
  (let* ((type-str (gethash "type" data))
         (kw (when type-str (to-keyword type-str)))
         (ref-type (if (and kw (typep kw 'external-reference-type)) kw type-str)))
    (make-instance 'external-reference
                   :url (gethash "url" data)
                   :type ref-type
                   :comment (gethash "comment" data "")
                   :hashes (build-hashes (gethash "hashes" data #()))
                   :properties (build-properties (gethash "properties" data #())))))

(defun build-external-references (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-external-reference vec)))

(defun build-dependency (data)
  (make-instance 'dependency
                 :ref (gethash "ref" data)
                 :depends-on (gethash "dependsOn" data #())
                 :provides (gethash "provides" data #())))

(defun build-dependencies (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-dependency vec)))

(defun build-service (data)
  (make-instance 'service
                 :bom-ref (gethash "bom-ref" data "")
                 :provider (when (gethash "provider" data)
                             (build-entity (gethash "provider" data)))
                 :group (gethash "group" data "")
                 :name (gethash "name" data)
                 :version (gethash "version" data "")
                 :description (gethash "description" data "")
                 :endpoints (gethash "endpoints" data #())
                 :authenticated (gethash "authenticated" data nil)
                 :x-trust-boundary (gethash "x-trust-boundary" data nil)
                 :trust-zone (gethash "trustZone" data "")
                 :licenses (build-licenses (gethash "licenses" data #()))
                 :external-references (build-external-references (gethash "externalReferences" data #()))
                 :services (build-services (gethash "services" data #()))
                 :properties (build-properties (gethash "properties" data #()))))

(defun build-services (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-service vec)))

(defun build-vulnerability-source (data)
  (when data
    (make-instance 'vulnerability-source
                   :name (gethash "name" data "")
                   :url (gethash "url" data ""))))

(defun build-vulnerability-reference (data)
  (make-instance 'vulnerability-reference
                 :id (gethash "id" data "")
                 :source (build-vulnerability-source (gethash "source" data))))

(defun build-vulnerability-rating (data)
  (let* ((sev-str (gethash "severity" data))
         (sev-kw (when sev-str (to-keyword sev-str)))
         (sev-val (if (and sev-kw (typep sev-kw 'severity-type)) sev-kw sev-str))
         (m-str (gethash "method" data))
         (m-kw (when m-str (to-keyword m-str)))
         (m-val (if (and m-kw (typep m-kw 'score-method-type)) m-kw m-str)))
    (make-instance 'vulnerability-rating
                   :source (build-vulnerability-source (gethash "source" data))
                   :score (gethash "score" data nil)
                   :severity sev-val
                   :method m-val
                   :vector (gethash "vector" data "")
                   :justification (gethash "justification" data ""))))

(defun build-vulnerability-advisory (data)
  (make-instance 'vulnerability-advisory
                 :title (gethash "title" data "")
                 :url (gethash "url" data "")))

(defun build-vulnerability-analysis (data)
  (when data
    (let* ((s-str (gethash "state" data))
           (s-kw (when s-str (to-keyword s-str)))
           (s-val (if (and s-kw (typep s-kw 'impact-analysis-state)) s-kw s-str))
           (j-str (gethash "justification" data))
           (j-kw (when j-str (to-keyword j-str)))
           (j-val (if (and j-kw (typep j-kw 'impact-analysis-justification)) j-kw j-str)))
      (make-instance 'vulnerability-analysis
                     :state s-val
                     :justification j-val
                     :response (gethash "response" data #())
                     :detail (gethash "detail" data "")
                     :first-issued (gethash "firstIssued" data "")
                     :last-updated (gethash "lastUpdated" data "")))))

(defun build-vulnerability-target (data)
  (make-instance 'vulnerability-target
                 :ref (gethash "ref" data)
                 :versions (gethash "versions" data #())))

(defun build-vulnerability (data)
  (make-instance 'vulnerability
                 :bom-ref (gethash "bom-ref" data "")
                 :id (gethash "id" data "")
                 :source (build-vulnerability-source (gethash "source" data))
                 :references (if (gethash "references" data)
                                 (map 'vector #'build-vulnerability-reference (gethash "references" data))
                                 #())
                 :ratings (if (gethash "ratings" data)
                              (map 'vector #'build-vulnerability-rating (gethash "ratings" data))
                              #())
                 :cwes (gethash "cwes" data #())
                 :description (gethash "description" data "")
                 :detail (gethash "detail" data "")
                 :recommendation (gethash "recommendation" data "")
                 :workaround (gethash "workaround" data "")
                 :advisories (if (gethash "advisories" data)
                                 (map 'vector #'build-vulnerability-advisory (gethash "advisories" data))
                                 #())
                 :created (gethash "created" data "")
                 :published (gethash "published" data "")
                 :updated (gethash "updated" data "")
                 :rejected (gethash "rejected" data "")
                 :analysis (build-vulnerability-analysis (gethash "analysis" data))
                 :affects (if (gethash "affects" data)
                              (map 'vector #'build-vulnerability-target (gethash "affects" data))
                              #())
                 :properties (build-properties (gethash "properties" data #()))))

(defun build-vulnerabilities (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-vulnerability vec)))

(defun build-component (data)
  (let* ((ctype (to-keyword (gethash "type" data)))
         (scope-str (gethash "scope" data))
         (scope-val (if scope-str (to-keyword scope-str) nil))
         (comp (make-instance 'component
                              :type ctype
                              :name (gethash "name" data))))
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
    (setf (external-references comp) (build-external-references (gethash "externalReferences" data #())))
    (setf (properties comp) (build-properties (gethash "properties" data #())))
    (setf (components comp) (build-components (gethash "components" data #())))
    comp))

(defun build-components (vec)
  (if (or (null vec) (zerop (length vec)))
      #()
      (map 'vector #'build-component vec)))

(defun build-tools (data)
  (when data
    (make-instance 'tools
                   :components (build-components (gethash "components" data #()))
                   :services (build-services (gethash "services" data #())))))

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
      (setf (services obj) (build-services (gethash "services" sbom #())))
      (setf (external-references obj) (build-external-references (gethash "externalReferences" sbom #())))
      (setf (dependencies obj) (build-dependencies (gethash "dependencies" sbom #())))
      (setf (vulnerabilities obj) (build-vulnerabilities (gethash "vulnerabilities" sbom #())))
      obj)))
