# cl-sbom: Comprehensive Documentation & API Reference

`cl-sbom` is a Common Lisp library for parsing, inspecting, querying, and manipulating **Software Bill of Materials (SBOM)** documents. It provides complete, native CLOS (Common Lisp Object System) modeling for the **CycloneDX 1.7 JSON** specification.

---

## Table of Contents

1. [Overview & Scope](#overview--scope)
2. [Installation & Requirements](#installation--requirements)
3. [Quick Start](#quick-start)
4. [Architecture & Design Principles](#architecture--design-principles)
   - [Strict Specification Versioning](#strict-specification-versioning)
   - [CLOS Object Model & Typed Slots](#clos-object-model--typed-slots)
   - [Deduplication Mixins](#deduplication-mixins)
   - [Polymorphic Tool & License Accessors](#polymorphic-tool--license-accessors)
   - [Package Organization](#package-organization)
5. [Error Handling & Conditions](#error-handling--conditions)
6. [API Reference: Package `cl-sbom`](#api-reference-package-cl-sbom)
7. [API Reference: Package `cl-sbom/cyclonedx-1.7`](#api-reference-package-cl-sbomcyclonedx-17)
   - [Root Document Model: `sbom`](#root-document-model-sbom)
   - [Metadata & Tools: `sbom-metadata`, `tools`](#metadata--tools-sbom-metadata-tools)
   - [Components: `component`](#components-component)
   - [Services: `service`](#services-service)
   - [Dependency Graph: `dependency`](#dependency-graph-dependency)
   - [External References: `external-reference`](#external-references-external-reference)
   - [Vulnerabilities & Advisories](#vulnerabilities--advisories)
   - [Licenses & Legal: `license`, `license-expression`](#licenses--legal-license-license-expression)
   - [Common Entities: `property`, `hash`, `attachment`, `organizational-entity`, `organizational-contact`, `address`](#common-entities)
   - [Mixins & Generic Functions](#mixins--generic-functions)
   - [Builders](#builders)
8. [API Reference: Package `cl-sbom/cyclonedx-1.7/enums`](#api-reference-package-cl-sbomcyclonedx-17enums)
9. [Recipes & Common Tasks](#recipes--common-tasks)
   - [Searching Components by Name or PURL](#searching-components-by-name-or-purl)
   - [Traversing the Dependency Graph](#traversing-the-dependency-graph)
   - [Auditing Vulnerabilities & CVSS Ratings](#auditing-vulnerabilities--cvss-ratings)
   - [Extracting Licenses](#extracting-licenses)
   - [Inspecting Microservices](#inspecting-microservices)
10. [Testing & Development](#testing--development)

---

## Overview & Scope

A Software Bill of Materials (SBOM) provides transparency into software supply chains, detailing inventory, open-source dependencies, licenses, security vulnerabilities, and system services.

`cl-sbom` currently implements the **CycloneDX v1.7 JSON** standard.
- **Scope Boundary:** Exclusively CycloneDX 1.7 JSON documents.
- **Validation:** Missing or non-matching `bomFormat` and `specVersion` values are not silently accepted; they raise typed Common Lisp conditions.
- **Idioms:** Bridges standard JSON representations into Common Lisp structures (keywords, CLOS instances, typed vectors, boolean values, and conditions).

---

## Installation & Requirements

### System Requirements
* **Lisp Implementation:** Tested on [SBCL](https://www.sbcl.org/) (macOS / Linux / BSD / Windows).
* **ASDF:** 3.3+.
* **Package Manager:** [Quicklisp](https://www.quicklisp.org/) or [Qlot](https://github.com/fukamachi/qlot).

### Dependencies
* [`com.inuoe.jzon`](https://github.com/Zulu-Inuoe/jzon): High-performance conforming JSON parser.
* [`alexandria`](https://alexandria.common-lisp.dev/): Utility library for keyword manipulation.
* [`rove`](https://github.com/fukamachi/rove): Testing framework (for running test suites).

### Loading the System
Via Quicklisp / ASDF:
```lisp
(asdf:load-system :cl-sbom)
```

With Qlot:
```sh
qlot exec ros run --eval '(asdf:load-system :cl-sbom)'
```

---

## Quick Start

```lisp
(in-package :cl-user)
(use-package :cl-sbom)

;; 1. Parse a CycloneDX 1.7 JSON file
(defparameter *bom* (parse #p"/path/to/sbom.json" :format :cyclonedx-1.7))

;; 2. Inspect root attributes directly via cl-sbom accessors
(format t "Spec: ~A ~A~%" 
        (bom-format *bom*)      ;; :CycloneDX
        (spec-version *bom*))    ;; "1.7"

;; 3. Access metadata and tools
(let ((meta (metadata *bom*)))
  (format t "Timestamp: ~A~%" (timestamp meta))
  (loop for tool across (tool-components *bom*)
        do (format t "Built with: ~A @ ~A~%"
                   (name tool)
                   (version tool))))

;; 4. Iterate over components
(loop for comp across (components *bom*)
      do (format t "Component: ~A (~A) - PURL: ~A~%"
                 (name comp)
                 (component-type comp)
                 (purl comp)))

;; 5. Inspect dependencies
(loop for dep across (dependencies *bom*)
      do (format t "Ref ~A depends on ~D packages~%"
                 (ref dep)
                 (length (depends-on dep))))
```

---

## Architecture & Design Principles

### Strict Specification Versioning
CycloneDX SBOMs specify top-level format parameters:
- `bomFormat`: Expected to be the exact string `"CycloneDX"`.
- `specVersion`: Expected to be the exact string `"1.7"`.

If an input document contains missing or unsupported formats (such as `"SPDX"` or older versions like `"1.5"` / `"1.6"`), [`build-sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L780-L799) signals specialized conditions.

### CLOS Object Model & Typed Slots
Every schema entity maps to a CLOS class with explicit `:type` declarations. JSON arrays map directly to Common Lisp vectors `(vector ...)` for memory compactness and fast indexed access. Missing optional collections default to empty vectors `#()`.

### Deduplication Mixins
In the CycloneDX 1.7 specification, multiple distinct entities share metadata capabilities:
* [`has-bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L201-L202): Provides slot `bom-ref :accessor bom-ref :type string`. Mixed into [`address`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L207-L213), [`organizational-contact`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L215-L218), [`organizational-entity`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L220-L224), [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304), [`service`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L311-L323), [`vulnerability`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L357-L373), [`license`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L249-L255), and [`license-expression`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L262-L266).
* [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205): Provides slot `properties :accessor properties :type (vector property)`. Mixed into [`sbom-metadata`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L379-L386), [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304), [`service`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L311-L323), [`vulnerability`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L357-L373), [`external-reference`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L277-L281), [`license`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L249-L255), and [`license-expression`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L262-L266).

### Polymorphic Tool & License Accessors
* **Tools Access**: CycloneDX tools can be defined as components or services inside `metadata -> tools`. `cl-sbom` defines generic functions [`tool-components`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L401-L435) and [`tool-services`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L404-L437) specialized for [`tools`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L375-L377), [`sbom-metadata`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L379-L386), [`sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L388-L399), and `nil` (returning `#()`).
* **License Acknowledgement**: Both [`license`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L249-L255) and [`license-expression`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L262-L266) implement generic function [`acknowledge`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L268-L275) for convenience.

### Package Organization
* [`cl-sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/main.lisp#L1-L12): High-level consumer interface.
* [`cl-sbom/cyclonedx-1.7`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L1-L178): Complete CLOS models, accessors, and builder functions.
* [`cl-sbom/cyclonedx-1.7/enums`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L1-L16): Deftype enumerations for CycloneDX types, algorithms, scopes, licenses, references, and severities.

---

## Error Handling & Conditions

All errors signaled by `cl-sbom` inherit from [`sbom-error`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L182-L184).

```
   error
     └── sbom-error
           ├── unsupported-bom-format
           └── unsupported-spec-version
```

### Condition Definitions

#### [`sbom-error`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L182-L184)
* **Inherits from:** `error`
* **Description:** Base condition class for all parsing and validation failures in `cl-sbom`.

#### [`unsupported-bom-format`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L186-L191)
* **Inherits from:** [`sbom-error`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L182-L184)
* **Slot / Reader:** `bom-format` (initarg `:bom-format` or `:format`)
* **Report:** `"Unsupported or missing bomFormat: <FORMAT> (expected \"CycloneDX\")"`
* **When signaled:** When the root JSON object lacks `"bomFormat"` or specifies any value other than `"CycloneDX"`.

#### [`unsupported-spec-version`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L193-L198)
* **Inherits from:** [`sbom-error`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L182-L184)
* **Slot / Reader:** `spec-version` (initarg `:spec-version` or `:version`)
* **Report:** `"Unsupported or missing specVersion: <VERSION> (expected \"1.7\")"`
* **When signaled:** When the root JSON object lacks `"specVersion"` or specifies any value other than `"1.7"`.

### Handling Conditions Example

```lisp
(handler-case
    (cl-sbom:parse #p"foreign-document.json" :format :cyclonedx-1.7)
  (cl-sbom:unsupported-bom-format (c)
    (format t "Cannot process BOM format: ~S~%" (cl-sbom:bom-format c)))
  (cl-sbom:unsupported-spec-version (c)
    (format t "Cannot process CycloneDX version: ~S~%" (cl-sbom:spec-version c)))
  (cl-sbom:sbom-error (c)
    (format t "Generic SBOM error: ~A~%" c)))
```

---

## API Reference: Package `cl-sbom`

The top-level package [`cl-sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/main.lisp#L1-L200) serves as the primary developer-facing interface. It defines the main loader function [`parse`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/main.lisp#L182-L194) and re-exports all CLOS models, slot accessors, mixins, generic functions, conditions, and enums.

Because `cl-sbom` avoids name conflicts with `COMMON-LISP`, downstream packages can simply `(:use :cl :cl-sbom)` without requiring any shadowing imports.

### Functions

#### `(parse path &key (format :cyclonedx-1.7))`
* **File:** [src/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/main.lisp#L182-L194)
* **Arguments:**
  - `path`: Pathname designator (string or pathname) or an open input stream containing the SBOM JSON.
  - `:format`: Format keyword designator (defaults to `:cyclonedx-1.7`). Supported values: `:cyclonedx-1.7`, `:cyclonedx`.
* **Returns:** An instance of [`sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L388-L399).
* **Signals:**
  - [`unsupported-bom-format`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L186-L191) if `:format` is not `:cyclonedx-1.7`/`:cyclonedx`, or if the document's `"bomFormat"` is not `"CycloneDX"`.
  - [`unsupported-spec-version`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L193-L198) if the document's `"specVersion"` is not `"1.7"`.

#### `(find-component sbom target &key (key #'bom-ref) (test #'string=))`
* **File:** [src/cyclonedx-1.7/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L547-L568)
* **Arguments:**
  - `sbom`: An instance of [`sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L388-L399).
  - `target`: The search value to match against (e.g. a `bom-ref` string, package name, or PURL).
  - `:key`: Function designator extracting the comparison value from each component (defaults to `#'bom-ref`).
  - `:test`: Equality/comparison function designator (defaults to `#'string=`).
* **Returns:** Multiple values `(values primary-match remaining-matches total-count)`:
  1. `primary-match`: The first matching [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304) instance, or `nil` if not found.
  2. `remaining-matches`: A list of any additional matching [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304) instances, or `nil` if unique or no match.
  3. `total-count`: Integer total count of matching components.
* **Performance:**
  - When querying by `bom-ref` (the default `:key #'bom-ref` with `:test #'string=`), lookups use a cached hash-table index for $O(1)$ fast retrieval.
  - When querying with arbitrary keys or tests, it searches across all components in the document (including root metadata components, tool components, and nested subcomponents).

#### `(all-components sbom)`
* **File:** [src/cyclonedx-1.7/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L510-L536)
* **Arguments:**
  - `sbom`: An instance of [`sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L388-L399).
* **Returns:** A flat list of all [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304) instances present in the SBOM document, traversing root metadata components, tool components, top-level components, and all recursively nested subcomponents.

### Re-exported Symbols
The package [`cl-sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/main.lisp#L1-L200) re-exports:
* **Core Functions:** [`parse`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/main.lisp#L182-L194), [`find-component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L547-L568), [`all-components`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L510-L536).
* **All Models:** [`sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L388-L399), [`sbom-metadata`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L379-L386), [`tools`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L375-L377), [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304), [`service`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L311-L323), [`dependency`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L306-L309), [`external-reference`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L277-L281), [`vulnerability`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L357-L373), and sub-models ([`vulnerability-source`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L325-L327), [`vulnerability-rating`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L333-L339), etc.).
* **All Accessors & Mixins:** [`components`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L395), [`dependencies`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L398), [`vulnerabilities`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L399), [`services`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L396), [`metadata`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L394), [`name`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L292), [`version`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L293), [`purl`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L302), [`bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L202), [`properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L205), [`tool-components`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L401-L435), [`tool-services`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L404-L437), [`acknowledge`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L268-L275).
* **All Conditions:** [`sbom-error`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L182-L184), [`unsupported-bom-format`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L186-L191), [`unsupported-spec-version`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L193-L198).
* **All Enums:** [`component-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L23-L37), [`scope-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L39-L43), [`algorithm-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L45-L60), [`license-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L71-L88), [`licence-id-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L90-L917), [`external-reference-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L919-L967), [`severity-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L969-L977), [`score-method-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L979-L987), [`impact-analysis-state`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L989-L996), [`impact-analysis-justification`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L998-L1008).

---

## API Reference: Package `cl-sbom/cyclonedx-1.7`

### Root Document Model: `sbom`

#### Class [`sbom`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L388-L399)
Root container representing a CycloneDX 1.7 SBOM.

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `schema` | `:schema` | `string` | `""` | `schema` | URI of the CycloneDX JSON schema (`$schema`). |
| `bom-format` | `:bom-format` | [`bom-format-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L19-L21) | `:CycloneDX` | `bom-format` | Always `:CycloneDX`. |
| `spec-version` | `:spec-version` | `string` | `""` | `spec-version` | CycloneDX specification version string (e.g. `"1.7"`). |
| `serial-number` | `:serial-number` | `string` | `""` | `serial-number` | Unique URN UUID serial number for this BOM. |
| `version` | `:version` | `integer` | `1` | `version` | Integer document version sequence. |
| `metadata` | `:metadata` | `(or null sbom-metadata)` | `nil` | `metadata` | Metadata describing author, tool, target, and timestamp. |
| `components` | `:components` | `(vector component)` | `#()` | `components` | Array of components included in this BOM. |
| `services` | `:services` | `(vector service)` | `#()` | `services` | Top-level external services / APIs described in this BOM. |
| `external-references` | `:external-references` | `(vector external-reference)` | `#()` | `external-references` | Top-level references (security, VCS, documents). |
| `dependencies` | `:dependencies` | `(vector dependency)` | `#()` | `dependencies` | Complete dependency graph mapping components to dependents. |
| `vulnerabilities` | `:vulnerabilities` | `(vector vulnerability)` | `#()` | `vulnerabilities` | Security advisories and vulnerabilities affecting targets. |

---

### Metadata & Tools: `sbom-metadata`, `tools`

#### Class [`sbom-metadata`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L379-L386)
Inherits: [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `timestamp` | `:timestamp` | `string` | `""` | `timestamp` | ISO-8601 creation timestamp. |
| `tools` | `:tools` | `(or null tools)` | `nil` | `tools` | Tools used to generate this SBOM. |
| `authors` | `:authors` | `(vector organizational-contact)` | `#()` | `authors` | Persons who authored the BOM. |
| `component` | `:component` | `(or null component)` | `nil` | `component` | Root subject component of the BOM (e.g. Docker image). |
| `manufacturer` | `:manufacturer` | `(or null organizational-entity)` | `nil` | `manufacturer` | Manufacturing entity. |
| `supplier` | `:supplier` | `(or null organizational-entity)` | `nil` | `supplier` | Supplying entity. |
| `licenses` | `:licenses` | `(vector (or license license-expression))` | `#()` | `licenses` | Licenses governing the BOM metadata itself. |
| `properties` | `:properties` | `(vector property)` | `#()` | `properties` | Name-value property pairs. |

#### Class [`tools`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L375-L377)
Represents the tools used to create the SBOM.

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `components` | `:components` | `(vector component)` | `#()` | `components` | Tool components (e.g. Syft, Trivy). |
| `services` | `:services` | `(vector service)` | `#()` | `services` | Tool services (e.g. hosted scanning SaaS). |

---

### Components: `component`

#### Class [`component`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L283-L304)
Inherits: [`has-bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L201-L202), [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).
Prints formatted as `#<COMPONENT Name: <name>, Type: <type> {identity}>`.

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `bom-ref` | `:bom-ref` | `string` | `""` | `bom-ref` | Unique reference key for graph cross-referencing. |
| `component-type` | `:type` | [`component-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L23-L37) | *(required)* | `component-type` | Type keyword (`:library`, `:container`, etc.). |
| `mime-type` | `:mime-type` | `string` | `""` | `mime-type` | Media type of the component. |
| `supplier` | `:supplier` | `(or null organizational-entity)` | `nil` | `supplier` | Supplying organization. |
| `manufacturer` | `:manufacturer` | `(or null organizational-entity)` | `nil` | `manufacturer` | Manufacturing organization. |
| `authors` | `:authors` | `(vector organizational-contact)` | `#()` | `authors` | Authors vector. |
| `author` | `:author` | `string` | `""` | `author` | Single author string. |
| `publisher` | `:publisher` | `string` | `""` | `publisher` | Publishing entity. |
| `group` | `:group` | `string` | `""` | `group` | Package group/namespace (e.g. Maven groupId). |
| `name` | `:name` | `string` | *(required)* | `name` | Component package name. |
| `version` | `:version` | `string` | `""` | `version` | Package release version. |
| `version-range` | `:version-range` | `string` | `""` | `version-range` | Version range constraint. |
| `is-external` | `:is-external` | `boolean` | `nil` | `is-external` | Whether component is external to the system. |
| `description` | `:description` | `string` | `""` | `description` | Description text. |
| `scope` | `:scope` | `(or null scope-type)` | `nil` | `scope` | Dependency scope (`:required`, `:optional`, `:excluded`). |
| `hashes` | `:hashes` | `(vector hash)` | `#()` | `hashes` | Cryptographic hashes. |
| `licenses` | `:licenses` | `(vector (or license license-expression))` | `#()` | `licenses` | License declarations. |
| `copyright` | `:copyright` | `string` | `""` | `copyright` | Copyright notice statement. |
| `cpe` | `:cpe` | `string` | `""` | `cpe` | Common Platform Enumeration designator. |
| `purl` | `:purl` | `string` | `""` | `purl` | Package URL (Package-URL specification). |
| `external-references`| `:external-references` | `(vector external-reference)` | `#()` | `external-references` | Associated links, VCS, bug trackers. |
| `properties` | `:properties` | `(vector property)` | `#()` | `properties` | Custom key-value properties. |
| `components` | `:components` | `(vector component)` | `#()` | `components` | Sub-components nested inside this component. |

---

### Services: `service`

#### Class [`service`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L311-L323)
Represents cloud, network, microservice, or API endpoints.
Inherits: [`has-bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L201-L202), [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `bom-ref` | `:bom-ref` | `string` | `""` | `bom-ref` | Unique BOM reference key. |
| `provider` | `:provider` | `(or null organizational-entity)` | `nil` | `provider` | Service provider organization. |
| `group` | `:group` | `string` | `""` | `group` | Group / namespace of service. |
| `name` | `:name` | `string` | *(required)* | `name` | Service name. |
| `version` | `:version` | `string` | `""` | `version` | Service version. |
| `description` | `:description` | `string` | `""` | `description` | Service purpose description. |
| `endpoints` | `:endpoints` | `(vector string)` | `#()` | `endpoints` | URLs/URIs where the service is exposed. |
| `authenticated` | `:authenticated` | `(or null boolean)` | `nil` | `authenticated` | Whether authentication is enforced. |
| `x-trust-boundary`| `:x-trust-boundary` | `(or null boolean)` | `nil` | `x-trust-boundary` | Crosses trust boundary. |
| `trust-zone` | `:trust-zone` | `string` | `""` | `trust-zone` | Security / network trust zone name. |
| `licenses` | `:licenses` | `(vector (or license license-expression))` | `#()` | `licenses` | Licenses for the service. |
| `external-references`| `:external-references`| `(vector external-reference)` | `#()` | `external-references`| API docs, Swagger links, OpenAPI specs. |
| `services` | `:services` | `(vector service)` | `#()` | `services` | Nested sub-services. |
| `properties` | `:properties` | `(vector property)` | `#()` | `properties` | Key-value properties. |

---

### Dependency Graph: `dependency`

#### Class [`dependency`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L306-L309)
Represents a node in the CycloneDX direct dependency graph.
Prints formatted as `#<DEPENDENCY Ref: <ref>, Depends-On: <count>, Provides: <count> {identity}>`.

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `ref` | `:ref` | `string` | *(required)* | `ref` | `bom-ref` identifier of the source component or service. |
| `depends-on` | `:depends-on` | `(vector string)` | `#()` | `depends-on` | Vector of `bom-ref` identifiers this node depends on. |
| `provides` | `:provides` | `(vector string)` | `#()` | `provides` | Vector of `bom-ref` identifiers this dependency provides. |

---

### External References: `external-reference`

#### Class [`external-reference`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L277-L281)
Links to external resources (documentation, VCS repos, issue trackers, audit logs).
Inherits: [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `url` | `:url` | `string` | *(required)* | `url` | URL/URI of the resource. |
| `reference-type`| `:type` | `(or external-reference-type string)` | *(required)* | `reference-type` | Type keyword (`:vcs`, `:issue-tracker`, `:website`, etc.). |
| `comment` | `:comment` | `string` | `""` | `comment` | Optional human-readable comment. |
| `hashes` | `:hashes` | `(vector hash)` | `#()` | `hashes` | Cryptographic hashes verifying the target file. |
| `properties` | `:properties` | `(vector property)` | `#()` | `properties` | Associated key-value properties. |

---

### Vulnerabilities & Advisories

#### Class [`vulnerability`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L357-L373)
Inherits: [`has-bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L201-L202), [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `bom-ref` | `:bom-ref` | `string` | `""` | `bom-ref` | BOM identifier. |
| `id` | `:id` | `string` | `""` | `id` | Advisory identifier (e.g. `"CVE-2024-1234"`). |
| `source` | `:source` | `(or null vulnerability-source)` | `nil` | `source` | Source organization / database (NVD, GitHub, etc.). |
| `references` | `:references` | `(vector vulnerability-reference)`| `#()` | `references` | Cross-referenced CVE/advisory identifiers. |
| `ratings` | `:ratings` | `(vector vulnerability-rating)` | `#()` | `ratings` | CVSS, OWASP, or SSVC scoring records. |
| `cwes` | `:cwes` | `(vector integer)` | `#()` | `cwes` | Common Weakness Enumeration integers (e.g. `#(79 89)`). |
| `description`| `:description`| `string` | `""` | `description` | Summary description of the flaw. |
| `detail` | `:detail` | `string` | `""` | `detail` | In-depth technical explanation. |
| `recommendation`|`:recommendation`| `string` | `""`| `recommendation`| Remediation recommendations. |
| `workaround` | `:workaround` | `string` | `""` | `workaround` | Temporary mitigation steps. |
| `advisories` | `:advisories` | `(vector vulnerability-advisory)`| `#()` | `advisories` | Published security advisory links. |
| `created` | `:created` | `string` | `""` | `created` | Record creation timestamp. |
| `published` | `:published` | `string` | `""` | `published` | Public disclosure timestamp. |
| `updated` | `:updated` | `string` | `""` | `updated` | Last update timestamp. |
| `rejected` | `:rejected` | `string` | `""` | `rejected` | Rejection timestamp (if revoked). |
| `analysis` | `:analysis` | `(or null vulnerability-analysis)`| `nil` | `analysis` | VEX assessment / triage state. |
| `affects` | `:affects` | `(vector vulnerability-target)` | `#()` | `affects` | List of affected components and version specs. |

#### Sub-models:
* **[`vulnerability-source`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L325-L327)**: Slots `name :type string`, `url :type string`.
* **[`vulnerability-reference`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L329-L331)**: Slots `id :type string`, `source :type (or null vulnerability-source)`.
* **[`vulnerability-rating`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L333-L339)**:
  - `source :accessor source`
  - `score :accessor score :type (or null number)` (e.g. `9.8`)
  - `severity :accessor severity :type (or null severity-type string)` (`:critical`, `:high`, `:medium`, `:low`, `:info`, `:none`, `:unknown`)
  - `score-method :accessor score-method :initarg :method :type (or null score-method-type string)` (`:CVSSv2`, `:CVSSv3`, `:CVSSv31`, `:CVSSv4`, `:OWASP`, `:SSVC`, `:other`)
  - `score-vector :accessor score-vector :initarg :vector :type string` (CVSS vector string)
  - `justification :accessor justification :type string`
* **[`vulnerability-advisory`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L341-L343)**: Slots `title :type string`, `url :type string`.
* **[`vulnerability-analysis`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L345-L351)**:
  - `state :type (or null impact-analysis-state string)` (`:resolved`, `:exploitable`, `:in_triage`, `:false_positive`, `:not_affected`, etc.)
  - `justification :type (or null impact-analysis-justification string)` (`:code_not_present`, `:code_not_reachable`, etc.)
  - `response :type (vector string)`
  - `detail :type string`, `first-issued :type string`, `last-updated :type string`
* **[`vulnerability-target`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L353-L355)**:
  - `ref :type string` (`bom-ref` of affected component)
  - `versions :type vector` (version range or exact version objects)

---

### Licenses & Legal: `license`, `license-expression`

#### Class [`license`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L249-L255)
Represents a discrete license choice.
Inherits: [`has-bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L201-L202), [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `id` | `:id` | `(or null licence-id-type string)` | `nil` | `id` | Standard SPDX license identifier keyword (e.g. `:MIT`, `:Apache-2.0`). |
| `name` | `:name` | `string` | `""` | `name` | Custom or non-SPDX license name. |
| `acknowledgement`| `:acknowledgement`| `(or null acknowledgement-type)` | `nil` | `acknowledgement`| `:declared` or `:concluded`. |
| `text` | `:text` | `(or null attachment)` | `nil` | `text` | Full license text attachment. |
| `url` | `:url` | `string` | `""` | `url` | License web link. |
| `licensing` | `:licensing` | `(or null licensing)` | `nil` | `licensing` | Commercial licensing metadata. |

#### Class [`license-expression`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L262-L266)
Represents compound SPDX license expressions (e.g. `"MIT OR Apache-2.0"`).
Inherits: [`has-bom-ref`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L201-L202), [`has-properties`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L204-L205).

| Slot | Initarg | Type | Default | Accessor | Description |
|---|---|---|---|---|---|
| `expression` | `:expression` | `string` | `""` | `expression` | The raw SPDX expression string. |
| `expression-details`| `:expression-details`| `(vector expression)`| `#()` | `expression-details`| Detailed expressions. |
| `acknowledgement`| `:acknowledgement`| `(or null acknowledgement-type)` | `nil` | `acknowledgement`| `:declared` or `:concluded`. |
| `licensing` | `:licensing` | `(or null licensing)` | `nil` | `licensing` | Commercial licensing details. |

---

### Common Entities

#### [`property`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L230-L232)
Key-value pair metadata.
- `name :accessor name :type string` *(required)*
- `value :accessor value :type string` (default: `""`)

#### [`hash`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L226-L228)
Cryptographic checksum.
- `alg :accessor alg :type algorithm-type` (`:SHA-256`, `:SHA-1`, `:MD5`, etc.)
- `content :accessor content :type string`

#### [`attachment`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L234-L237)
Embedded text or binary content.
- `content-type :accessor content-type :type string` (default: `"text/plain"`)
- `encoding :accessor encoding :type (or null encoding-type string)` (`:base64` or `nil`)
- `content :accessor content :type string` *(required)*

#### [`organizational-contact`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L215-L218)
- `name :accessor name :type string`
- `email :accessor email :type string`
- `phone :accessor phone :type string`

#### [`organizational-entity`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L220-L224)
- `name :accessor name :type string`
- `address :accessor address :type (or null address)`
- `url :accessor url :type (vector string)`
- `contact :accessor contact :type (vector organizational-contact)`

#### [`address`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L207-L213)
- `country`, `region`, `locality`, `post-office-box-number`, `postal-code`, `street-address` (all `string`).

---

### Mixins & Generic Functions

#### Generic Function `(tool-components object)`
* **File:** [src/cyclonedx-1.7/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L401-L435)
* **Methods:**
  - `(tools tools)`: Returns `(components tools)`.
  - `(meta sbom-metadata)`: Returns tool components if `tools` is present, or `#()`.
  - `(sbom sbom)`: Returns tool components from `(metadata sbom)`, or `#()`.
  - `(obj null)`: Returns `#()`.

#### Generic Function `(tool-services object)`
* **File:** [src/cyclonedx-1.7/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L404-L437)
* **Methods:**
  - `(tools tools)`: Returns `(services tools)`.
  - `(meta sbom-metadata)`: Returns tool services if `tools` is present, or `#()`.
  - `(sbom sbom)`: Returns tool services from `(metadata sbom)`, or `#()`.
  - `(obj null)`: Returns `#()`.

#### Generic Function `(acknowledge object)`
* **File:** [src/cyclonedx-1.7/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L268-L275)
* **Methods:**
  - `(lic license)`: Returns `(acknowledgement lic)`.
  - `(expr license-expression)`: Returns `(acknowledgement expr)`.

---

### Builders

The package provides explicit builder functions transforming parsed hash-table structures into CLOS objects:

* [`build-sbom (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L780-L799)
* [`build-metadata (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L763-L778)
* [`build-tools (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L757-L761)
* [`build-component (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L720-L750)
* [`build-components (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L752-L755)
* [`build-service (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L611-L627)
* [`build-services (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L629-L632)
* [`build-dependency (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L600-L604)
* [`build-dependencies (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L606-L609)
* [`build-external-reference (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L584-L593)
* [`build-external-references (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L595-L598)
* [`build-vulnerability (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L686-L713)
* [`build-vulnerabilities (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L715-L718)
* [`build-vulnerability-source (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L634-L638)
* [`build-vulnerability-reference (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L640-L643)
* [`build-vulnerability-rating (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L645-L658)
* [`build-vulnerability-advisory (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L660-L663)
* [`build-vulnerability-analysis (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L665-L679)
* [`build-vulnerability-target (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L681-L684)
* [`build-license (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L544-L561)
* [`build-licenses (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L579-L582)
* [`build-hash (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L462-L465)
* [`build-hashes (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L467-L470)
* [`build-property (data)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L452-L455)
* [`build-properties (vec)`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/main.lisp#L457-L460)

---

## API Reference: Package `cl-sbom/cyclonedx-1.7/enums`

The [`enums.lisp`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp) file exports all member types specified by CycloneDX 1.7:

| Type Name | Defined Values / Description | File Link |
|---|---|---|
| [`bom-format-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L19-L21) | `:CycloneDX` | [enums.lisp#L19](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L19-L21) |
| [`component-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L23-L37) | `:application`, `:framework`, `:library`, `:container`, `:platform`, `:operating-system`, `:device`, `:device-driver`, `:firmware`, `:file`, `:machine-learning-model`, `:data`, `:cryptographic-asset` | [enums.lisp#L23](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L23-L37) |
| [`scope-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L39-L43) | `:required`, `:optional`, `:excluded` | [enums.lisp#L39](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L39-L43) |
| [`algorithm-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L45-L60) | `:MD5`, `:SHA-1`, `:SHA-256`, `:SHA-384`, `:SHA-512`, `:SHA3-256`, `:SHA3-384`, `:SHA3-512`, `:BLAKE2b-256`, `:BLAKE2b-384`, `:BLAKE2b-512`, `:BLAKE3`, `:Streebog-256`, `:Streebog-512` | [enums.lisp#L45](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L45-L60) |
| [`acknowledgement-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L62-L65) | `:declared`, `:concluded` | [enums.lisp#L62](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L62-L65) |
| [`encoding-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L67-L69) | `:base64` | [enums.lisp#L67](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L67-L69) |
| [`license-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L71-L88) | Commercial license types: `:academic`, `:appliance`, `:client-access`, `:concurrent-user`, `:core-points`, `:custom-metric`, `:device`, `:evaluation`, `:named-user`, `:node-locked`, `:oem`, `:perpetual`, `:processor-points`, `:subscription`, `:user`, `:other` | [enums.lisp#L71](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L71-L88) |
| [`licence-id-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L90-L917) | Complete standard SPDX license identifiers (700+ entries, e.g. `:MIT`, `:Apache-2.0`, `:GPL-3.0-only`, `:BSD-3-Clause`) | [enums.lisp#L90](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L90-L917) |
| [`external-reference-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L919-L967) | `:vcs`, `:issue-tracker`, `:website`, `:advisories`, `:bom`, `:mailing-list`, `:social`, `:chat`, `:documentation`, `:support`, `:source-distribution`, `:distribution`, `:distribution-intake`, `:license`, `:build-meta`, `:build-system`, `:release-notes`, `:security-contact`, `:model-card`, `:log`, `:configuration`, `:evidence`, `:formulation`, `:attestation`, `:threat-model`, `:adversary-model`, `:risk-assessment`, `:vulnerability-assertion`, `:exploitability-statement`, `:pentest-report`, `:static-analysis-report`, `:dynamic-analysis-report`, `:runtime-analysis-report`, `:component-analysis-report`, `:maturity-report`, `:certification-report`, `:codified-infrastructure`, `:quality-metrics`, `:poam`, `:electronic-signature`, `:digital-signature`, `:rfc-9116`, `:patent`, `:patent-family`, `:patent-assertion`, `:citation`, `:other` | [enums.lisp#L919](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L919-L967) |
| [`severity-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L969-L977) | `:critical`, `:high`, `:medium`, `:low`, `:info`, `:none`, `:unknown` | [enums.lisp#L969](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L969-L977) |
| [`score-method-type`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L979-L987) | `:CVSSv2`, `:CVSSv3`, `:CVSSv31`, `:CVSSv4`, `:OWASP`, `:SSVC`, `:other` | [enums.lisp#L979](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L979-L987) |
| [`impact-analysis-state`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L989-L996) | `:resolved`, `:resolved_with_pedigree`, `:exploitable`, `:in_triage`, `:false_positive`, `:not_affected` | [enums.lisp#L989](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L989-L996) |
| [`impact-analysis-justification`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L998-L1008)| `:code_not_present`, `:code_not_reachable`, `:requires_configuration`, `:requires_dependency`, `:requires_environment`, `:protected_by_compiler`, `:protected_at_runtime`, `:protected_at_perimeter`, `:protected_by_mitigating_control` | [enums.lisp#L998](file:///Users/nmunro/Dev/common-lisp/cl-sbom/src/cyclonedx-1.7/enums.lisp#L998-L1008) |

---

## Recipes & Common Tasks

### Searching Components by Name, PURL, or BOM-Ref

Use `find-component` to search across all components in the document (including root metadata, tool components, and nested subcomponents).

```lisp
;; 1. Fast O(1) lookup by unique bom-ref (the default):
(let ((comp (cl-sbom:find-component sbom "pkg:apk/wolfi/apk-tools@2.14.10-r14...")))
  (when comp
    (format t "Found: ~A~%" comp)))

;; 2. Search by package name:
(let ((comp (cl-sbom:find-component sbom "apk-tools" :key #'cl-sbom:name)))
  (when comp
    (describe comp)))

;; 3. Check for multiple copies or ambiguity using multiple return values:
(multiple-value-bind (primary others total)
    (cl-sbom:find-component sbom "openssl" :key #'cl-sbom:name :test #'search)
  (if primary
      (format t "Found ~D matches! Primary: ~A, Others: ~A~%" total primary others)
      (format t "No matches found.~%")))
```

### Traversing the Dependency Graph

```lisp
(defun get-direct-dependencies (sbom target-ref)
  "Find all components that TARGET-REF directly depends on."
  (let ((dep-entry (find target-ref (cl-sbom:dependencies sbom)
                         :key #'cl-sbom:ref
                         :test #'string=)))
    (if dep-entry
        (cl-sbom:depends-on dep-entry)
        #())))
```

### Auditing Vulnerabilities & CVSS Ratings

```lisp
(defun print-critical-vulnerabilities (sbom)
  (loop for vuln across (cl-sbom:vulnerabilities sbom)
        do (loop for rating across (cl-sbom:ratings vuln)
                 when (eq (cl-sbom:severity rating) :critical)
                 do (format t "CRITICAL [~A] Score: ~A Method: ~A Description: ~A~%"
                            (cl-sbom:id vuln)
                            (cl-sbom:score rating)
                            (cl-sbom:score-method rating)
                            (cl-sbom:description vuln)))))
```

### Extracting Licenses

```lisp
(defun component-license-names (comp)
  (map 'list
       (lambda (lic-choice)
         (etypecase lic-choice
           (cl-sbom:license
            (or (cl-sbom:id lic-choice)
                (cl-sbom:name lic-choice)))
           (cl-sbom:license-expression
            (cl-sbom:expression lic-choice))))
       (cl-sbom:licenses comp)))
```

### Inspecting Microservices

```lisp
(defun list-microservices (sbom)
  (loop for svc across (cl-sbom:services sbom)
        do (format t "Service: ~A (Endpoints: ~A, Authenticated: ~A)~%"
                   (cl-sbom:name svc)
                   (cl-sbom:endpoints svc)
                   (cl-sbom:authenticated svc))))
```

---

## Testing & Development

Tests are implemented using [Rove](https://github.com/fukamachi/rove) in [tests/main.lisp](file:///Users/nmunro/Dev/common-lisp/cl-sbom/tests/main.lisp).

### Running Tests

Using the [`justfile`](file:///Users/nmunro/Dev/common-lisp/cl-sbom/justfile):
```sh
just test
```

Using Common Lisp directly:
```lisp
(asdf:test-system :cl-sbom)
```

Or via Qlot:
```sh
qlot exec ros run --eval '(asdf:test-system :cl-sbom)' --eval '(quit)'
```
