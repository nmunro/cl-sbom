(defpackage cl-sbom/tests/main
  (:use :cl
        :cl-sbom
        :rove)
  (:import-from :cl-sbom/cyclonedx-1.7/enums
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
  (:import-from :cl-sbom/cyclonedx-1.7
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
                #:property
                #:name
                #:address
                #:organizational-contact
                #:organizational-entity
                #:hash
                #:alg
                #:content
                #:attachment
                #:content-type
                #:encoding
                #:licensing
                #:license
                #:expression
                #:license-expression
                #:id
                #:acknowledgement
                #:acknowledge
                #:component
                #:version
                #:author
                #:authors
                #:publisher
                #:cpe
                #:purl
                #:timestamp
                #:metadata
                #:schema
                #:bom-format
                #:spec-version
                #:serial-number
                #:hashes
                #:licenses
                #:build-sbom
                #:build-metadata
                #:build-tools
                #:build-component
                #:build-property
                #:build-hash
                #:build-license
                #:sbom-error
                #:unsupported-bom-format
                #:unsupported-spec-version
                #:external-reference
                #:build-external-reference
                #:build-external-references
                #:external-references
                #:reference-type
                #:comment
                #:dependency
                #:build-dependency
                #:build-dependencies
                #:dependencies
                #:ref
                #:depends-on
                #:provides
                #:service
                #:build-service
                #:build-services
                #:provider
                #:endpoints
                #:authenticated
                #:x-trust-boundary
                #:trust-zone
                #:vulnerability
                #:build-vulnerability
                #:build-vulnerabilities
                #:vulnerability-source
                #:build-vulnerability-source
                #:vulnerability-reference
                #:build-vulnerability-reference
                #:vulnerability-rating
                #:build-vulnerability-rating
                #:vulnerability-advisory
                #:build-vulnerability-advisory
                #:vulnerability-analysis
                #:build-vulnerability-analysis
                #:vulnerability-target
                #:build-vulnerability-target
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
                #:description
                #:group
                #:url
                #:vulnerabilities))
(in-package :cl-sbom/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :cl-sbom)' in your Lisp.

(deftest test-component-type-enum
  (testing "valid component-type values"
    (let ((valid-types '(:application
                         :framework
                         :library
                         :container
                         :platform
                         :operating-system
                         :device
                         :device-driver
                         :firmware
                         :file
                         :machine-learning-model
                         :data
                         :cryptographic-asset)))
      (dolist (type-val valid-types)
        (ok (typep type-val 'component-type)
            (format nil "~S should be a valid component-type" type-val)))))

  (testing "invalid component-type values"
    (ok (not (typep :unknown-component 'component-type)))
    (ok (not (typep "application" 'component-type)))
    (ok (not (typep 'application 'component-type)))
    (ok (not (typep nil 'component-type)))))

(deftest test-scope-type-enum
  (testing "valid scope-type values"
    (let ((valid-scopes '(:required
                          :optional
                          :excluded)))
      (dolist (scope-val valid-scopes)
        (ok (typep scope-val 'scope-type)
            (format nil "~S should be a valid scope-type" scope-val)))))

  (testing "invalid scope-type values"
    (ok (not (typep :unknown-scope 'scope-type)))
    (ok (not (typep "required" 'scope-type)))
    (ok (not (typep 'required 'scope-type)))
    (ok (not (typep nil 'scope-type)))))

(deftest test-algorithm-type-enum
  (testing "valid algorithm-type values"
    (let ((valid-algorithms '(:MD5
                             :SHA-1
                             :SHA-256
                             :SHA-384
                             :SHA-512
                             :SHA3-256
                             :SHA3-384
                             :SHA3-512
                             :BLAKE2b-256
                             :BLAKE2b-384
                             :BLAKE2b-512
                             :BLAKE3
                             :Streebog-256
                             :Streebog-512)))
      (dolist (alg-val valid-algorithms)
        (ok (typep alg-val 'algorithm-type)
            (format nil "~S should be a valid algorithm-type" alg-val)))))

  (testing "invalid algorithm-type values"
    (ok (not (typep :unknown-alg 'algorithm-type)))
    (ok (not (typep "SHA-256" 'algorithm-type)))
    (ok (not (typep 'SHA-256 'algorithm-type)))
    (ok (not (typep nil 'algorithm-type)))))

(deftest test-acknowledgement-type-enum
  (testing "valid acknowledgement-type values"
    (let ((valid-acks '(:declared
                        :concluded)))
      (dolist (ack-val valid-acks)
        (ok (typep ack-val 'acknowledgement-type)
            (format nil "~S should be a valid acknowledgement-type" ack-val)))))

  (testing "invalid acknowledgement-type values"
    (ok (not (typep :unknown-ack 'acknowledgement-type)))
    (ok (not (typep "declared" 'acknowledgement-type)))
    (ok (not (typep 'declared 'acknowledgement-type)))
    (ok (not (typep nil 'acknowledgement-type)))))

(deftest test-encoding-type-enum
  (testing "valid encoding-type values"
    (let ((valid-encodings '(:base64)))
      (dolist (enc-val valid-encodings)
        (ok (typep enc-val 'encoding-type)
            (format nil "~S should be a valid encoding-type" enc-val)))))

  (testing "invalid encoding-type values"
    (ok (not (typep :unknown-encoding 'encoding-type)))
    (ok (not (typep "base64" 'encoding-type)))
    (ok (not (typep 'base64 'encoding-type)))
    (ok (not (typep nil 'encoding-type)))))

(deftest test-license-type-enum
  (testing "valid license-type values"
    (let ((valid-license-types '(:academic
                                :appliance
                                :client-access
                                :concurrent-user
                                :core-points
                                :custom-metric
                                :device
                                :evaluation
                                :named-user
                                :node-locked
                                :oem
                                :perpetual
                                :processor-points
                                :subscription
                                :user
                                :other)))
      (dolist (lic-val valid-license-types)
        (ok (typep lic-val 'license-type)
            (format nil "~S should be a valid license-type" lic-val)))))

  (testing "invalid license-type values"
    (ok (not (typep :unknown-license-type 'license-type)))
    (ok (not (typep "academic" 'license-type)))
    (ok (not (typep 'academic 'license-type)))
    (ok (not (typep nil 'license-type)))))

(deftest test-licence-id-type-enum
  (testing "valid licence-id-type values"
    (let ((valid-licence-ids '(:0BSD
                               :3D-Slicer-1.0
                               :AAL
                               :Abstyles
                               :AdaCore-doc
                               :Adobe-2006
                               :Adobe-Display-PostScript
                               :Adobe-Glyph
                               :Adobe-Utopia
                               :ADSL
                               :Advanced-Cryptics-Dictionary
                               :AFL-1.1
                               :AFL-1.2
                               :AFL-2.0
                               :AFL-2.1
                               :AFL-3.0
                               :Afmparse
                               :AGPL-1.0
                               :AGPL-1.0-only
                               :AGPL-1.0-or-later
                               :AGPL-3.0
                               :AGPL-3.0-only
                               :AGPL-3.0-or-later
                               :Aladdin
                               :ALGLIB-Documentation
                               :AMD-newlib
                               :AMDPLPA
                               :AML
                               :AML-glslang
                               :AMPAS
                               :ANTLR-PD
                               :ANTLR-PD-fallback
                               :any-OSI
                               :any-OSI-perl-modules
                               :Apache-1.0
                               :Apache-1.1
                               :Apache-2.0
                               :APAFML
                               :APL-1.0
                               :App-s2p
                               :APSL-1.0
                               :APSL-1.1
                               :APSL-1.2
                               :APSL-2.0
                               :Arphic-1999
                               :Artistic-1.0
                               :Artistic-1.0-cl8
                               :Artistic-1.0-Perl
                               :Artistic-2.0
                               :Artistic-dist
                               :Aspell-RU
                               :ASWF-Digital-Assets-1.0
                               :ASWF-Digital-Assets-1.1
                               :atc-game
                               :Baekmuk
                               :Bahyph
                               :Barr
                               :bcrypt-Solar-Designer
                               :Beerware
                               :Bitstream-Charter
                               :Bitstream-Vera
                               :BitTorrent-1.0
                               :BitTorrent-1.1
                               :blessing
                               :BlueOak-1.0.0
                               :Boehm-GC
                               :Boehm-GC-without-fee
                               :BOLA-1.1
                               :Borceux
                               :Brian-Gladman-2-Clause
                               :Brian-Gladman-3-Clause
                               :Brian-Gladman-3-Clause-no-conversion
                               :BSD-1-Clause
                               :BSD-2-Clause
                               :BSD-2-Clause-Darwin
                               :BSD-2-Clause-first-lines
                               :BSD-2-Clause-FreeBSD
                               :BSD-2-Clause-NetBSD
                               :BSD-2-Clause-Patent
                               :BSD-2-Clause-pkgconf-disclaimer
                               :BSD-2-Clause-pos-unchanged
                               :BSD-2-Clause-Views
                               :BSD-3-Clause
                               :BSD-3-Clause-acpica
                               :BSD-3-Clause-Attribution
                               :BSD-3-Clause-Clear
                               :BSD-3-Clause-flex
                               :BSD-3-Clause-HP
                               :BSD-3-Clause-LBNL
                               :BSD-3-Clause-Modification
                               :BSD-3-Clause-No-Military-License
                               :BSD-3-Clause-No-Nuclear-License
                               :BSD-3-Clause-No-Nuclear-License-2014
                               :BSD-3-Clause-No-Nuclear-Warranty
                               :BSD-3-Clause-Open-MPI
                               :BSD-3-Clause-OpenWebUI
                               :BSD-3-Clause-Sun
                               :BSD-3-Clause-Tso
                               :BSD-4-Clause
                               :BSD-4-Clause-Shortened
                               :BSD-4-Clause-UC
                               :BSD-4.3RENO
                               :BSD-4.3TAHOE
                               :BSD-Advertising-Acknowledgement
                               :BSD-ask-to-endorse
                               :BSD-Attribution-HPND-disclaimer
                               :BSD-Inferno-Nettverk
                               :BSD-Mark-Modifications
                               :BSD-Protection
                               :BSD-Source-alt-GPL
                               :BSD-Source-beginning-file
                               :BSD-Source-Code
                               :BSD-Source-Code-no-disclaimer
                               :BSD-Systemics
                               :BSD-Systemics-W3Works
                               :BSL-1.0
                               :Buddy
                               :Bugroff
                               :BUSL-1.1
                               :bzip2-1.0.5
                               :bzip2-1.0.6
                               :C-UDA-1.0
                               :CAL-1.0
                               :CAL-1.0-Combined-Work-Exception
                               :Caldera
                               :Caldera-no-preamble
                               :CAPEC-tou
                               :Catharon
                               :CATOSL-1.1
                               :CC-BY-1.0
                               :CC-BY-2.0
                               :CC-BY-2.5
                               :CC-BY-2.5-AU
                               :CC-BY-3.0
                               :CC-BY-3.0-AT
                               :CC-BY-3.0-AU
                               :CC-BY-3.0-DE
                               :CC-BY-3.0-IGO
                               :CC-BY-3.0-NL
                               :CC-BY-3.0-US
                               :CC-BY-4.0
                               :CC-BY-NC-1.0
                               :CC-BY-NC-2.0
                               :CC-BY-NC-2.5
                               :CC-BY-NC-3.0
                               :CC-BY-NC-3.0-DE
                               :CC-BY-NC-3.0-IGO
                               :CC-BY-NC-4.0
                               :CC-BY-NC-ND-1.0
                               :CC-BY-NC-ND-2.0
                               :CC-BY-NC-ND-2.5
                               :CC-BY-NC-ND-3.0
                               :CC-BY-NC-ND-3.0-DE
                               :CC-BY-NC-ND-3.0-IGO
                               :CC-BY-NC-ND-4.0
                               :CC-BY-NC-SA-1.0
                               :CC-BY-NC-SA-2.0
                               :CC-BY-NC-SA-2.0-DE
                               :CC-BY-NC-SA-2.0-FR
                               :CC-BY-NC-SA-2.0-UK
                               :CC-BY-NC-SA-2.5
                               :CC-BY-NC-SA-3.0
                               :CC-BY-NC-SA-3.0-DE
                               :CC-BY-NC-SA-3.0-IGO
                               :CC-BY-NC-SA-4.0
                               :CC-BY-ND-1.0
                               :CC-BY-ND-2.0
                               :CC-BY-ND-2.5
                               :CC-BY-ND-3.0
                               :CC-BY-ND-3.0-DE
                               :CC-BY-ND-4.0
                               :CC-BY-SA-1.0
                               :CC-BY-SA-2.0
                               :CC-BY-SA-2.0-UK
                               :CC-BY-SA-2.1-JP
                               :CC-BY-SA-2.5
                               :CC-BY-SA-3.0
                               :CC-BY-SA-3.0-AT
                               :CC-BY-SA-3.0-DE
                               :CC-BY-SA-3.0-IGO
                               :CC-BY-SA-4.0
                               :CC-PDDC
                               :CC-PDM-1.0
                               :CC-SA-1.0
                               :CC0-1.0
                               :CDDL-1.0
                               :CDDL-1.1
                               :CDL-1.0
                               :CDLA-Permissive-1.0
                               :CDLA-Permissive-2.0
                               :CDLA-Sharing-1.0
                               :CECILL-1.0
                               :CECILL-1.1
                               :CECILL-2.0
                               :CECILL-2.1
                               :CECILL-B
                               :CECILL-C
                               :CERN-OHL-1.1
                               :CERN-OHL-1.2
                               :CERN-OHL-P-2.0
                               :CERN-OHL-S-2.0
                               :CERN-OHL-W-2.0
                               :CFITSIO
                               :check-cvs
                               :checkmk
                               :ClArtistic
                               :Clips
                               :CMU-Mach
                               :CMU-Mach-nodoc
                               :CNRI-Jython
                               :CNRI-Python
                               :CNRI-Python-GPL-Compatible
                               :COIL-1.0
                               :Community-Spec-1.0
                               :Condor-1.1
                               :copyleft-next-0.3.0
                               :copyleft-next-0.3.1
                               :Cornell-Lossless-JPEG
                               :CPAL-1.0
                               :CPL-1.0
                               :CPOL-1.02
                               :Cronyx
                               :Crossword
                               :CryptoSwift
                               :CrystalStacker
                               :CUA-OPL-1.0
                               :Cube
                               :curl
                               :cve-tou
                               :D-FSL-1.0
                               :DEC-3-Clause
                               :diffmark
                               :DL-DE-BY-2.0
                               :DL-DE-ZERO-2.0
                               :DOC
                               :DocBook-DTD
                               :DocBook-Schema
                               :DocBook-Stylesheet
                               :DocBook-XML
                               :Dotseqn
                               :DRL-1.0
                               :DRL-1.1
                               :DSDP
                               :dtoa
                               :dvipdfm
                               :ECL-1.0
                               :ECL-2.0
                               :eCos-2.0
                               :EFL-1.0
                               :EFL-2.0
                               :eGenix
                               :Elastic-2.0
                               :Entessa
                               :EPICS
                               :EPL-1.0
                               :EPL-2.0
                               :ErlPL-1.1
                               :ESA-PL-permissive-2.4
                               :ESA-PL-strong-copyleft-2.4
                               :ESA-PL-weak-copyleft-2.4
                               :etalab-2.0
                               :EUDatagrid
                               :EUPL-1.0
                               :EUPL-1.1
                               :EUPL-1.2
                               :Eurosym
                               :Fair
                               :FBM
                               :FDK-AAC
                               :FDK-MPEG-H
                               :Ferguson-Twofish
                               :Frameworx-1.0
                               :FreeBSD-DOC
                               :FreeImage
                               :FSFAP
                               :FSFAP-no-warranty-disclaimer
                               :FSFUL
                               :FSFULLR
                               :FSFULLRSD
                               :FSFULLRWD
                               :FSL-1.1-ALv2
                               :FSL-1.1-MIT
                               :FTL
                               :Furuseth
                               :fwlw
                               :Game-Programming-Gems
                               :GCR-docs
                               :GD
                               :generic-xts
                               :GFDL-1.1
                               :GFDL-1.1-invariants-only
                               :GFDL-1.1-invariants-or-later
                               :GFDL-1.1-no-invariants-only
                               :GFDL-1.1-no-invariants-or-later
                               :GFDL-1.1-only
                               :GFDL-1.1-or-later
                               :GFDL-1.2
                               :GFDL-1.2-invariants-only
                               :GFDL-1.2-invariants-or-later
                               :GFDL-1.2-no-invariants-only
                               :GFDL-1.2-no-invariants-or-later
                               :GFDL-1.2-only
                               :GFDL-1.2-or-later
                               :GFDL-1.3
                               :GFDL-1.3-invariants-only
                               :GFDL-1.3-invariants-or-later
                               :GFDL-1.3-no-invariants-only
                               :GFDL-1.3-no-invariants-or-later
                               :GFDL-1.3-only
                               :GFDL-1.3-or-later
                               :Giftware
                               :GL2PS
                               :Glide
                               :Glulxe
                               :GLWTPL
                               :gnuplot
                               :GPL-1.0
                               :GPL-1.0+
                               :GPL-1.0-only
                               :GPL-1.0-or-later
                               :GPL-2.0
                               :GPL-2.0+
                               :GPL-2.0-only
                               :GPL-2.0-or-later
                               :GPL-2.0-with-autoconf-exception
                               :GPL-2.0-with-bison-exception
                               :GPL-2.0-with-classpath-exception
                               :GPL-2.0-with-font-exception
                               :GPL-2.0-with-GCC-exception
                               :GPL-3.0
                               :GPL-3.0+
                               :GPL-3.0-only
                               :GPL-3.0-or-later
                               :GPL-3.0-with-autoconf-exception
                               :GPL-3.0-with-GCC-exception
                               :Graphics-Gems
                               :gSOAP-1.3b
                               :gtkbook
                               :Gutmann
                               :HaskellReport
                               :HDF5
                               :hdparm
                               :HIDAPI
                               :Hippocratic-2.1
                               :Hippocratic-3.0-core
                               :HP-1986
                               :HP-1989
                               :HPND
                               :HPND-DEC
                               :HPND-doc
                               :HPND-doc-sell
                               :HPND-export-US
                               :HPND-export-US-acknowledgement
                               :HPND-export-US-modify
                               :HPND-export2-US
                               :HPND-Fenneberg-Livingston
                               :HPND-INRIA-IMAG
                               :HPND-Intel
                               :HPND-Kevlin-Henney
                               :HPND-Markus-Kuhn
                               :HPND-merchantability-variant
                               :HPND-MIT-disclaimer
                               :HPND-Netrek
                               :HPND-Pbmplus
                               :HPND-sell-MIT-disclaimer-xserver
                               :HPND-sell-regexpr
                               :HPND-sell-variant
                               :HPND-sell-variant-critical-systems
                               :HPND-sell-variant-MIT-disclaimer
                               :HPND-sell-variant-MIT-disclaimer-rev
                               :HPND-SMC
                               :HPND-UC
                               :HPND-UC-export-US
                               :HTMLTIDY
                               :hyphen-bulgarian
                               :IBM-pibs
                               :ICU
                               :IEC-Code-Components-EULA
                               :IJG
                               :IJG-short
                               :ImageMagick
                               :iMatix
                               :Imlib2
                               :Info-ZIP
                               :Informatica
                               :Inner-Net-2.0
                               :InnoSetup
                               :Intel
                               :Intel-ACPI
                               :Interbase-1.0
                               :IPA
                               :IPL-1.0
                               :ISC
                               :ISC-Veillard
                               :ISO-permission
                               :Jam
                               :JasPer-2.0
                               :jove
                               :JPL-image
                               :JPNIC
                               :JSON
                               :Kastrup
                               :Kazlib
                               :Knuth-CTAN
                               :LAL-1.2
                               :LAL-1.3
                               :Latex2e
                               :Latex2e-translated-notice
                               :Leptonica
                               :LGPL-2.0
                               :LGPL-2.0+
                               :LGPL-2.0-only
                               :LGPL-2.0-or-later
                               :LGPL-2.1
                               :LGPL-2.1+
                               :LGPL-2.1-only
                               :LGPL-2.1-or-later
                               :LGPL-3.0
                               :LGPL-3.0+
                               :LGPL-3.0-only
                               :LGPL-3.0-or-later
                               :LGPLLR
                               :Libpng
                               :libpng-1.6.35
                               :libpng-2.0
                               :libselinux-1.0
                               :libtiff
                               :libutil-David-Nugent
                               :LiLiQ-P-1.1
                               :LiLiQ-R-1.1
                               :LiLiQ-Rplus-1.1
                               :Linux-man-pages-1-para
                               :Linux-man-pages-copyleft
                               :Linux-man-pages-copyleft-2-para
                               :Linux-man-pages-copyleft-var
                               :Linux-OpenIB
                               :LOOP
                               :LPD-document
                               :LPL-1.0
                               :LPL-1.02
                               :LPPL-1.0
                               :LPPL-1.1
                               :LPPL-1.2
                               :LPPL-1.3a
                               :LPPL-1.3c
                               :lsof
                               :Lucida-Bitmap-Fonts
                               :LZMA-SDK-9.11-to-9.20
                               :LZMA-SDK-9.22
                               :Mackerras-3-Clause
                               :Mackerras-3-Clause-acknowledgment
                               :magaz
                               :mailprio
                               :MakeIndex
                               :man2html
                               :Martin-Birgmeier
                               :McPhee-slideshow
                               :metamail
                               :Minpack
                               :MIPS
                               :MirOS
                               :MIT
                               :MIT-0
                               :MIT-advertising
                               :MIT-Click
                               :MIT-CMU
                               :MIT-enna
                               :MIT-feh
                               :MIT-Festival
                               :MIT-Khronos-old
                               :MIT-Modern-Variant
                               :MIT-open-group
                               :MIT-STK
                               :MIT-testregex
                               :MIT-Wu
                               :MITNFA
                               :MMIXware
                               :MMPL-1.0.1
                               :Motosoto
                               :MPEG-SSG
                               :mpi-permissive
                               :mpich2
                               :MPL-1.0
                               :MPL-1.1
                               :MPL-2.0
                               :MPL-2.0-no-copyleft-exception
                               :mplus
                               :MS-LPL
                               :MS-PL
                               :MS-RL
                               :MTLL
                               :MulanPSL-1.0
                               :MulanPSL-2.0
                               :Multics
                               :Mup
                               :MVT-1.1
                               :NAIST-2003
                               :NASA-1.3
                               :Naumen
                               :NBPL-1.0
                               :NCBI-PD
                               :NCGL-UK-2.0
                               :NCL
                               :NCSA
                               :Net-SNMP
                               :NetCDF
                               :Newsletr
                               :NGPL
                               :ngrep
                               :NICTA-1.0
                               :NIST-PD
                               :NIST-PD-fallback
                               :NIST-PD-TNT
                               :NIST-Software
                               :NLOD-1.0
                               :NLOD-2.0
                               :NLPL
                               :Nokia
                               :NOSL
                               :Noweb
                               :NPL-1.0
                               :NPL-1.1
                               :NPOSL-3.0
                               :NRL
                               :NTIA-PD
                               :NTP
                               :NTP-0
                               :Nunit
                               :O-UDA-1.0
                               :OAR
                               :OCCT-PL
                               :OCLC-2.0
                               :ODbL-1.0
                               :ODC-By-1.0
                               :OFFIS
                               :OFL-1.0
                               :OFL-1.0-no-RFN
                               :OFL-1.0-RFN
                               :OFL-1.1
                               :OFL-1.1-no-RFN
                               :OFL-1.1-RFN
                               :OGC-1.0
                               :OGDL-Taiwan-1.0
                               :OGL-Canada-2.0
                               :OGL-UK-1.0
                               :OGL-UK-2.0
                               :OGL-UK-3.0
                               :OGTSL
                               :OLDAP-1.1
                               :OLDAP-1.2
                               :OLDAP-1.3
                               :OLDAP-1.4
                               :OLDAP-2.0
                               :OLDAP-2.0.1
                               :OLDAP-2.1
                               :OLDAP-2.2
                               :OLDAP-2.2.1
                               :OLDAP-2.2.2
                               :OLDAP-2.3
                               :OLDAP-2.4
                               :OLDAP-2.5
                               :OLDAP-2.6
                               :OLDAP-2.7
                               :OLDAP-2.8
                               :OLFL-1.3
                               :OML
                               :OpenMDW-1.0
                               :OpenPBS-2.3
                               :OpenSSL
                               :OpenSSL-standalone
                               :OpenVision
                               :OPL-1.0
                               :OPL-UK-3.0
                               :OPUBL-1.0
                               :OSC-1.0
                               :OSET-PL-2.1
                               :OSL-1.0
                               :OSL-1.1
                               :OSL-2.0
                               :OSL-2.1
                               :OSL-3.0
                               :OSSP
                               :PADL
                               :ParaType-Free-Font-1.3
                               :Parity-6.0.0
                               :Parity-7.0.0
                               :PDDL-1.0
                               :PHP-3.0
                               :PHP-3.01
                               :Pixar
                               :pkgconf
                               :Plexus
                               :pnmstitch
                               :PolyForm-Noncommercial-1.0.0
                               :PolyForm-Small-Business-1.0.0
                               :PostgreSQL
                               :PPL
                               :PSF-2.0
                               :psfrag
                               :psutils
                               :Python-2.0
                               :Python-2.0.1
                               :python-ldap
                               :Qhull
                               :QPL-1.0
                               :QPL-1.0-INRIA-2004
                               :radvd
                               :Rdisc
                               :RHeCos-1.1
                               :RPL-1.1
                               :RPL-1.5
                               :RPSL-1.0
                               :RSA-MD
                               :RSCPL
                               :Ruby
                               :Ruby-pty
                               :SAX-PD
                               :SAX-PD-2.0
                               :Saxpath
                               :SCEA
                               :SchemeReport
                               :Sendmail
                               :Sendmail-8.23
                               :Sendmail-Open-Source-1.1
                               :SGI-B-1.0
                               :SGI-B-1.1
                               :SGI-B-2.0
                               :SGI-OpenGL
                               :SGMLUG-PM
                               :SGP4
                               :SHL-0.5
                               :SHL-0.51
                               :SimPL-2.0
                               :SISSL
                               :SISSL-1.2
                               :SL
                               :Sleepycat
                               :SMAIL-GPL
                               :SMLNJ
                               :SMPPL
                               :SNIA
                               :snprintf
                               :SOFA
                               :softSurfer
                               :Soundex
                               :Spencer-86
                               :Spencer-94
                               :Spencer-99
                               :SPL-1.0
                               :ssh-keyscan
                               :SSH-OpenSSH
                               :SSH-short
                               :SSLeay-standalone
                               :SSPL-1.0
                               :StandardML-NJ
                               :SugarCRM-1.1.3
                               :SUL-1.0
                               :Sun-PPP
                               :Sun-PPP-2000
                               :SunPro
                               :SWL
                               :swrule
                               :Symlinks
                               :TAPR-OHL-1.0
                               :TCL
                               :TCP-wrappers
                               :TekHVC
                               :TermReadKey
                               :TGPPL-1.0
                               :ThirdEye
                               :threeparttable
                               :TMate
                               :TORQUE-1.1
                               :TOSL
                               :TPDL
                               :TPL-1.0
                               :TrustedQSL
                               :TTWL
                               :TTYP0
                               :TU-Berlin-1.0
                               :TU-Berlin-2.0
                               :Ubuntu-font-1.0
                               :UCAR
                               :UCL-1.0
                               :ulem
                               :UMich-Merit
                               :Unicode-3.0
                               :Unicode-DFS-2015
                               :Unicode-DFS-2016
                               :Unicode-TOU
                               :UnixCrypt
                               :Unlicense
                               :Unlicense-libtelnet
                               :Unlicense-libwhirlpool
                               :UnRAR
                               :UPL-1.0
                               :URT-RLE
                               :Vim
                               :Vixie-Cron
                               :VOSTROM
                               :VSL-1.0
                               :W3C
                               :W3C-19980720
                               :W3C-20150513
                               :w3m
                               :Watcom-1.0
                               :Widget-Workshop
                               :WordNet
                               :Wsuipa
                               :WTFNMFPL
                               :WTFPL
                               :wwl
                               :wxWindows
                               :X11
                               :X11-distribute-modifications-variant
                               :X11-no-permit-persons
                               :X11-swapped
                               :Xdebug-1.03
                               :Xerox
                               :Xfig
                               :XFree86-1.1
                               :xinetd
                               :xkeyboard-config-Zinoviev
                               :xlock
                               :Xnet
                               :xpp
                               :XSkat
                               :xzoom
                               :YPL-1.0
                               :YPL-1.1
                               :Zed
                               :Zeeff
                               :Zend-2.0
                               :Zimbra-1.3
                               :Zimbra-1.4
                               :Zlib
                               :zlib-acknowledgement
                               :ZPL-1.1
                               :ZPL-2.0
                               :ZPL-2.1
                               :389-exception
                               :Asterisk-exception
                               :Asterisk-linking-protocols-exception
                               :Autoconf-exception-2.0
                               :Autoconf-exception-3.0
                               :Autoconf-exception-generic
                               :Autoconf-exception-generic-3.0
                               :Autoconf-exception-macro
                               :Bison-exception-1.24
                               :Bison-exception-2.2
                               :Bootloader-exception
                               :CGAL-linking-exception
                               :Classpath-exception-2.0
                               :Classpath-exception-2.0-short
                               :CLISP-exception-2.0
                               :cryptsetup-OpenSSL-exception
                               :Digia-Qt-LGPL-exception-1.1
                               :DigiRule-FOSS-exception
                               :eCos-exception-2.0
                               :erlang-otp-linking-exception
                               :Fawkes-Runtime-exception
                               :FLTK-exception
                               :fmt-exception
                               :Font-exception-2.0
                               :freertos-exception-2.0
                               :GCC-exception-2.0
                               :GCC-exception-2.0-note
                               :GCC-exception-3.1
                               :Gmsh-exception
                               :GNAT-exception
                               :GNOME-examples-exception
                               :GNU-compiler-exception
                               :gnu-javamail-exception
                               :Google-Patent-WebM
                               :GPL-3.0-389-ds-base-exception
                               :GPL-3.0-interface-exception
                               :GPL-3.0-linking-exception
                               :GPL-3.0-linking-source-exception
                               :GPL-CC-1.0
                               :GStreamer-exception-2005
                               :GStreamer-exception-2008
                               :harbour-exception
                               :i2p-gpl-java-exception
                               :Independent-modules-exception
                               :KiCad-libraries-exception
                               :kvirc-openssl-exception
                               :LGPL-3.0-linking-exception
                               :libpri-OpenH323-exception
                               :Libtool-exception
                               :Linux-syscall-note
                               :LLGPL
                               :LLVM-exception
                               :LZMA-exception
                               :mif-exception
                               :mxml-exception
                               :Nokia-Qt-exception-1.1
                               :OCaml-LGPL-linking-exception
                               :OCCT-exception-1.0
                               :OpenJDK-assembly-exception-1.0
                               :openvpn-openssl-exception
                               :PCRE2-exception
                               :polyparse-exception
                               :PS-or-PDF-font-exception-20170817
                               :QPL-1.0-INRIA-2004-exception
                               :Qt-GPL-exception-1.0
                               :Qt-LGPL-exception-1.1
                               :Qwt-exception-1.0
                               :romic-exception
                               :RRDtool-FLOSS-exception-2.0
                               :rsync-linking-exception
                               :SANE-exception
                               :SHL-2.0
                               :SHL-2.1
                               :Simple-Library-Usage-exception
                               :Spelling-Provider-LGPL-exception
                               :sqlitestudio-OpenSSL-exception
                               :stunnel-exception
                               :SWI-exception
                               :Swift-exception
                               :Texinfo-exception
                               :u-boot-exception-2.0
                               :UBDL-exception
                               :Universal-FOSS-exception-1.0
                               :vsftpd-openssl-exception
                               :WxWindows-exception-3.1
                               :x11vnc-openssl-exception)))
      (dolist (id valid-licence-ids)
        (ok (typep id 'licence-id-type)
            (format nil "~S should be a valid licence-id-type" id)))))

  (testing "invalid licence-id-type values"
    (ok (not (typep :unknown-licence-id 'licence-id-type)))
    (ok (not (typep "0BSD" 'licence-id-type)))
    (ok (not (typep '0BSD 'licence-id-type)))
    (ok (not (typep nil 'licence-id-type)))))

(deftest test-property-model
  (testing "property creation and accessors"
    (let ((prop (make-instance 'property :name "sample-prop" :value "sample-value")))
      (ok (typep prop 'property))
      (ok (string= (name prop) "sample-prop"))
      (ok (string= (cl-sbom/cyclonedx-1.7:value prop) "sample-value"))))

  (testing "has-properties mixin on classes"
    (let ((c (make-instance 'component :type :library :name "lib"))
          (lic (make-instance 'license))
          (lexpr (make-instance 'license-expression))
          (meta (make-instance 'sbom-metadata)))
      (ok (typep c 'has-properties))
      (ok (typep lic 'has-properties))
      (ok (typep lexpr 'has-properties))
      (ok (typep meta 'has-properties))
      (ok (equalp (properties c) #()))
      (ok (equalp (properties lic) #()))
      (ok (equalp (properties lexpr) #()))
      (ok (equalp (properties meta) #())))))

(deftest test-has-bom-ref-mixin
  (testing "bom-ref accessors on deduplicated classes"
    (let ((addr (make-instance 'address :bom-ref "ref-addr"))
          (contact (make-instance 'organizational-contact :bom-ref "ref-contact"))
          (entity (make-instance 'organizational-entity :bom-ref "ref-entity"))
          (comp (make-instance 'component :type :application :name "app" :bom-ref "ref-comp"))
          (lic (make-instance 'license :bom-ref "ref-lic"))
          (lexpr (make-instance 'license-expression :bom-ref "ref-lexpr"))
          (expr (make-instance 'expression :license-identifier "MIT" :bom-ref "ref-expr")))
      (ok (typep addr 'has-bom-ref))
      (ok (typep contact 'has-bom-ref))
      (ok (typep entity 'has-bom-ref))
      (ok (typep comp 'has-bom-ref))
      (ok (typep lic 'has-bom-ref))
      (ok (typep lexpr 'has-bom-ref))
      (ok (typep expr 'has-bom-ref))
      (ok (string= (bom-ref addr) "ref-addr"))
      (ok (string= (bom-ref contact) "ref-contact"))
      (ok (string= (bom-ref entity) "ref-entity"))
      (ok (string= (bom-ref comp) "ref-comp"))
      (ok (string= (bom-ref lic) "ref-lic"))
      (ok (string= (bom-ref lexpr) "ref-lexpr"))
      (ok (string= (bom-ref expr) "ref-expr")))))

(deftest test-hash-and-attachment-models
  (testing "hash creation and algorithms"
    (let ((h (make-instance 'hash :alg :SHA-256 :content "abcdef")))
      (ok (eq (alg h) :SHA-256))
      (ok (string= (content h) "abcdef")))
    (let ((h-sha1 (make-instance 'hash :alg :SHA-1 :content "123456")))
      (ok (eq (alg h-sha1) :SHA-1))))

  (testing "attachment creation"
    (let ((att (make-instance 'attachment :content "license body text")))
      (ok (string= (content-type att) "text/plain"))
      (ok (null (encoding att)))
      (ok (string= (content att) "license body text")))
    (let ((att-b64 (make-instance 'attachment :content "YmFzZTY0" :encoding :base64)))
      (ok (eq (encoding att-b64) :base64)))))

(deftest test-license-and-expressions
  (testing "license instance and acknowledge method"
    (let ((lic (make-instance 'license
                              :id :MIT
                              :name "MIT License"
                              :acknowledgement :declared)))
      (ok (eq (id lic) :MIT))
      (ok (string= (name lic) "MIT License"))
      (ok (eq (acknowledgement lic) :declared))
      (ok (eq (acknowledge lic) :declared))))

  (testing "license-expression and acknowledge method"
    (let ((lexpr (make-instance 'license-expression
                                :expression "MIT OR Apache-2.0"
                                :acknowledgement :concluded)))
      (ok (string= (cl-sbom/cyclonedx-1.7:expression lexpr) "MIT OR Apache-2.0"))
      (ok (eq (acknowledgement lexpr) :concluded))
      (ok (eq (acknowledge lexpr) :concluded)))))

(deftest test-tools-and-generic-accessors
  (testing "tools object and generic accessors on tools, sbom-metadata, sbom, and nil"
    (let* ((comp (make-instance 'component :type :application :name "syft" :version "1.52.0"))
           (tool-obj (make-instance 'tools :components (vector comp)))
           (meta (make-instance 'sbom-metadata :tools tool-obj))
           (sbom-inst (make-instance 'sbom :metadata meta)))
      ;; tool-components
      (ok (= (length (tool-components tool-obj)) 1))
      (ok (= (length (tool-components meta)) 1))
      (ok (= (length (tool-components sbom-inst)) 1))
      (ok (string= (name (aref (tool-components sbom-inst) 0)) "syft"))

      ;; tool-services
      (ok (equalp (tool-services tool-obj) #()))
      (ok (equalp (tool-services meta) #()))
      (ok (equalp (tool-services sbom-inst) #()))

      ;; nil safety
      (ok (equalp (tool-components nil) #()))
      (ok (equalp (tool-services nil) #()))
      (let ((empty-meta (make-instance 'sbom-metadata))
            (empty-sbom (make-instance 'sbom)))
        (ok (equalp (tool-components empty-meta) #()))
        (ok (equalp (tool-services empty-meta) #()))
        (ok (equalp (tool-components empty-sbom) #()))
        (ok (equalp (tool-services empty-sbom) #()))))))

(deftest test-parse-sbom-json-integration
  (testing "parsing full sbom.json fixture"
    (let* ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json"))
           (sbom (cl-sbom:parse sbom-path)))
      (ok (typep sbom 'sbom))
      (ok (string= (schema sbom) "http://cyclonedx.org/schema/bom-1.7.schema.json"))
      (ok (eq (bom-format sbom) :CycloneDX))
      (ok (string= (spec-version sbom) "1.7"))
      (ok (string= (serial-number sbom) "urn:uuid:8377c553-e2d9-4f1f-9014-46f5ded34187"))
      (ok (= (version sbom) 1))

      ;; Metadata
      (let ((meta (metadata sbom)))
        (ok (typep meta 'sbom-metadata))
        (ok (string= (timestamp meta) "2026-10-10T15:22:24+01:00"))
        (ok (> (length (properties meta)) 0))

        ;; Metadata component
        (let ((root-comp (cl-sbom/cyclonedx-1.7:component meta)))
          (ok (typep root-comp 'component))
          (ok (string= (name root-comp) "dradis-app"))
          (ok (eq (component-type root-comp) :container))
          (ok (string= (bom-ref root-comp) "61289ac238cf2a58")))

        ;; Tools via generic accessor
        (let ((tools-vec (tool-components sbom)))
          (ok (= (length tools-vec) 1))
          (let ((syft (aref tools-vec 0)))
            (ok (string= (name syft) "syft"))
            (ok (string= (version syft) "1.54.0"))
            (ok (string= (author syft) "anchore"))
            (ok (eq (component-type syft) :application))))

        (ok (equalp (tool-services sbom) #())))

      ;; Components
      (let ((comps (components sbom)))
        (ok (= (length comps) 4445))

        ;; Component 0: apk-tools
        (let ((c0 (aref comps 0)))
          (ok (string= (name c0) "apk-tools"))
          (ok (string= (version c0) "2.14.10-r16"))
          (ok (eq (component-type c0) :library))
          (ok (string= (publisher c0) "wolfi"))
          (ok (string= (cpe c0) "cpe:2.3:a:apk-tools:apk-tools:2.14.10-r16:*:*:*:*:*:*:*"))
          (ok (string= (purl c0) "pkg:apk/wolfi/apk-tools@2.14.10-r16?arch=aarch64&distro=wolfi-20230201"))
          (ok (> (length (properties c0)) 0))
          (ok (= (length (licenses c0)) 1))
          (let ((lic (aref (licenses c0) 0)))
            (ok (typep lic 'license))
            (ok (eq (id lic) :GPL-2.0-only))))

        ;; Component with license expression: ca-certificates
        (let ((ca-cert (find "ca-certificates" comps :key #'name :test #'string=)))
          (ok (not (null ca-cert)))
          (ok (= (length (licenses ca-cert)) 1))
          (let ((lexpr (aref (licenses ca-cert) 0)))
            (ok (typep lexpr 'license-expression))
            (ok (string= (cl-sbom/cyclonedx-1.7:expression lexpr) "MPL-2.0 AND MIT"))))

        ;; Component with hashes: /etc/ssl/ca.cnf
        (let ((ca-cnf (find "/etc/ssl/ca.cnf" comps :key #'name :test #'string=)))
          (ok (not (null ca-cnf)))
          (let ((h-vec (hashes ca-cnf)))
            (ok (= (length h-vec) 2))
            (ok (eq (alg (aref h-vec 0)) :SHA-1))
            (ok (string= (content (aref h-vec 0)) "505fe275888ebe08b0f1c474bd395d84217bf4c8"))
            (ok (eq (alg (aref h-vec 1)) :SHA-256))
            (ok (string= (content (aref h-vec 1)) "5b6e66467de39cf6f108c55674ae90be274bde59e33cf5b5fe1313bbc5794c97"))))

        ;; Component with externalReferences: wolfi
        (let ((wolfi-comp (find "wolfi" comps :key #'name :test #'string=)))
          (ok (not (null wolfi-comp)))
          (let ((ext-vec (external-references wolfi-comp)))
            (ok (= (length ext-vec) 2))
            (let ((ext0 (aref ext-vec 0))
                  (ext1 (aref ext-vec 1)))
              (ok (eq (reference-type ext0) :issue-tracker))
              (ok (string= (url ext0) "https://github.com/wolfi-dev/os/issues"))
              (ok (eq (reference-type ext1) :website))
              (ok (string= (url ext1) "https://wolfi.dev"))))))

      ;; Dependencies
      (let ((deps (dependencies sbom)))
        (ok (= (length deps) 61))
        (let ((dep0 (aref deps 0)))
          (ok (typep dep0 'dependency))
          (ok (string= (ref dep0) "pkg:apk/wolfi/apk-tools@2.14.10-r16?arch=aarch64&distro=wolfi-20230201&package-id=bb8200af5ed698a3"))
          (ok (= (length (depends-on dep0)) 7))
          (ok (string= (aref (depends-on dep0) 0) "pkg:apk/wolfi/ca-certificates-bundle@20260909-r1?arch=aarch64&distro=wolfi-20230201&package-id=dd3b0202d2da07d9&upstream=ca-certificates"))
          (ok (equalp (provides dep0) #()))))

      ;; Top-level collections
      (ok (equalp (services sbom) #()))
      (ok (equalp (external-references sbom) #()))
      (ok (equalp (vulnerabilities sbom) #())))))

(deftest test-build-sbom-validation
  (testing "invalid or missing bomFormat signals unsupported-bom-format"
    (let ((ht (make-hash-table :test 'equal)))
      (setf (gethash "specVersion" ht) "1.7")
      ;; Missing bomFormat
      (ok (signals (build-sbom ht) 'unsupported-bom-format))
      (ok (signals (build-sbom ht) 'sbom-error))
      ;; Invalid bomFormat
      (setf (gethash "bomFormat" ht) "SPDX")
      (ok (signals (build-sbom ht) 'unsupported-bom-format))
      (handler-case (build-sbom ht)
        (unsupported-bom-format (c)
          (ok (string= (bom-format c) "SPDX"))))
      (setf (gethash "bomFormat" ht) 123)
      (ok (signals (build-sbom ht) 'unsupported-bom-format))))

  (testing "invalid or missing specVersion signals unsupported-spec-version"
    (let ((ht (make-hash-table :test 'equal)))
      (setf (gethash "bomFormat" ht) "CycloneDX")
      ;; Missing specVersion
      (ok (signals (build-sbom ht) 'unsupported-spec-version))
      (ok (signals (build-sbom ht) 'sbom-error))
      ;; Invalid specVersion
      (setf (gethash "specVersion" ht) "1.6")
      (ok (signals (build-sbom ht) 'unsupported-spec-version))
      (handler-case (build-sbom ht)
        (unsupported-spec-version (c)
          (ok (string= (spec-version c) "1.6"))))
      (setf (gethash "specVersion" ht) "2.0")
      (ok (signals (build-sbom ht) 'unsupported-spec-version))))

  (testing "valid bomFormat and specVersion succeeds"
    (let ((ht (make-hash-table :test 'equal)))
      (setf (gethash "bomFormat" ht) "CycloneDX")
      (setf (gethash "specVersion" ht) "1.7")
      (let ((res (build-sbom ht)))
        (ok (typep res 'sbom))
        (ok (eq (bom-format res) :CycloneDX))
        (ok (string= (spec-version res) "1.7"))))))

(deftest test-cyclonedx-1-7-new-enums
  (testing "valid external-reference-type values"
    (let ((valid-refs '(:vcs
                        :issue-tracker
                        :website
                        :advisories
                        :bom
                        :documentation
                        :support
                        :distribution
                        :license
                        :build-meta
                        :release-notes
                        :security-contact
                        :model-card
                        :log
                        :configuration
                        :evidence
                        :attestation
                        :threat-model
                        :other)))
      (dolist (ref-val valid-refs)
        (ok (typep ref-val 'external-reference-type)
            (format nil "~S should be a valid external-reference-type" ref-val))))
    (ok (not (typep :unknown-reference 'external-reference-type)))
    (ok (not (typep "website" 'external-reference-type)))
    (ok (not (typep nil 'external-reference-type))))

  (testing "valid severity-type values"
    (let ((valid-sevs '(:critical :high :medium :low :info :none :unknown)))
      (dolist (s valid-sevs)
        (ok (typep s 'severity-type)
            (format nil "~S should be a valid severity-type" s))))
    (ok (not (typep :extreme 'severity-type)))
    (ok (not (typep "high" 'severity-type)))
    (ok (not (typep nil 'severity-type))))

  (testing "valid score-method-type values"
    (let ((valid-methods '(:CVSSv2 :CVSSv3 :CVSSv31 :CVSSv4 :OWASP :SSVC :other)))
      (dolist (m valid-methods)
        (ok (typep m 'score-method-type)
            (format nil "~S should be a valid score-method-type" m))))
    (ok (not (typep :UNKNOWN-METHOD 'score-method-type)))
    (ok (not (typep "CVSSv3" 'score-method-type))))

  (testing "valid impact-analysis-state values"
    (let ((valid-states '(:resolved :resolved_with_pedigree :exploitable :in_triage :false_positive :not_affected)))
      (dolist (st valid-states)
        (ok (typep st 'impact-analysis-state)
            (format nil "~S should be a valid impact-analysis-state" st))))
    (ok (not (typep :unknown-state 'impact-analysis-state))))

  (testing "valid impact-analysis-justification values"
    (let ((valid-justs '(:code_not_present :code_not_reachable :requires_configuration
                         :requires_dependency :requires_environment :protected_by_compiler
                         :protected_at_runtime :protected_at_perimeter :protected_by_mitigating_control)))
      (dolist (j valid-justs)
        (ok (typep j 'impact-analysis-justification)
            (format nil "~S should be a valid impact-analysis-justification" j))))
    (ok (not (typep :not_a_justification 'impact-analysis-justification)))))

(deftest test-external-reference-model-and-builders
  (testing "external-reference model creation and slot accessors"
    (let ((ext (make-instance 'external-reference
                              :url "https://example.com/repo.git"
                              :type :vcs
                              :comment "Source code repository"
                              :hashes (vector (make-instance 'hash :alg :SHA-256 :content "abc123hash"))
                              :properties (vector (make-instance 'property :name "env" :value "prod")))))
      (ok (typep ext 'external-reference))
      (ok (typep ext 'has-properties))
      (ok (string= (url ext) "https://example.com/repo.git"))
      (ok (eq (reference-type ext) :vcs))
      (ok (string= (comment ext) "Source code repository"))
      (ok (= (length (hashes ext)) 1))
      (ok (= (length (properties ext)) 1))))

  (testing "build-external-reference and build-external-references from hash-table"
    (let ((ht (make-hash-table :test 'equal)))
      (setf (gethash "url" ht) "https://example.com/issues")
      (setf (gethash "type" ht) "issue-tracker")
      (setf (gethash "comment" ht) "Bug tracker")
      (let ((ext (build-external-reference ht)))
        (ok (typep ext 'external-reference))
        (ok (string= (url ext) "https://example.com/issues"))
        (ok (eq (reference-type ext) :issue-tracker))
        (ok (string= (comment ext) "Bug tracker"))
        (ok (equalp (hashes ext) #()))
        (ok (equalp (properties ext) #()))))

    (let ((vec (build-external-references #())))
      (ok (equalp vec #())))
    (ok (equalp (build-external-references nil) #()))))

(deftest test-dependency-model-and-builders
  (testing "dependency model creation"
    (let ((dep (make-instance 'dependency
                              :ref "pkg:npm/foo@1.0.0"
                              :depends-on #("pkg:npm/bar@1.0.0" "pkg:npm/baz@1.0.0")
                              :provides #("pkg:npm/feature@1.0.0"))))
      (ok (typep dep 'dependency))
      (ok (string= (ref dep) "pkg:npm/foo@1.0.0"))
      (ok (= (length (depends-on dep)) 2))
      (ok (= (length (provides dep)) 1))))

  (testing "build-dependency and build-dependencies"
    (let ((ht (make-hash-table :test 'equal)))
      (setf (gethash "ref" ht) "pkg:golang/app@1.0")
      (setf (gethash "dependsOn" ht) #("pkg:golang/lib1@1.0"))
      (let ((dep (build-dependency ht)))
        (ok (typep dep 'dependency))
        (ok (string= (ref dep) "pkg:golang/app@1.0"))
        (ok (= (length (depends-on dep)) 1))
        (ok (string= (aref (depends-on dep) 0) "pkg:golang/lib1@1.0"))
        (ok (equalp (provides dep) #()))))
    (ok (equalp (build-dependencies nil) #()))
    (ok (equalp (build-dependencies #()) #())))

  (testing "dependency print-object includes ref, depends-on count, and provides count"
    (let* ((dep (make-instance 'dependency
                               :ref "pkg:npm/foo@1.0.0"
                               :depends-on #("pkg:npm/bar@1.0.0" "pkg:npm/baz@1.0.0")
                               :provides #("pkg:npm/feature@1.0.0")))
           (printed (format nil "~A" dep)))
      (ok (search "Ref: pkg:npm/foo@1.0.0" printed))
      (ok (search "Depends-On: 2" printed))
      (ok (search "Provides: 1" printed)))))

(deftest test-service-model-and-builders
  (testing "service model creation and mixins"
    (let* ((child-svc (make-instance 'service :name "auth-subservice"))
           (lic (make-instance 'license :id :Apache-2.0))
           (ref (make-instance 'external-reference :url "https://auth.example.com" :type :website))
           (prop (make-instance 'property :name "tier" :value "1"))
           (provider (make-instance 'organizational-entity :name "AuthCorp"))
           (svc (make-instance 'service
                               :bom-ref "svc-123"
                               :name "auth-service"
                               :group "security"
                               :version "2.1.0"
                               :description "Authentication microservice"
                               :provider provider
                               :endpoints #("https://auth.example.com/v1" "https://auth.example.com/v2")
                               :authenticated t
                               :x-trust-boundary t
                               :trust-zone "internal"
                               :licenses (vector lic)
                               :external-references (vector ref)
                               :services (vector child-svc)
                               :properties (vector prop))))
      (ok (typep svc 'service))
      (ok (typep svc 'has-bom-ref))
      (ok (typep svc 'has-properties))
      (ok (string= (bom-ref svc) "svc-123"))
      (ok (string= (name svc) "auth-service"))
      (ok (string= (group svc) "security"))
      (ok (string= (version svc) "2.1.0"))
      (ok (string= (description svc) "Authentication microservice"))
      (ok (typep (provider svc) 'organizational-entity))
      (ok (string= (name (provider svc)) "AuthCorp"))
      (ok (= (length (endpoints svc)) 2))
      (ok (eq (authenticated svc) t))
      (ok (eq (x-trust-boundary svc) t))
      (ok (string= (trust-zone svc) "internal"))
      (ok (= (length (licenses svc)) 1))
      (ok (= (length (external-references svc)) 1))
      (ok (= (length (services svc)) 1))
      (ok (= (length (properties svc)) 1))))

  (testing "build-service and build-services from hash-table"
    (let ((ht (make-hash-table :test 'equal)))
      (setf (gethash "bom-ref" ht) "svc-456")
      (setf (gethash "name" ht) "payment-service")
      (setf (gethash "version" ht) "1.0.0")
      (setf (gethash "endpoints" ht) #("/pay"))
      (setf (gethash "authenticated" ht) t)
      (let ((svc (build-service ht)))
        (ok (typep svc 'service))
        (ok (string= (bom-ref svc) "svc-456"))
        (ok (string= (name svc) "payment-service"))
        (ok (string= (version svc) "1.0.0"))
        (ok (= (length (endpoints svc)) 1))
        (ok (eq (authenticated svc) t))
        (ok (null (provider svc)))
        (ok (equalp (licenses svc) #()))
        (ok (equalp (external-references svc) #()))
        (ok (equalp (services svc) #()))))
    (ok (equalp (build-services nil) #()))
    (ok (equalp (build-services #()) #()))))

(deftest test-vulnerability-model-and-builders
  (testing "vulnerability sub-models and builders"
    ;; Source
    (let* ((src-ht (make-hash-table :test 'equal))
           (_ (progn
                (setf (gethash "name" src-ht) "NVD")
                (setf (gethash "url" src-ht) "https://nvd.nist.gov")))
           (src (build-vulnerability-source src-ht)))
      (declare (ignore _))
      (ok (typep src 'vulnerability-source))
      (ok (string= (name src) "NVD"))
      (ok (string= (url src) "https://nvd.nist.gov")))

    ;; Reference
    (let* ((ref-ht (make-hash-table :test 'equal))
           (_ (setf (gethash "id" ref-ht) "CVE-2023-1234"))
           (vref (build-vulnerability-reference ref-ht)))
      (declare (ignore _))
      (ok (typep vref 'vulnerability-reference))
      (ok (string= (id vref) "CVE-2023-1234")))

    ;; Rating
    (let* ((rate-ht (make-hash-table :test 'equal))
           (_ (progn
                (setf (gethash "score" rate-ht) 9.8)
                (setf (gethash "severity" rate-ht) "critical")
                (setf (gethash "method" rate-ht) "CVSSv31")
                (setf (gethash "vector" rate-ht) "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                (setf (gethash "justification" rate-ht) "Remotely exploitable")))
           (rating (build-vulnerability-rating rate-ht)))
      (declare (ignore _))
      (ok (typep rating 'vulnerability-rating))
      (ok (= (score rating) 9.8))
      (ok (eq (severity rating) :critical))
      (ok (eq (score-method rating) :CVSSv31))
      (ok (string= (score-vector rating) "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
      (ok (string= (justification rating) "Remotely exploitable")))

    ;; Advisory
    (let* ((adv-ht (make-hash-table :test 'equal))
           (_ (progn
                (setf (gethash "title" adv-ht) "GHSA Advisory")
                (setf (gethash "url" adv-ht) "https://github.com/advisories/GHSA-1234")))
           (adv (build-vulnerability-advisory adv-ht)))
      (declare (ignore _))
      (ok (typep adv 'vulnerability-advisory))
      (ok (string= (title adv) "GHSA Advisory"))
      (ok (string= (url adv) "https://github.com/advisories/GHSA-1234")))

    ;; Analysis
    (let* ((ana-ht (make-hash-table :test 'equal))
           (_ (progn
                (setf (gethash "state" ana-ht) "not_affected")
                (setf (gethash "justification" ana-ht) "code_not_reachable")
                (setf (gethash "detail" ana-ht) "Vulnerable code path is never called")
                (setf (gethash "response" ana-ht) #("will_not_fix"))
                (setf (gethash "firstIssued" ana-ht) "2026-01-01T00:00:00Z")
                (setf (gethash "lastUpdated" ana-ht) "2026-01-02T00:00:00Z")))
           (analysis (build-vulnerability-analysis ana-ht)))
      (declare (ignore _))
      (ok (typep analysis 'vulnerability-analysis))
      (ok (eq (state analysis) :not_affected))
      (ok (eq (justification analysis) :code_not_reachable))
      (ok (string= (detail analysis) "Vulnerable code path is never called"))
      (ok (= (length (response analysis)) 1))
      (ok (string= (first-issued analysis) "2026-01-01T00:00:00Z"))
      (ok (string= (last-updated analysis) "2026-01-02T00:00:00Z")))

    ;; Target
    (let* ((target-ht (make-hash-table :test 'equal))
           (_ (progn
                (setf (gethash "ref" target-ht) "pkg:npm/vulnerable-pkg@1.0.0")
                (setf (gethash "versions" target-ht) #("1.0.0"))))
           (target (build-vulnerability-target target-ht)))
      (declare (ignore _))
      (ok (typep target 'vulnerability-target))
      (ok (string= (ref target) "pkg:npm/vulnerable-pkg@1.0.0"))
      (ok (= (length (versions target)) 1))))

  (testing "full vulnerability model and build-vulnerability"
    (let ((v-ht (make-hash-table :test 'equal)))
      (setf (gethash "bom-ref" v-ht) "vuln-cve-2024-9999")
      (setf (gethash "id" v-ht) "CVE-2024-9999")
      (setf (gethash "cwes" v-ht) #(79 89))
      (setf (gethash "description" v-ht) "Buffer overflow vulnerability")
      (setf (gethash "detail" v-ht) "Detailed explanation")
      (setf (gethash "recommendation" v-ht) "Upgrade to version 2.0.0")
      (setf (gethash "workaround" v-ht) "Disable affected endpoint")
      (setf (gethash "created" v-ht) "2026-02-01T10:00:00Z")
      (setf (gethash "published" v-ht) "2026-02-02T10:00:00Z")
      (setf (gethash "updated" v-ht) "2026-02-03T10:00:00Z")
      (let ((vuln (build-vulnerability v-ht)))
        (ok (typep vuln 'vulnerability))
        (ok (typep vuln 'has-bom-ref))
        (ok (typep vuln 'has-properties))
        (ok (string= (bom-ref vuln) "vuln-cve-2024-9999"))
        (ok (string= (id vuln) "CVE-2024-9999"))
        (ok (equalp (cwes vuln) #(79 89)))
        (ok (string= (description vuln) "Buffer overflow vulnerability"))
        (ok (string= (detail vuln) "Detailed explanation"))
        (ok (string= (recommendation vuln) "Upgrade to version 2.0.0"))
        (ok (string= (workaround vuln) "Disable affected endpoint"))
        (ok (string= (created vuln) "2026-02-01T10:00:00Z"))
        (ok (string= (published vuln) "2026-02-02T10:00:00Z"))
        (ok (string= (updated vuln) "2026-02-03T10:00:00Z"))
        (ok (equalp (ratings vuln) #()))
        (ok (equalp (advisories vuln) #()))
        (ok (equalp (references vuln) #()))
        (ok (equalp (affects vuln) #()))))
    (ok (equalp (build-vulnerabilities nil) #()))
    (ok (equalp (build-vulnerabilities #()) #()))))

(deftest test-cl-sbom-parse-entrypoint
  (testing "parsing sbom via cl-sbom:parse with explicit and default formats"
    (let* ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json"))
           ;; Explicit :format :cyclonedx-1.7
           (sbom-1 (cl-sbom:parse sbom-path :format :cyclonedx-1.7))
           ;; Default format
           (sbom-2 (cl-sbom:parse sbom-path))
           ;; Format :cyclonedx
           (sbom-3 (cl-sbom:parse sbom-path :format :cyclonedx)))
      (ok (typep sbom-1 'cl-sbom:sbom))
      (ok (typep sbom-2 'cl-sbom:sbom))
      (ok (typep sbom-3 'cl-sbom:sbom))
      (ok (eq (cl-sbom:bom-format sbom-1) :CycloneDX))
      (ok (string= (cl-sbom:spec-version sbom-1) "1.7"))
      (ok (= (length (cl-sbom:components sbom-1)) 4445))
      (ok (= (length (cl-sbom:dependencies sbom-1)) 61))
      (ok (equalp (cl-sbom:services sbom-1) #()))
      (ok (equalp (cl-sbom:vulnerabilities sbom-1) #()))
      (ok (equalp (cl-sbom:external-references sbom-1) #()))

      ;; Test direct accessors from cl-sbom without reaching into subpackages
      (let ((c0 (aref (cl-sbom:components sbom-1) 0)))
        (ok (string= (cl-sbom:name c0) "apk-tools"))
        (ok (string= (cl-sbom:version c0) "2.14.10-r16"))
        (ok (eq (cl-sbom:component-type c0) :library))
        (ok (string= (cl-sbom:purl c0) "pkg:apk/wolfi/apk-tools@2.14.10-r16?arch=aarch64&distro=wolfi-20230201"))
        (ok (= (length (cl-sbom:licenses c0)) 1)))

      (let ((meta (cl-sbom:metadata sbom-1)))
        (ok (typep meta 'cl-sbom:sbom-metadata))
        (ok (string= (cl-sbom:timestamp meta) "2026-10-10T15:22:24+01:00"))
        (ok (= (length (cl-sbom:tool-components sbom-1)) 1))
        (ok (equalp (cl-sbom:tool-services sbom-1) #())))

      ;; Test component print-object and describe-object
      (let* ((c0 (aref (cl-sbom:components sbom-1) 0))
             (str (format nil "~A" c0))
             (c-desc (with-output-to-string (s) (describe c0 s))))
        (ok (search "Name: apk-tools" str))
        (ok (search "Version: 2.14.10-r16" str))
        (ok (search "Type: LIBRARY" str))
        (ok (not (search "{" str)))
        (ok (search "Component: apk-tools@2.14.10-r16 (LIBRARY)" c-desc))
        (ok (search "BOM-Ref:" c-desc))
        (ok (search "PURL:" c-desc))
        (ok (search "Licenses:" c-desc)))

      ;; Test describe-object on sbom
      (let ((desc (with-output-to-string (s) (describe sbom-1 s))))
        (ok (search "CycloneDX SBOM" desc))
        (ok (search "Components:      4445" desc))
        (ok (search "Dependencies:    61 entries" desc)))))

  (testing "component print-object includes name and type without identity"
    (let* ((comp (make-instance 'cl-sbom:component :name "my-lib" :version "1.0.0" :type :library))
           (printed (format nil "~A" comp)))
      (ok (search "Name: my-lib" printed))
      (ok (search "Version: 1.0.0" printed))
      (ok (search "Type: LIBRARY" printed))
      (ok (not (search "{" printed)))))

  (testing "parsing sbom with invalid or unsupported format signals unsupported-bom-format"
    (let ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json")))
      (ok (signals (cl-sbom:parse sbom-path :format :spdx) 'cl-sbom:unsupported-bom-format))
      (ok (signals (cl-sbom:parse sbom-path :format :spdx-2.3) 'cl-sbom:unsupported-bom-format))
      (ok (signals (cl-sbom:parse sbom-path :format :unknown) 'cl-sbom:sbom-error))
      (ok (signals (cl-sbom:parse 12345) 'cl-sbom:sbom-error))
      (handler-case (cl-sbom:parse sbom-path :format :spdx)
        (cl-sbom:unsupported-bom-format (c)
          (ok (eq (cl-sbom:bom-format c) :spdx))))))

  (testing "parsing sbom from polymorphic input sources"
    (let ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json")))
      ;; String namestring path
      (let ((parsed (cl-sbom:parse (namestring sbom-path))))
        (ok (typep parsed 'cl-sbom:sbom))
        (ok (= (length (cl-sbom:components parsed)) 4445)))

      ;; Raw JSON string
      (let* ((json-text (uiop:read-file-string sbom-path))
             (parsed (cl-sbom:parse json-text)))
        (ok (typep parsed 'cl-sbom:sbom))
        (ok (= (length (cl-sbom:components parsed)) 4445)))

      ;; Open stream
      (with-open-file (s sbom-path)
        (let ((parsed (cl-sbom:parse s)))
          (ok (typep parsed 'cl-sbom:sbom))
          (ok (= (length (cl-sbom:components parsed)) 4445))))

      ;; Pre-parsed hash table (e.g. from jzon:parse)
      (let* ((table (com.inuoe.jzon:parse sbom-path))
             (parsed (cl-sbom:parse table)))
        (ok (typep parsed 'cl-sbom:sbom))
        (ok (= (length (cl-sbom:components parsed)) 4445)))

      ;; Octet vector (unsigned-byte 8)
      (let* ((octets (with-open-file (in sbom-path :element-type '(unsigned-byte 8))
                       (let ((seq (make-array (file-length in) :element-type '(unsigned-byte 8))))
                         (read-sequence seq in)
                         seq)))
             (parsed (cl-sbom:parse octets)))
        (ok (typep parsed 'cl-sbom:sbom))
        (ok (= (length (cl-sbom:components parsed)) 4445))))))

(deftest test-find-component
  (testing "finding components in sbom by bom-ref, name, and purl"
    (let* ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json"))
           (sbom (cl-sbom:parse sbom-path)))
      ;; all-components includes 4445 top-level + 1 metadata root component + 1 tool component
      (ok (= (length (cl-sbom:all-components sbom)) 4447))

      ;; Lookup by bom-ref (default key)
      (multiple-value-bind (match others count)
          (cl-sbom:find-component sbom "pkg:apk/wolfi/apk-tools@2.14.10-r16?arch=aarch64&distro=wolfi-20230201&package-id=bb8200af5ed698a3")
        (ok (typep match 'cl-sbom:component))
        (ok (string= (cl-sbom:name match) "apk-tools"))
        (ok (null others))
        (ok (= count 1)))

      ;; Lookup non-existent bom-ref
      (multiple-value-bind (match others count)
          (cl-sbom:find-component sbom "non-existent-ref")
        (ok (null match))
        (ok (null others))
        (ok (= count 0)))

      ;; Lookup by name
      (multiple-value-bind (match others count)
          (cl-sbom:find-component sbom "apk-tools" :key #'cl-sbom:name)
        (ok (typep match 'cl-sbom:component))
        (ok (string= (cl-sbom:name match) "apk-tools"))
        (ok (null others))
        (ok (= count 1)))

      ;; Lookup metadata root component by bom-ref
      (multiple-value-bind (match others count)
          (cl-sbom:find-component sbom "61289ac238cf2a58")
        (ok (typep match 'cl-sbom:component))
        (ok (string= (cl-sbom:name match) "dradis-app"))
        (ok (eq (cl-sbom:component-type match) :container))
        (ok (= count 1)))))

  (testing "multiple return values when multiple components match"
    (let* ((c1 (make-instance 'cl-sbom:component :name "shared-lib" :version "1.0.0" :type :library))
           (c2 (make-instance 'cl-sbom:component :name "shared-lib" :version "2.0.0" :type :library))
           (c3 (make-instance 'cl-sbom:component :name "other-lib" :version "0.5.0" :type :library))
           (dummy-sbom (make-instance 'cl-sbom:sbom :components (vector c1 c2 c3))))
      (setf (cl-sbom:bom-ref c1) "ref-1")
      (setf (cl-sbom:bom-ref c2) "ref-2")
      (setf (cl-sbom:bom-ref c3) "ref-3")

      ;; Multiple matches on name
      (multiple-value-bind (first others total)
          (cl-sbom:find-component dummy-sbom "shared-lib" :key #'cl-sbom:name)
        (ok (eq first c1))
        (ok (equal others (list c2)))
        (ok (= total 2)))

      ;; Substring search matching all 3
      (multiple-value-bind (first others total)
          (cl-sbom:find-component dummy-sbom "lib" :key #'cl-sbom:name :test #'search)
        (ok (eq first c1))
        (ok (equal others (list c2 c3)))
        (ok (= total 3)))

      ;; Single match by bom-ref
      (multiple-value-bind (first others total)
          (cl-sbom:find-component dummy-sbom "ref-2")
        (ok (eq first c2))
        (ok (null others))
        (ok (= total 1))))))

(deftest test-dependencies-of
  (testing "direct and transitive dependencies from sbom.json"
    (let* ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json"))
           (sbom (cl-sbom:parse sbom-path))
           (apk-ref "pkg:apk/wolfi/apk-tools@2.14.10-r16?arch=aarch64&distro=wolfi-20230201&package-id=bb8200af5ed698a3")
           (wolfi-base-ref "pkg:apk/wolfi/wolfi-base@1-r7?arch=aarch64&distro=wolfi-20230201&package-id=860ff9983d9bf8a1")
           (ca-bundle-ref "pkg:apk/wolfi/ca-certificates-bundle@20260909-r1?arch=aarch64&distro=wolfi-20230201&package-id=dd3b0202d2da07d9&upstream=ca-certificates"))

      ;; Direct dependencies of apk-tools by string ref
      (let ((deps (cl-sbom:dependencies-of sbom apk-ref)))
        (ok (= (length deps) 7))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) deps))
        (let ((names (mapcar #'cl-sbom:name deps)))
          (ok (member "ca-certificates-bundle" names :test #'string=))
          (ok (member "glibc-2.44" names :test #'string=))
          (ok (member "ld-linux-2.44" names :test #'string=))
          (ok (member "libcrypto3" names :test #'string=))
          (ok (member "libssl3" names :test #'string=))
          (ok (member "wolfi-baselayout" names :test #'string=))
          (ok (member "zlib" names :test #'string=))))

      ;; Direct dependencies by component instance
      (let* ((apk-comp (cl-sbom:find-component sbom apk-ref))
             (deps (cl-sbom:dependencies-of sbom apk-comp)))
        (ok (typep apk-comp 'cl-sbom:component))
        (ok (= (length deps) 7))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) deps)))

      ;; Transitive dependencies of wolfi-base (direct: 3, transitive: 20)
      (let ((direct (cl-sbom:dependencies-of sbom wolfi-base-ref))
            (trans (cl-sbom:dependencies-of sbom wolfi-base-ref :transitive t)))
        (ok (= (length direct) 3))
        (ok (= (length trans) 20))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) trans))
        ;; Transitive dependencies must include all direct dependencies
        (dolist (d direct)
          (ok (member d trans :test #'eq))))

      ;; Circular dependency handling (ca-certificates-bundle <-> wolfi-baselayout)
      (let ((ca-direct (cl-sbom:dependencies-of sbom ca-bundle-ref))
            (ca-trans (cl-sbom:dependencies-of sbom ca-bundle-ref :transitive t)))
        (ok (= (length ca-direct) 1))
        (ok (= (length ca-trans) 1))
        (ok (string= (cl-sbom:name (first ca-direct)) "wolfi-baselayout"))
        (ok (string= (cl-sbom:name (first ca-trans)) "wolfi-baselayout")))

      ;; Unknown / nonexistent ref returns NIL
      (ok (null (cl-sbom:dependencies-of sbom "nonexistent-ref")))
      (ok (null (cl-sbom:dependencies-of sbom "nonexistent-ref" :transitive t)))))

  (testing "synthetic sbom with unresolved component ref"
    (let* ((c1 (make-instance 'cl-sbom:component :name "app" :version "1.0.0" :type :application))
           (c2 (make-instance 'cl-sbom:component :name "dep-lib" :version "1.0.0" :type :library))
           (dep-entry (make-instance 'cl-sbom:dependency
                                     :ref "app-ref"
                                     :depends-on #("dep-ref" "dangling-external-ref")))
           (dummy-sbom (make-instance 'cl-sbom:sbom
                                      :components (vector c1 c2)
                                      :dependencies (vector dep-entry))))
      (setf (cl-sbom:bom-ref c1) "app-ref")
      (setf (cl-sbom:bom-ref c2) "dep-ref")

      ;; Direct dependencies resolves c2 to component, and keeps dangling-external-ref as string
      (let ((deps (cl-sbom:dependencies-of dummy-sbom c1)))
        (ok (= (length deps) 2))
        (ok (eq (first deps) c2))
        (ok (string= (second deps) "dangling-external-ref")))

      ;; Ref string works as well
      (let ((deps (cl-sbom:dependencies-of dummy-sbom "app-ref")))
        (ok (= (length deps) 2))
        (ok (eq (first deps) c2))
        (ok (string= (second deps) "dangling-external-ref"))))))

(deftest test-dependents-of
  (testing "direct and transitive dependents (blast radius) from sbom.json"
    (let* ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json"))
           (sbom (cl-sbom:parse sbom-path))
           (z-ref "pkg:apk/wolfi/zlib@1.3.2.1_rc20260601-r0?arch=aarch64&distro=wolfi-20230201&package-id=50a856ba27cac15a")
           (wolfi-base-ref "pkg:apk/wolfi/wolfi-base@1-r7?arch=aarch64&distro=wolfi-20230201&package-id=860ff9983d9bf8a1")
           (ca-bundle-ref "pkg:apk/wolfi/ca-certificates-bundle@20260909-r1?arch=aarch64&distro=wolfi-20230201&package-id=dd3b0202d2da07d9&upstream=ca-certificates"))

      ;; Direct dependents of zlib by string ref (6 packages)
      (let ((dependents (cl-sbom:dependents-of sbom z-ref)))
        (ok (= (length dependents) 6))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) dependents))
        (let ((names (mapcar #'cl-sbom:name dependents)))
          (ok (member "apk-tools" names :test #'string=))
          (ok (member "binutils" names :test #'string=))
          (ok (member "curl" names :test #'string=))
          (ok (member "gcc" names :test #'string=))
          (ok (member "git" names :test #'string=))
          (ok (member "libcurl-openssl4" names :test #'string=))))

      ;; Direct dependents by component instance
      (let* ((z-comp (cl-sbom:find-component sbom z-ref))
             (dependents (cl-sbom:dependents-of sbom z-comp)))
        (ok (typep z-comp 'cl-sbom:component))
        (ok (= (length dependents) 6))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) dependents)))

      ;; Transitive dependents of zlib (direct: 6, transitive: 7, adds wolfi-base via apk-tools)
      (let ((direct (cl-sbom:dependents-of sbom z-ref))
            (trans (cl-sbom:dependents-of sbom z-ref :transitive t)))
        (ok (= (length direct) 6))
        (ok (= (length trans) 7))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) trans))
        ;; Transitive dependents include all direct dependents
        (dolist (d direct)
          (ok (member d trans :test #'eq)))
        ;; And wolfi-base is included as indirect dependent
        (ok (member "wolfi-base" (mapcar #'cl-sbom:name trans) :test #'string=)))

      ;; Component with no dependents returns NIL
      (ok (null (cl-sbom:dependents-of sbom wolfi-base-ref)))
      (ok (null (cl-sbom:dependents-of sbom wolfi-base-ref :transitive t)))

      ;; Circular dependency handling (ca-certificates-bundle <-> wolfi-baselayout)
      (let ((ca-direct (cl-sbom:dependents-of sbom ca-bundle-ref))
            (ca-trans (cl-sbom:dependents-of sbom ca-bundle-ref :transitive t)))
        (ok (plusp (length ca-direct)))
        (ok (plusp (length ca-trans))))

      ;; Unknown / nonexistent ref returns NIL
      (ok (null (cl-sbom:dependents-of sbom "nonexistent-ref")))
      (ok (null (cl-sbom:dependents-of sbom "nonexistent-ref" :transitive t)))))

  (testing "synthetic sbom with dangling dependent ref"
    (let* ((c1 (make-instance 'cl-sbom:component :name "app" :version "1.0.0" :type :application))
           (dep-entry (make-instance 'cl-sbom:dependency
                                     :ref "dangling-parent-ref"
                                     :depends-on #("app-ref")))
           (dummy-sbom (make-instance 'cl-sbom:sbom
                                      :components (vector c1)
                                      :dependencies (vector dep-entry))))
      (setf (cl-sbom:bom-ref c1) "app-ref")

      ;; Direct dependents returns the dangling-parent-ref as string
      (let ((deps (cl-sbom:dependents-of dummy-sbom c1)))
        (ok (= (length deps) 1))
        (ok (string= (first deps) "dangling-parent-ref"))))))

(deftest test-relationships-of
  (testing "direct and transitive relationships from sbom.json"
    (let* ((sbom-path (asdf:system-relative-pathname :cl-sbom "sbom.json"))
           (sbom (cl-sbom:parse sbom-path))
           (z-ref "pkg:apk/wolfi/zlib@1.3.2.1_rc20260601-r0?arch=aarch64&distro=wolfi-20230201&package-id=50a856ba27cac15a"))

      ;; Direct relationships by bom-ref string
      (multiple-value-bind (deps parents)
          (cl-sbom:relationships-of sbom z-ref)
        (ok (= (length deps) 3))
        (ok (= (length parents) 6))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) deps))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) parents)))

      ;; Direct relationships by component instance
      (let ((z-comp (cl-sbom:find-component sbom z-ref)))
        (ok (typep z-comp 'cl-sbom:component))
        (multiple-value-bind (deps parents)
            (cl-sbom:relationships-of sbom z-comp)
          (ok (= (length deps) 3))
          (ok (= (length parents) 6))))

      ;; Transitive relationships
      (multiple-value-bind (deps parents)
          (cl-sbom:relationships-of sbom z-ref :transitive t)
        (ok (= (length deps) 6))
        (ok (= (length parents) 7))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) deps))
        (ok (every (lambda (c) (typep c 'cl-sbom:component)) parents)))

      ;; Unknown ref returns (values nil nil)
      (multiple-value-bind (deps parents)
          (cl-sbom:relationships-of sbom "nonexistent-ref")
        (ok (null deps))
        (ok (null parents)))

      ;; NIL input returns (values nil nil)
      (multiple-value-bind (deps parents)
          (cl-sbom:relationships-of sbom nil)
        (ok (null deps))
        (ok (null parents))))))








