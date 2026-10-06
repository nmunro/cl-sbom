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
                #:licence-id-type)
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
                #:unsupported-spec-version))
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
      (ok (string= (serial-number sbom) "urn:uuid:574fba47-c836-413f-9f0d-444c117bad26"))
      (ok (= (version sbom) 1))

      ;; Metadata
      (let ((meta (metadata sbom)))
        (ok (typep meta 'sbom-metadata))
        (ok (string= (timestamp meta) "2026-09-22T22:10:41+01:00"))
        (ok (> (length (properties meta)) 0))

        ;; Metadata component
        (let ((root-comp (cl-sbom/cyclonedx-1.7:component meta)))
          (ok (typep root-comp 'component))
          (ok (string= (name root-comp) "dradis-app-prod"))
          (ok (eq (component-type root-comp) :container))
          (ok (string= (bom-ref root-comp) "6d3f2bf143208b05")))

        ;; Tools via generic accessor
        (let ((tools-vec (tool-components sbom)))
          (ok (= (length tools-vec) 1))
          (let ((syft (aref tools-vec 0)))
            (ok (string= (name syft) "syft"))
            (ok (string= (version syft) "1.52.0"))
            (ok (string= (author syft) "anchore"))
            (ok (eq (component-type syft) :application))))

        (ok (equalp (tool-services sbom) #())))

      ;; Components
      (let ((comps (components sbom)))
        (ok (= (length comps) 703))

        ;; Component 0: apk-tools
        (let ((c0 (aref comps 0)))
          (ok (string= (name c0) "apk-tools"))
          (ok (string= (version c0) "2.14.10-r14"))
          (ok (eq (component-type c0) :library))
          (ok (string= (publisher c0) "wolfi"))
          (ok (string= (cpe c0) "cpe:2.3:a:apk-tools:apk-tools:2.14.10-r14:*:*:*:*:*:*:*"))
          (ok (string= (purl c0) "pkg:apk/wolfi/apk-tools@2.14.10-r14?arch=aarch64&distro=wolfi-20230201"))
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
            (ok (string= (content (aref h-vec 1)) "5b6e66467de39cf6f108c55674ae90be274bde59e33cf5b5fe1313bbc5794c97"))))))))

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

