;;;
;;; resolv.scm - resolver (see RFC 1034, 1035 and so on.)
;;;
;;;   Copyright (c) 2012 Yoshiyuki Asaba, All rights reserved.
;;; 
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;; 
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;
;;;   3. Neither the name of the authors nor the names of its contributors
;;;      may be used to endorse or promote products derived from this
;;;      software without specific prior written permission.
;;;
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;


(define-module dns.resolv
  (use binary.pack)
  (use gauche.net)
  (use gauche.regexp)
  (use file.util)
  (use math.mt-random)
  
  (export <dns-message> <resource-record> <a-record> <ns-record>
	  <soa-record> <cname-record> <mx-record> <hinfo-record>
	  <resolver>
	  <dns-message-error> <resolver-error> <nxdomain-error>
	  <query-format-error> <server-failure-error>
	  <not-implemented-error> <refused-error> <other-resolver-error>
	  <resolver-io-error> <resolver-timeout-error>

	  ;; resource record constant value
	  RR:A RR:NS RR:CNAME RR:SOA RR:PTR RR:HINFO RR:MX RR:ANY

	  ;; rcode constant value
	  NOERROR FORMATERROR SERFFAIL NXDOMAIN NOTIMPLE REFUSED

	  ;; resolv function
	  resolv:name->address resolv:address->name
	  resolv:get-resource-records resolv:get-dns-message
	  call-with-message-body

	  ;; <resolver> method
	  resolver-server resolver-port resolver-protocol
	  resolver-timeout resolver-retry

	  ;; <dns-message> method
	  dns-message-id dns-message-opcode dns-message-rcode
	  dns-message-authoritative-answer? dns-message-trancation?
	  dns-message-recursive-available?
	  dns-message-qdcount dns-message-ancount dns-message-nscount
	  dns-message-arcount dns-message-question-section
	  dns-message-answer-section dns-message-authority-section
	  dns-message-additional-section

	  ;; <resource-record> method
	  resource-record-name resource-record-type resource-record-class
	  resource-record-ttl

	  ;; <a-record> method
	  a-address

	  ;; <soa-record> method
	  soa-master-name soa-rname soa-serial soa-refresh
	  soa-retry soa-expire soa-minimum
	  
	  ;; <cname-record> method
	  cname-cname
	  
	  ;; <mx-record> method
	  mx-preference mx-exchange
	  
	  ;; <ns-record> method
	  ns-nsdname

	  ;; <ptr-record> method
	  ptr-ptrdname

	  ;; <hinfo-record> method
	  hinfo-os hinfo-cpu

	  ;; condition predicate
	  resolver-error? nxdomain-error? dns-message-error?
	  query-format-error? server-failure-error?
	  not-implemented-error? refused-error? resolver-others-error?
	  resolver-io-error? resolver-timeout-error?
	  )
  )

(select-module dns.resolv)

(define-class <resolver> ()
  ((server :init-value '() :getter resolver-server)
   (port :init-value 53 :init-keyword :port :getter resolver-port)
   (protocol :init-value SOCK_DGRAM :init-keyword :protocol)
   (read-config? :init-value #t :init-keyword :read-config?)
   (config-file :init-value "/etc/resolv.conf")
   (timeout :init-value 5 :init-keyword :timeout :getter resolver-timeout)
   (retry :init-value 2 :init-keyword :retry :getter resolver-retry)
   (random-seed :init-form (make <mersenne-twister> :seed (sys-time)))))
  

(define-method initialize ((resolver <resolver>) initargs)
  (next-method)
  (let ((protocol (get-keyword :protocol initargs #f))
	(server (get-keyword :server initargs #f))
	(config-file (get-keyword :config-file initargs #f))
	(timeout (get-keyword :timeout initargs #f))
	(retry (get-keyword :retry initargs #f)))
    (if config-file
	(slot-set! resolver 'config-file config-file))

    (if (slot-ref resolver 'read-config?)
	(read-config resolver))

    (if (null? (slot-ref resolver 'server))
	(slot-set! resolver 'server '(127.0.0.1)))

    (if protocol
	(case protocol
	  ((udp) (slot-set! resolver 'protocol SOCK_DGRAM))
	  ((tcp) (slot-set! resolver 'protocol SOCK_STREAM))
	  (else
	   (raise (condition
		   (<resolver-error>
		    (message #`"unknown protocol: ,protocol")))))))
    (if server
	(begin
	  (cond ((is-a? server <string>)
		 (slot-set! resolver 'server (list server)))
		((is-a? server <pair>)
		 (if (null? server)
		     (slot-set! resolver 'server '("127.0.0.1"))
		     (slot-set! resolver 'server server))))))

    (if timeout
	(if (and (is-a? timeout <integer>) (>= timeout 0))
	    (slot-set! resolver 'timeout timeout)
	    (raise (condition
		    (<resolver-error>
		     (message #`"invalid timeout parameter: ,timeout"))))))

    (if retry
	(if (and (is-a? retry <integer>) (>= retry 0))
	    (slot-set! resolver 'retry retry)
	    (raise (condition
		    (<resolver-error>
		     (message #`"invalid retry parameter: ,retry"))))))))


(define-method resolver-protocol ((resolver <resolver>))
  (let ((protocol (slot-ref resolver 'protocol)))
    (cond ((= protocol SOCK_STREAM)
	   'tcp)
	  ((= protocol SOCK_DGRAM)
	   'udp)
	  (else
	   (raise (condition
		   (<resolver-error>
		    (message "unrecognized protocol"))))))))
     

(define-class <dns-message> ()
   ; 16 bit id
  ((id :getter dns-message-id)

   ; message is a query(0), or a response(1)
   qr

   ; operation code
   (opcode :getter dns-message-opcode)

   ; authritative answer bit
   (authoritative-answer :getter dns-message-authoritative-answer?)

   ; truncation bit
   (truncation :getter dns-message-trancation?)

   ; recursion desired
   rd

   ; recursion avaliable
   (recursive-available :getter dns-message-recursive-available?)

   ; reserved for future use.
   z

   ; response code
   (rcode :getter dns-message-rcode)

   ; number of records in question section
   (qdcount :init-value 0 :getter dns-message-qdcount)

   ; number of records in answer section
   (ancount :init-value 0 :getter dns-message-ancount)

   ; number of NS resource records in authority section
   (nscount :init-value 0 :getter dns-message-nscount)

   ; number of records in additional section
   (arcount :init-value 0 :getter dns-message-arcount)

   (question-section :init-value '() :getter dns-message-question-section)
   (answer-section :init-value '() :getter dns-message-answer-section)
   (authority-section :init-value '() :getter dns-message-authority-section)
   (additional-section :init-value '() :getter dns-message-additional-section)

   (offset-index :init-value 0) ; do not edit the value
   (buffer-input-port)
   (offset-table :init-form (make-hash-table)) ; offset (hash) table
                                               ; key is offset index
                                               ; value is label with length
))

(define-method initialize ((message <dns-message>) initargs)
  (next-method)
  (slot-set! message 'offset-table (make-hash-table))
  )


(define-condition-type <resolver-error> <error>
  resolver-error?)

(define-condition-type <query-format-error> <resolver-error>
  query-format-error?)

(define-condition-type <server-failure-error> <resolver-error>
  server-failure-error?)

(define-condition-type <nxdomain-error> <resolver-error>
  nxdomain-error?
  (dns-message dns-message))

(define-condition-type <not-implemented-error> <resolver-error>
  not-implemented-error?)

(define-condition-type <refused-error> <resolver-error>
  refused-error?)

(define-condition-type <other-resolver-error> <resolver-error>
  other-resolver-error?)

(define-condition-type <resolver-io-error> <resolver-error>
  resolver-io-error?)

(define-condition-type <resolver-timeout-error> <resolver-error>
  resolver-timeout-error?)

(define-constant RR:A 1)
(define-constant RR:NS 2)
(define-constant RR:CNAME 5)
(define-constant RR:SOA 6)
(define-constant RR:PTR 12)
(define-constant RR:HINFO 13)
(define-constant RR:MX 15)
(define-constant RR:ANY 255)

;; RCODE constant
(define-constant NOERROR 0)
(define-constant FORMATERROR 1)
(define-constant SERVFAIL 2)
(define-constant NXDOMAIN 3)
(define-constant NOTIMPLE 4)
(define-constant REFUSED 5)

;;;
;;; Resource Record
;;;

(define-class <resource-record> ()
  ((name :getter resource-record-name)
   (type :getter resource-record-type)
   (class :getter resource-record-class)
   (ttl :getter resource-record-ttl)
   rdlength
   ))


;;;
;;;  A Record
;;;
(define-class <a-record> (<resource-record>)
  ((address :getter a-address)))

(define-method decode-rdata ((rdata <a-record>) message)
  (let* ((data (read-block-from-message 4 message))
	 (address (unpack "CCCC" :from-string data)))
    (slot-set! rdata 'address
	       (string-join (map (lambda (label) (format #f "~s" label))
				 address)
			    "."))))

;;;
;;;  SOA Record
;;;

(define-class <soa-record> (<resource-record>)
  ((master-name :getter soa-master-name)
   (rname :getter soa-rname)
   (serial :getter soa-serial)
   (refresh :getter soa-refresh)
   (retry :getter soa-retry)
   (expire :getter soa-expire)
   (minimum :getter soa-minimum)
   ))

(define-method decode-rdata ((rdata <soa-record>) message)
  (let* ((mname (recv-name message))
	 (rname (recv-name message))
	 (serial (car (unpack "N" :from-string
			      (read-block-from-message 4 message))))
	 (refresh (car (unpack "N" :from-string
			      (read-block-from-message 4 message))))
	 (retry (car (unpack "N" :from-string
			      (read-block-from-message 4 message))))
	 (expire (car (unpack "N" :from-string
			      (read-block-from-message 4 message))))
	 (minimum (car (unpack "N" :from-string
			      (read-block-from-message 4 message)))))
    (slot-set! rdata 'master-name (qname->string
				   (string-incomplete->complete mname)))
    (slot-set! rdata 'rname (qname->string
			     (string-incomplete->complete rname)))
    (slot-set! rdata 'serial serial)
    (slot-set! rdata 'refresh refresh)
    (slot-set! rdata 'retry retry)
    (slot-set! rdata 'expire expire)
    (slot-set! rdata 'minimum minimum)))

;;;
;;;  CNAME Record
;;;

(define-class <cname-record> (<resource-record>)
  (cname :getter cname-cname)
  )

(define-method decode-rdata ((rdata <cname-record>) message)
  (let ((name (recv-name message)))
    (slot-set! rdata 'cname
	       (qname->string (string-incomplete->complete name)))))

;;;
;;;  MX Record
;;;

(define-class <mx-record> (<resource-record>)
  ((preference :getter mx-preference)
   (exchange :getter mx-exchange)))

(define-method decode-rdata ((rdata <mx-record>) message)
  (let* ((data (read-block-from-message 2 message))
	 (preference (car (unpack "n" :from-string data)))
	 (exchange (recv-name message)))
    (slot-set! rdata 'preference preference)
    (slot-set! rdata 'exchange
	       (qname->string (string-incomplete->complete exchange)))))


;;;
;;; NS Record
;;;

(define-class <ns-record> (<resource-record>)
  (nsdname :getter ns-nsdname))

(define-method decode-rdata ((rdata <ns-record>) message)
  (let ((name (recv-name message)))
    (slot-set! rdata 'nsdname
	       (qname->string (string-incomplete->complete name)))
  ))


;;;
;;;  PTR Record
;;;

(define-class <ptr-record> (<resource-record>)
  (ptrdname :getter ptr-ptrdname))

(define-method decode-rdata ((rdata <ptr-record>) message)
  (slot-set! rdata 'ptrdname (qname->string
			      (string-incomplete->complete
			       (recv-name message)))))

;;;
;;;  HINFO Record
;;;

(define-class <hinfo-record> (<resource-record>)
  ((cpu :getter hinfo-cpu)
   (os :getter hinfo-os)))

(define-method decode-rdata ((rdata <hinfo-record>) message)
  (let* ((cpulen (read-byte-from-message message))
	 (cpu (read-block-from-message cpulen message))
	 (oslen (read-byte-from-message message))
	 (os (read-block-from-message oslen message)))
    (slot-set! rdata 'cpu (string-incomplete->complete cpu))
    (slot-set! rdata 'os (string-incomplete->complete os))))


(define (read-block-from-message len message)
  (let ((iport (slot-ref message 'buffer-input-port)))
    (guard (exc
	    ((condition-has-type? exc <system-error>)
	     (raise (condition
		     (<resolver-io-error>
		      (message "read-block-from-message failure"))))))
	   (slot-set! message 'offset-index
		      (+ (slot-ref message 'offset-index) len))
	   (read-block len iport))))

(define (read-byte-from-message message)
  (let ((iport (slot-ref message 'buffer-input-port)))
    (guard (exc
	    ((condition-has-type? exc <system-error>)
	     (raise (condition
		     (<resolver-io-error>
		      (message "read-byte-from-message failure"))))))
	   (slot-set! message 'offset-index
		      (+ (slot-ref message 'offset-index) 1))
	   (read-byte iport))))

(define-constant resource-record-table
  (let ((table (make-hash-table)))
    (hash-table-put! table RR:A (lambda () (make <a-record>)))
    (hash-table-put! table RR:NS (lambda () (make <ns-record>)))
    (hash-table-put! table RR:CNAME (lambda () (make <cname-record>)))
    (hash-table-put! table RR:SOA (lambda () (make <soa-record>)))
    (hash-table-put! table RR:PTR (lambda () (make <ptr-record>)))
    (hash-table-put! table RR:HINFO (lambda () (make <hinfo-record>)))
    (hash-table-put! table RR:MX (lambda () (make <mx-record>)))
    table))

(define (read-config resolver)
  (let ((config-file (slot-ref resolver 'config-file)))
    (if (file-is-readable? config-file)
	(begin
	  (call-with-input-file config-file
	    (lambda (iport)
	      (let ((lines (port->string-list iport)))
		(for-each
		 (lambda (line)
		   (let* ((line-nocomment
			   (regexp-replace #/#.*/ line ""))
			  (item (string-split line-nocomment #/\s+/)))
		     (if (>= (length item) 2)
			 (begin
			   (let ((var (car item))
				 (vals (cdr item)))
			     (cond ((string=? var "nameserver")
				    (slot-set! resolver 'server
					       (append
						(slot-ref resolver 'server)
						vals)))))))))
		 lines))))))
    #f))

;; convert "www.foo.bar.jp" to "\03www\03foo\03bar\02jp\0"
;; if last character is not ".", add #\.
(define (string->qname name)
  (if (string=? name ".") "\0"
      (begin
	(let ((labels (string-split
		       (if (char=? (string-ref name
					       (- (string-length name) 1))
				   #\.)
			   name
			   (string-append name "."))
		       ".")))
	  (fold-right string-append
		      ""
		      (map (lambda (label)
			     (string-append
			      (string (integer->char (string-length label)))
			      label))
			   labels))))))

;; convert "11.22.33.44" to "44.33.22.11.in-addr.arpa".
(define (string->ptrname name)
  (let ((labels (string-split
		 name
		 ".")))
    (string-append (string-join (reverse labels) ".")
		   ".in-addr.arpa.")))
		 

(define (qname->string qname)
  (define (qname->string-inner qname result)
    (let ((i (char->integer (string-ref qname 0)))
	  (len (string-length qname)))
      (cond ((= i 0) result)
	    ((> i len) result)
	    (else
	     (qname->string-inner
	      (substring
	       qname
	       (+ i 1)
	       len)
	      (string-append result
			     (substring qname
					1
					(+ i 1))
			     "."
			     ))))))
  (if (string=? qname "\0")
      "."
      (qname->string-inner qname "")))

(define (with-udp-server server port proc)
  (let* ((sock (make-socket AF_INET SOCK_DGRAM))
	 (addr (car (make-sockaddrs server port))))
    (dynamic-wind
	(lambda () #f)
	(lambda () (proc sock addr))
	(lambda () (socket-close sock)))))

(define (with-tcp-server server port proc)
  (let* ((sock (make-socket AF_INET SOCK_STREAM))
	 (addr (car (make-sockaddrs server port)))
	 (conn (socket-connect sock addr)))
    (dynamic-wind
	(lambda () #f)
	(lambda () (proc sock))
	(lambda () (socket-close sock)))))


(define (send-query resolver name type)
  (let* ((header (make-header (mt-random-integer
			       (slot-ref resolver 'random-seed)
			       65535)
			      1 1))
	 (qname (if (= type RR:PTR)
		    (string->qname (string->ptrname name))
		    (string->qname name)))
	 (query (make-query header qname type 1))
	 (timeout (slot-ref resolver 'timeout))
	 (servers (slot-ref resolver 'server))
	 (num_servers (length servers)))
    
    (define (send-query-udp server query cont)
      (with-udp-server server (slot-ref resolver 'port)
		       (lambda (sock addr)
			 (socket-sendto
			  sock
			  query
			  addr)
			 (cont
			  (recv-response resolver sock timeout)))))

    (define (send-query-tcp server query cont)
      (let ((len (pack "n" (list (string-length query)) :to-string? #t)))
	(with-tcp-server server (slot-ref resolver 'port)
			 (lambda (sock)
			   (socket-send
			    sock
			    (string-append len query))
			   (cont
			    (recv-response resolver sock timeout))))))

    (define (loop count timeout continuation)
      (if (<= count 0)
	  (raise
	   (condition
	    (<resolver-timeout-error>
	     (message "connection timeout"))))
	  (begin
	    (for-each
	     (lambda (server)
	       (guard (exc
		       ((condition-has-type? exc <resolver-io-error>)
			#f)
		       ((condition-has-type? exc <system-error>)
			#f)
		       ((condition-has-type? exc <resolver-timeout-error>)
			#f))
		      
		      (if (= (slot-ref resolver 'protocol)
			     SOCK_STREAM)
			  (send-query-tcp server query continuation)
			  (send-query-udp server query continuation))))
	     servers)
	    (loop (- count 1) (* timeout 2) continuation))))

    (call/cc
     (lambda (cont)
       (loop (slot-ref resolver 'retry)
	     (quotient timeout num_servers)
	     cont)))))

(define (make-query header qname qtype qclass)
  (string-append header qname
		 (pack "nn" (list qtype qclass) :to-string? #t)))

(define (recv-response-udp socket)
  (receive (msg from)
	   (socket-recvfrom socket 512)
	   msg))

(define (recv-response-tcp socket)
  (let ((len (car (unpack "n" :from-string (socket-recv socket 2)))))
    (data (socket-recv socket len))))

(define (recv-response resolver socket timeout)
  (guard (exc
	  ((condition-has-type? exc <system-error>)
	   (raise (condition
		   (<resolver-io-error>
		    (message "read-block failure"))))))

	 (let ((fdset (make <sys-fdset>)))
	   (sys-fdset-set! fdset (socket-fd socket) #t)
	   (receive (nfds rfds wfds efds)
		    (sys-select! fdset #f #f
				(list timeout 0))
		    (if (= nfds 0)
			(raise
			 (condition
			  (<resolver-timeout-error>
			   (message "timeout error"))))
			(let* ((data ((if (= (slot-ref resolver 'protocol)
					     SOCK_STREAM)
					  recv-response-tcp
					  recv-response-udp)
				      socket))
			       (string-iport (open-input-string data))
			       (message (make <dns-message>)))
			  (slot-set! message 'buffer-input-port string-iport)
			  (dynamic-wind
			      (lambda () #f)
			      (lambda ()
				(recv-response-header message)
				(recv-response-body message))
			      (lambda () (close-input-port string-iport)))))))))

(define (recv-response-header message)
  (let* ((id (car (unpack "n" :from-string
			  (read-block-from-message 2 message))))
	 (data (car (unpack "n" :from-string
			    (read-block-from-message 2 message))))
	 (qr (logand 1 (ash data -15)))
	 (opcode (logand 15 (ash data -11)))
	 (aa (logand 1 (ash data -10)))
	 (tc (logand 1 (ash data -9)))
	 (rd (logand 1 (ash data -8)))
	 (ra (logand 1 (ash data -7)))
	 (z (logand 15 (ash data -4)))
	 (rcode (logand 15 data))
	 (qdcount (car (unpack "n" :from-string
			       (read-block-from-message 2 message))))
	 (ancount (car (unpack "n" :from-string
			       (read-block-from-message 2 message))))
	 (nscount (car (unpack "n" :from-string
			       (read-block-from-message 2 message))))
	 (arcount (car (unpack "n" :from-string
			       (read-block-from-message 2 message)))))


    (slot-set! message 'id id)
    (slot-set! message 'qr qr)
    (slot-set! message 'opcode opcode)
    (slot-set! message 'authoritative-answer (= aa 1))
    (slot-set! message 'truncation (= tc 1))
    (slot-set! message 'rd (= rd 1))
    (slot-set! message 'recursive-available (= ra 1))
    (slot-set! message 'z z)
    (slot-set! message 'rcode rcode)
    (slot-set! message 'qdcount qdcount)
    (slot-set! message 'ancount ancount)
    (slot-set! message 'nscount nscount)
    (slot-set! message 'arcount arcount)
))

(define (recv-response-body message)
  (define (loop count result proc)
    (if (> count 0)
	(loop (- count 1) (cons (proc message) result)
	      proc)
	(reverse result)))

  (let ((qdcount (slot-ref message 'qdcount))
	(ancount (slot-ref message 'ancount))
	(nscount (slot-ref message 'nscount))
	(arcount (slot-ref message 'arcount))
	(rcode (slot-ref message 'rcode)))

    (slot-set! message 'question-section (loop qdcount '() recv-question ))
    (slot-set! message 'answer-section (loop ancount '() recv-resource-record))
    (slot-set! message 'authority-section (loop nscount '() recv-resource-record))
    (slot-set! message 'additional-section (loop arcount '() recv-resource-record))
  
    (cond ((= rcode NOERROR) message)
	  ((= rcode FORMATERROR)
	   (raise (condition
		   (<nxdomain-error>
		    (dns-message message)
		    (message "name is not exist")))))
	  ((= rcode SERVFAIL)
	   (raise (condition
		   (<server-failure-error>
		    (message "server failure")))))
	  ((= rcode NXDOMAIN)
	   (raise (condition
		   (<nxdomain-error>
		    (message "name does not exist")))))
	  ((= rcode NOTIMPLE)
	   (raise (condition
		   (<not-implemented-error>
		    (message "name server does not support the request")))))
	  ((= rcode REFUSED)
	   (raise (condition
		   (<refused-error>
		    (message "name server refuses your request")))))
	  (else
	   (raise (condition
		   (<other-resolver-error>
		    (message #`"other error: ,rcode"))))))))
	  
(define (recv-question message)
  (let* ((name (recv-name message))
	 (qtype (car (unpack "n" :from-string
			     (read-block-from-message 2 message))))
	 (qclass (car (unpack "n" :from-string
			      (read-block-from-message 2 message)))))
    (list (qname->string (string-incomplete->complete name)) qtype qclass)))

(define (recv-resource-record message)
  (let* ((name (recv-name message))
	 (type (car (unpack "n" :from-string
			    (read-block-from-message 2 message))))
	 (class (car (unpack "n" :from-string
			     (read-block-from-message 2 message))))
	 (ttl (car (unpack "N" :from-string
			   (read-block-from-message 4 message))))
	 (rdlength (car (unpack "n" :from-string
				(read-block-from-message 2 message))))
	 )
    
    (if (hash-table-exists? resource-record-table type)
	(let ((record ((hash-table-get resource-record-table type))))
	  (slot-set! record 'name (qname->string (string-incomplete->complete name)))
	  (slot-set! record 'type type)
	  (slot-set! record 'class class)
	  (slot-set! record 'ttl ttl)
	  (slot-set! record 'rdlength rdlength)
	  (decode-rdata record message)
	  record)
	(raise (condition
		(<dns-message-error>
		 (message "unrecognized type")))))
  ))

(define (recv-name message)
  (define (recv-name-in result)
    (let ((len (read-byte-from-message message)))
      (cond ((eof-object? len) (raise (condition
				       (<dns-message-error>
					(message "name is not valid")))))
	    ((= len 0)
	     (hash-table-put! (slot-ref message 'offset-table)
			      (- (slot-ref message 'offset-index) 1)
			      "\0")
	     (string-append result "\0"))
	    ((= (logand 192 len) 192) ; lookup from offset table
	     (let* ((high (string (integer->char (logand 63 len))))
		    (low (string (integer->char (read-byte-from-message message))))
		    (offset (car (unpack "n" :from-string
					 (string-append high low)))))
	       (hash-table-put! (slot-ref message 'offset-table)
				(- (slot-ref message 'offset-index) 2)
				offset)
	       (string-append result (get-label-from-offset-table
		(slot-ref message 'offset-table)
		offset))))
	    (else
	     (let ((label (string-append
			   (string (integer->char len))
			   (read-block-from-message len message))))
	       (hash-table-put! (slot-ref message 'offset-table)
				(- (slot-ref message 'offset-index) len 1)
				label)
				
	       (recv-name-in (string-append
			      result
			      label)))))))
  (recv-name-in ""))


(define (get-label-from-offset-table offset-table offset)
  (define (get-table-from-offset-table-inner offset-table offset result)
    (if (hash-table-exists? offset-table offset)
	(let ((label (hash-table-get offset-table offset)))
	  (cond ((is-a? label <string>)
		 (let ((len (string-byte-ref label 0)))
		   (cond ((= len 0)
			  (string-append result label))
			 (else
			  (get-table-from-offset-table-inner
			   offset-table
			   (+ offset len 1)
			   (string-append result label))))))
		((is-a? label <integer>)
		 (get-table-from-offset-table-inner offset-table label
						    result))))
	(raise (condition
		(<dns-message-error>
		 (message "invalid offset"))))))
  (get-table-from-offset-table-inner offset-table offset ""))


(define (make-header id recursive count)
   (pack "nCCnnnn" (list id recursive 0 count 0 0 0)
	 :to-string? #t)
)

(define (resolv:name->address resolver name)
  (let ((answer (resolv:get-resource-records resolver name RR:A)))
    (map (lambda (rr)
	   (slot-ref rr 'address))
	 (check-cname name answer))))
	
(define (check-cname name section)
  (let ((name-list (list name))
	(result '()))
    (for-each (lambda (rr)
		(if (= (resource-record-type rr) RR:CNAME)
		    (set! name-list (cons (slot-ref rr 'cname) name-list))
		    (begin (member (slot-ref rr 'name) name-list)
			   (set! result (cons rr result)))))
	      section)
    (reverse result)))

(define (resolv:address->name resolver address)
  (let ((answer (resolv:get-resource-records resolver address RR:PTR)))
    (map (lambda (rr) (slot-ref rr 'ptrdname)) answer)))

(define (resolv:get-resource-records resolver name type)
  (let ((message (resolv:get-dns-message resolver name type)))
    (dns-message-answer-section message)))

(define (resolv:get-dns-message resolver name type)
  (cond ((is-a? type <integer>)
	 (when (not (hash-table-exists? resource-record-table type))
	       (raise (condition
		       (<resolver>
			(message #`"unrecognized type: ,type"))))))
	((is-a? type <symbol>)
	 (cond ((eq? type 'A)
		(set! type RR:A))
	       ((eq? type 'NS)
		(set! type RR:NS))
	       ((eq? type 'MX)
		(set! type RR:MX))
	       ((eq? type 'CNAME)
		(set! type RR:CNAME))
	       ((eq? type 'SOA)
		(set! type RR:SOA))
	       ((eq? type 'PTR)
		(set! type RR:PTR))
	       ((eq? type 'HINFO)
		(set! type RR:HINFO))
	       ((eq? type 'ANY)
		(set! type RR:ANY))
	       (else
		(raise (condition
			(<resolver-error>
			 (message #`"unrecognized type: ,type"))))))))
  (send-query resolver name type))

(define (call-with-message-body resolver name type proc)
  (let ((message (resolv:get-dns-message resolver name type)))
    (proc (dns-message-question-section message)
	  (dns-message-answer-section message)
	  (dns-message-authority-section message)
	  (dns-message-additional-section message))))

(provide "dns/resolv")
