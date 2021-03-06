#! /usr/bin/gosh

(use dns.resolv)

(define resolver (make <resolver>))

(guard (exc
	((condition-has-type? exc <nxdomain-error>)
	 (display "nxdomain error\n")))
       (for-each (lambda (address) (format #t "~s\n" address))
		 (resolv:name->address resolver "www.sra.co.jp")))
