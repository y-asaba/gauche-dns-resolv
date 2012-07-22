#! /usr/bin/gosh

(use dns.resolv)

(define resolver (make <resolver>))

(guard (exc
	((condition-has-type? exc <nxdomain-error>)
	 (display "nxdomain error\n")))
       (for-each (lambda (mx)
		   (format #t "~s ~s\n" (mx-preference mx)
			   (mx-exchange mx)))
		 (resolv:get-resource-records resolver "sra.co.jp" 'MX)))

