;;;; openssl.scm
;;;; Bindings to the OpenSSL SSL/TLS library

(module openssl
  (
   ssl-connect ssl-connect*
   ssl-make-client-context ssl-make-client-context*
   ssl-client-context?
   ssl-listen ssl-listen*
   ssl-close
   ssl-port?
   ssl-port->tcp-port
   tcp-port->ssl-port
   ssl-listener?
   ssl-listener?
   ssl-listener-port
   ssl-listener-fileno
   ssl-accept-ready?
   ssl-accept
   ssl-handshake-timeout
   ssl-shutdown-timeout
   ssl-set-cipher-list!
   ssl-load-certificate-chain!
   ssl-load-private-key!
   ssl-set-verify!
   ssl-load-verify-root-certificates!
   ssl-load-suggested-certificate-authorities!
   ssl-peer-verified?
   ssl-peer-subject-name ssl-peer-issuer-name
   ssl-default-certificate-authority-directory
   ssl-make-i/o-ports
   net-unwrap-tcp-ports)

(import scheme chicken foreign ports)

(declare
 (usual-integrations)
 (no-procedure-checks-for-usual-bindings)
 (disable-interrupts)
 (bound-to-procedure
   ##sys#update-errno
   ##sys#signal-hook
   ##sys#string-append
   ##sys#tcp-port->fileno
   ##sys#current-thread
   ##sys#size
   ##sys#setslot
   ##sys#check-string))

(use srfi-13 srfi-18 tcp)

(import
 (only srfi-13 string-join)
 (only data-structures ->string)
 (only files make-pathname))

(require-library
 srfi-13 data-structures)

#>
#include <errno.h>
#ifdef _WIN32
  #ifdef _MSC_VER
    #include <winsock2.h>
  #else
    #include <ws2tcpip.h>
  #endif

  #include <openssl/rand.h>
#else
  #define closesocket     close
#endif

#ifdef ECOS
  #include <sys/sockio.h>
#else
  #include <unistd.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
<#

(foreign-code #<<EOF
ERR_load_crypto_strings();
SSL_load_error_strings();
SSL_library_init();

#ifdef _WIN32
  RAND_screen();
#endif

EOF
)

;;; support routines

(define-foreign-variable strerror c-string "strerror(errno)")

(define ssl-handshake-timeout (make-parameter 120000))
(define ssl-shutdown-timeout (make-parameter 120000))

(define (net-close-socket fd)
  (when ((foreign-lambda bool "closesocket" int) fd)
    (##sys#update-errno)
    (##sys#signal-hook
     network-error: 'net-close-socket
     (##sys#string-append "can not close socket - " strerror)
     fd)))

(define (net-unwrap-tcp-ports tcp-in tcp-out)
  (let ((fd (##sys#tcp-port->fileno tcp-in)))
    (tcp-abandon-port tcp-in)
    (tcp-abandon-port tcp-out)
    fd))

(define (ssl-abort loc sym . args)
  (let ((err ((foreign-lambda unsigned-long "ERR_get_error"))))
    (abort
     (make-composite-condition
      (make-property-condition
       'exn
       'message
       (string-append
	(if sym
	    (symbol->string sym)
	    "error")
	": library="
	(or
	 ((foreign-lambda c-string "ERR_lib_error_string" unsigned-long)
	  err)
	 "<unknown>")
	", function="
	(or
	 ((foreign-lambda c-string "ERR_func_error_string" unsigned-long)
	  err)
	 "<unknown>")
	", reason="
	(or
	 ((foreign-lambda c-string "ERR_reason_error_string" unsigned-long)
	  err)
	 "<unknown>"))
       'location
       loc
       'arguments args)
      (make-property-condition
       'i/o)
      (make-property-condition
       'net)
      (make-property-condition
       'openssl
       'status
       sym)))))

(define ssl-clear-error (foreign-lambda void "ERR_clear_error"))

(define ssl-ctx-free (foreign-lambda void "SSL_CTX_free" c-pointer))

(define (ssl-ctx-new protocol server)
  (ssl-clear-error)
  (let ((ctx
	 ((foreign-lambda*
	   c-pointer ((c-pointer method))
	   "SSL_CTX *ctx;"
	   "if ((ctx = SSL_CTX_new((SSL_METHOD *)method)))\n"
	   "  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | "
           "                        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);\n"
	   "return(ctx);\n")
	  (case protocol
	    ((sslv2-or-v3)
	     (if server
		 ((foreign-lambda c-pointer "SSLv23_server_method"))
		 ((foreign-lambda c-pointer "SSLv23_client_method"))))
	    ((sslv3)
	     (if server
		 ((foreign-lambda c-pointer "SSLv3_server_method"))
		 ((foreign-lambda c-pointer "SSLv3_client_method"))))
	    ((tls tlsv1)
	     (if server
		 ((foreign-lambda c-pointer "TLSv1_server_method"))
		 ((foreign-lambda c-pointer "TLSv1_client_method"))))
	    ((tlsv11)
	     (if server
		 ((foreign-lambda c-pointer "TLSv1_1_server_method"))
		 ((foreign-lambda c-pointer "TLSv1_1_client_method"))))
	    ((tlsv12)
	     (if server
		 ((foreign-lambda c-pointer "TLSv1_2_server_method"))
		 ((foreign-lambda c-pointer "TLSv1_2_client_method"))))
	    (else
	     (abort
	      (make-composite-condition
	       (make-property-condition
		'exn
		'message "invalid SSL/TLS connection protocol"
		'location 'ssl-ctx-new
		'arguments (list protocol))
	       (make-property-condition
		'type))))))))
    (unless ctx (ssl-abort 'ssl-ctx-new #f))
    (set-finalizer! ctx ssl-ctx-free)
    ctx))


(define (ssl-new ctx)
  (ssl-clear-error)
  (cond
   (((foreign-lambda c-pointer "SSL_new" c-pointer) ctx)
    => values)
   (else
    (ssl-abort 'ssl-new #f))))

(define ssl-free (foreign-lambda void "SSL_free" c-pointer))

(define (ssl-result-or-abort loc ssl ret allow-i/o? . args)
  (call-with-current-continuation
   (lambda (q)
     (let ((sym
	    (let ((x ((foreign-lambda int "SSL_get_error" c-pointer int)
                      ssl ret)))
	      (cond
               ((eq? x (foreign-value "SSL_ERROR_NONE" int))
                (q ret))
               ((eq? x (foreign-value "SSL_ERROR_ZERO_RETURN" int))
                'zero-return)
               ((eq? x (foreign-value "SSL_ERROR_WANT_READ" int))
                (if allow-i/o?
                    (q 'want-read)
                    'want-read))
               ((eq? x (foreign-value "SSL_ERROR_WANT_WRITE" int))
                (if allow-i/o?
                    (q 'want-write)
                    'want-write))
               ((eq? x (foreign-value "SSL_ERROR_WANT_CONNECT" int))
		'want-connect)
               ((eq? x (foreign-value "SSL_ERROR_WANT_ACCEPT" int))
                'want-accept)
               ((eq? x (foreign-value "SSL_ERROR_WANT_X509_LOOKUP" int))
                'want-X509-lookup)
               ((eq? x (foreign-value "SSL_ERROR_SYSCALL" int))
                'syscall)
               ((eq? x (foreign-value "SSL_ERROR_SSL" int))
                'ssl)
               (else
                #f)))))
       (apply ssl-abort loc sym args)))))

(define (ssl-set-fd! ssl fd)
  (ssl-clear-error)
  (ssl-result-or-abort
   'ssl-set-fd! ssl
   ((foreign-lambda int "SSL_set_fd" c-pointer int) ssl fd) #f
   fd)
  (void))

(define (ssl-shutdown ssl)
  (ssl-clear-error)
  (let ((ret
	 ((foreign-lambda*
	   scheme-object ((c-pointer ssl))
	   "int ret;\n"
	   "switch (ret = SSL_shutdown((SSL *)ssl)) {\n"
	   "case 0: return(C_SCHEME_FALSE);\n"
	   "case 1: return(C_SCHEME_TRUE);\n"
	   "default: return(C_fix(ret));\n"
	   "}\n") ssl)))
    (if (fixnum? ret)
	(ssl-result-or-abort 'ssl-shutdown ssl ret #t)
	ret)))

(define (ssl-get-char ssl)
  (ssl-clear-error)
  (let ((ret
	 ((foreign-lambda*
	   scheme-object ((c-pointer ssl))
	   "unsigned char ch;\n"
	   "int ret;\n"
	   "switch (ret = SSL_read((SSL *)ssl, &ch, 1)) {\n"
	   "case 0: return(SSL_get_error((SSL *)ssl, 0) == SSL_ERROR_ZERO_RETURN ?\n"
           "               C_SCHEME_END_OF_FILE : C_fix(0));\n"
	   "case 1: return(C_make_character(ch));\n"
	   "default: return(C_fix(ret));\n"
	   "}\n")
	  ssl)))
    (if (fixnum? ret)
	(ssl-result-or-abort 'ssl-get-char ssl ret #t)
	ret)))

(define (ssl-write ssl buffer offset size)
  (ssl-clear-error)
  (ssl-result-or-abort
   'ssl-write ssl
   ((foreign-lambda*
     int ((c-pointer ssl) (scheme-pointer buf) (int offset) (int size))
     "return(SSL_write((SSL *)ssl, (char *)buf + offset, size));\n")
    ssl buffer offset size)
   #t))

(define-record-type ssl-port-data
  (ssl-make-port-data startup ssl tcp-port)
  ssl-port-data?
  (startup ssl-port-data-startup)
  (ssl ssl-port-data-ssl)
  (tcp-port ssl-port-data-tcp-port))

(define (ssl-port? obj)
  (and (port? obj) (eq? (##sys#slot obj 10) 'ssl-socket)))

(define (ssl-port-startup p)
  (when (ssl-port? p)
    ((ssl-port-data-startup (##sys#slot p 11)))))

(define (ssl-port->ssl p)
  (if (ssl-port? p)
      (ssl-port-data-ssl (##sys#slot p 11))
      (abort
       (make-composite-condition
	(make-property-condition
	 'exn
	 'location 'ssl-port->ssl-context
	 'message "expected an ssl port, got"
	 'arguments (list p))
	(make-property-condition
	 'type)))))

(define (ssl-port->tcp-port p)
  (if (ssl-port? p)
      (ssl-port-data-tcp-port (##sys#slot p 11))
      (abort
       (make-composite-condition
        (make-property-condition
         'exn
         'location 'ssl-port->tcp-port
         'message "expected an ssl port, got"
         'arguments (list p))
        (make-property-condition
         'type)))))

(define (tcp-port->ssl-port tcp-in tcp-out #!optional (ctx 'sslv2-or-v3))
  (let* ((fd (net-unwrap-tcp-ports tcp-in tcp-out))
         (ctx
          (if (ssl-client-context? ctx)
              (ssl-unwrap-client-context ctx)
              (ssl-ctx-new ctx #f)))
         (ssl
          (ssl-new ctx)))
    (ssl-set-connect-state! ssl)
    (ssl-make-i/o-ports ctx fd ssl tcp-in tcp-out)))


(define (ssl-do-handshake ssl)
  (ssl-clear-error)
  (ssl-result-or-abort 'ssl-do-handshake ssl
                       ((foreign-lambda int "SSL_do_handshake" c-pointer) ssl) #t))

(define (ssl-call/timeout loc proc fd timeout timeout-message)
  (let loop ((res (proc)))
    (case res
      ((want-read)
       (when timeout
         (##sys#thread-block-for-timeout!
          ##sys#current-thread (+ (current-milliseconds) timeout)))
       (##sys#thread-block-for-i/o! ##sys#current-thread fd #:input)
       (thread-yield!)
       (if (##sys#slot ##sys#current-thread 13)
           (##sys#signal-hook
            #:network-timeout-error loc timeout-message timeout fd)
           (loop (proc))))
      ((want-write)
       (when timeout
             (##sys#thread-block-for-timeout!
              ##sys#current-thread (+ (current-milliseconds) timeout)))
       (##sys#thread-block-for-i/o! ##sys#current-thread fd #:output)
       (thread-yield!)
       (if (##sys#slot ##sys#current-thread 13)
           (##sys#signal-hook
            #:network-timeout-error loc timeout-message timeout fd)
           (loop (proc))))
      (else res))))

(define (ssl-make-i/o-ports ctx fd ssl tcp-in tcp-out)
  ;; note that the ctx parameter is never used but it is passed in order
  ;; to be present in the closure data of the various port functions
  ;; so it isn't garbage collected before the ports are all gone
  (let ((in-open? #f) (out-open? #f)
        (mutex (make-mutex 'ssl-mutex)))
    (define (startup #!optional (called-from-close #f))
      (dynamic-wind
          (lambda ()
            (mutex-lock! mutex))
          (lambda ()
	   (let ((skip-startup (not ssl)))
             (if skip-startup
               (when (not called-from-close)
                 (error "SSL socket already closed"))
               (unless (or in-open? out-open?)
                 (let ((success? #f))
                   (dynamic-wind
                     void
                     (lambda ()
                       (ssl-set-fd! ssl fd)
                       (ssl-call/timeout 'ssl-do-handshake
                                         (lambda () (ssl-do-handshake ssl))
                                         fd (ssl-handshake-timeout)
                                         "SSL handshake operation timed out")
                       (set! in-open? #t)
                       (set! out-open? #t)
                       (set! success? #t))
                     (lambda ()
                       (unless success?
                         (ssl-free ssl)
                         (set! ssl #f)
                         (net-close-socket fd)))))))
             (not skip-startup)))
          (lambda ()
            (mutex-unlock! mutex))))
    (define (shutdown)
      (unless (or in-open? out-open?)
	(set! ctx #f) ;; ensure that this reference is lost
	(dynamic-wind
	    void
	    (lambda ()
              (ssl-call/timeout 'ssl-shutdown
                                (lambda () (ssl-shutdown ssl))
                                fd (ssl-shutdown-timeout)
                                "SSL shutdown operation timed out"))
	    (lambda ()
	      (ssl-free ssl)
	      (net-close-socket fd)))))
    (let ((in
	   (let ((buffer #f))
	     (make-input-port
	      ;; read
	      (lambda ()
                (startup)
		(unless buffer
                  (set! buffer
                        (ssl-call/timeout 'ssl-get-char
                                          (lambda () (ssl-get-char ssl))
                                          fd (tcp-read-timeout)
                                          "SSL read timed out")))
                (let ((ch buffer))
                  (unless (eof-object? buffer)
                    (set! buffer #f))
                  ch))
	      ;; ready?
	      (lambda ()
                (startup)
		(or buffer
		    (let ((ret (ssl-get-char ssl)))
                      (case ret
                        ((want-read want-write)
                         #f)
                        (else
                         (set! buffer ret)
                         #t)))))
	      ;; close
	      (lambda ()
                (when (startup #t)
                  (set! in-open? #f)
                  (shutdown)))
	      ;; peek
	      (lambda ()
                (startup)
		(unless buffer
                  (set! buffer (ssl-call/timeout 'ssl-peek-char
                                                 (lambda () (ssl-get-char ssl))
                                                 fd (tcp-read-timeout)
                                                 "SSL read timed out")))
		buffer))))
    (out
      (let* ((outbufmax  (tcp-buffer-size))
	     (outbuf     (and outbufmax (fx> outbufmax 0) (make-string outbufmax)))
	     (outbufsize 0)
	     (unbuffered-write
              (lambda (buffer #!optional (offset 0) (size (##sys#size buffer)))
		(when (> size 0) ; Undefined behaviour for 0 bytes!
		  (let loop ((offset offset) (size size))
		    (let ((ret (ssl-call/timeout
				'ssl-write
				(lambda () (ssl-write ssl buffer offset size))
				fd (tcp-write-timeout) "SSL write timed out")))
		      (when (fx< ret size) ; Partial write
			(loop (fx+ offset ret) (fx- size ret)))))))))

	(define (buffered-write data #!optional (start 0))
	  (let* ((size      (- (##sys#size data) start))
		 (to-copy   (min (- outbufmax outbufsize) size))
		 (left-over (- size to-copy)))

	    (string-copy! outbuf outbufsize data start (+ start to-copy))
	    (set! outbufsize (+ outbufsize to-copy))

	    (if (= outbufsize outbufmax)
	      (begin
		(unbuffered-write outbuf)
		(set! outbufsize 0)))

	    (if (> left-over 0)
	      (buffered-write data (+ start to-copy)))))

        (make-output-port
	 ;; write
	 (lambda (buffer)
	   (startup)
	   (if outbuf
	     (buffered-write buffer)
	     (unbuffered-write buffer)))
	 ;; close
	 (lambda ()
	   (when (startup #t)
	     (dynamic-wind
	       void
	       (lambda ()
		 (when outbuf
		   (unbuffered-write outbuf 0 outbufsize)
		   (set! outbufsize 0)))
	       (lambda ()
		 (set! out-open? #f)
		 (shutdown)))))
	 ;; flush
	 (lambda ()
	   (when outbuf
	     (startup)
	     (unbuffered-write outbuf 0 outbufsize)
	     (set! outbufsize 0)))))))
      (##sys#setslot in 3 "(ssl)")
      (##sys#setslot out 3 "(ssl)")
      ;; first "reserved" slot
      ;; Slot 7 should probably stay 'custom
      (##sys#setslot in 10 'ssl-socket)
      (##sys#setslot out 10 'ssl-socket)
      ;; second "reserved" slot
      (##sys#setslot in 11 (ssl-make-port-data startup ssl tcp-in))
      (##sys#setslot out 11 (ssl-make-port-data startup ssl tcp-out))
      (values in out))))

(define (ssl-unwrap-context obj)
  (cond
   ((ssl-client-context? obj)
    (ssl-unwrap-client-context obj))
   ((ssl-listener? obj)
    (ssl-unwrap-listener-context obj))
   (else
    (abort
     (make-composite-condition
      (make-property-condition
       'exn
       'location 'ssl-unwrap-context
       'message "expected an ssl-client-context or ssl-listener, got"
       'arguments (list obj))
      (make-property-condition
       'type))))))

;;; exported routines

;; create SSL client context
(define-record-type ssl-client-context
  (ssl-wrap-client-context context)
  ssl-client-context?
  (context ssl-unwrap-client-context))

(define (ssl-make-client-context #!optional (protocol 'sslv2-or-v3))
  (ssl-wrap-client-context (ssl-ctx-new protocol #f)))

(define ssl-set-connect-state! (foreign-lambda void "SSL_set_connect_state" c-pointer))

;; connect to SSL server
(define (ssl-connect hostname #!optional port (ctx 'sslv2-or-v3))
  (receive (tcp-in tcp-out)
      (tcp-connect hostname port)
    (let* ((fd (net-unwrap-tcp-ports tcp-in tcp-out))
           (ctx
            (if (ssl-client-context? ctx)
                (ssl-unwrap-client-context ctx)
                (ssl-ctx-new ctx #f)))
           (ssl
            (ssl-new ctx)))
      (ssl-set-connect-state! ssl)
      (ssl-make-i/o-ports ctx fd ssl tcp-in tcp-out))))

;; create listener/SSL server context
(define-record-type ssl-listener
  (ssl-wrap-listener context listener)
  ssl-listener?
  (context ssl-unwrap-listener-context)
  (listener ssl-unwrap-listener))

(define (ssl-listen port #!optional (backlog 4) (hostname #f) (protocol 'sslv2-or-v3))
  (ssl-wrap-listener
   (ssl-ctx-new protocol #t)
   (tcp-listen port backlog hostname)))

;; shutdown a SSL server
(define (ssl-close listener)
  (tcp-close (ssl-unwrap-listener listener)))

;; return the port number this listener is operating on
(define (ssl-listener-port listener)
  (tcp-listener-port (ssl-unwrap-listener listener)))

;; get the underlying socket descriptor number for an SSL listener
(define (ssl-listener-fileno listener)
  (tcp-listener-fileno (ssl-unwrap-listener listener)))

;; check whether an incoming connection is pending
(define (ssl-accept-ready? listener)
  (tcp-accept-ready? (ssl-unwrap-listener listener)))

(define ssl-set-accept-state! (foreign-lambda void "SSL_set_accept_state" c-pointer))

;; accept a connection from an SSL listener
(define (ssl-accept listener)
  (receive (tcp-in tcp-out)
    (tcp-accept (ssl-unwrap-listener listener))
   (let* ((fd (net-unwrap-tcp-ports tcp-in tcp-out))
          (ctx (ssl-unwrap-listener-context listener))
          (ssl (ssl-new ctx)))
     (ssl-set-accept-state! ssl)
     (ssl-make-i/o-ports ctx fd ssl tcp-in tcp-out))))

;; set the list of allowed ciphers
(define (ssl-set-cipher-list! obj v)
  (ssl-clear-error)
  (unless (eq?
	   ((foreign-lambda
	     int "SSL_CTX_set_cipher_list" c-pointer c-string)
	    (ssl-unwrap-context obj)
	    (if (pair? v)
		(string-join (map ->string v) ":")
		(->string v)))
	   1)
    (ssl-abort 'ssl-set-cipher-list! #f v)))

;; load identifying certificate or certificate chain into SSL context
(define (ssl-load-certificate-chain! obj pathname/blob #!optional (asn1? #f))
  (ssl-clear-error)
  (unless
   (eq?
    (if (blob? pathname/blob)
	((foreign-lambda
	  int "SSL_CTX_use_certificate_ASN1" c-pointer int scheme-pointer)
	 (ssl-unwrap-context obj) (blob-size pathname/blob) pathname/blob)
	(begin
	  (##sys#check-string pathname/blob)
	  (if asn1?
	      ((foreign-lambda*
		int ((c-pointer ctx) (c-string path))
		"return(SSL_CTX_use_certificate_file((SSL_CTX *)ctx, path, SSL_FILETYPE_ASN1));")
	       (ssl-unwrap-context obj) pathname/blob)
	      ((foreign-lambda
		int "SSL_CTX_use_certificate_chain_file" c-pointer c-string)
	       (ssl-unwrap-context obj) pathname/blob))))
    1)
   (ssl-abort 'ssl-load-certificate-chain! #f pathname/blob asn1?)))

;; load the private key for the identifying certificate chain
(define (ssl-load-private-key! obj pathname/blob #!optional (rsa? #t) (asn1? #f))
  (ssl-clear-error)
  (unless
   (eq?
    (if (blob? pathname/blob)
	((foreign-lambda
	  int "SSL_CTX_use_PrivateKey_ASN1" int c-pointer scheme-pointer long)
	 (case rsa?
	   ((rsa #t)
	    (foreign-value "EVP_PKEY_RSA" int))
	   ((dsa #f)
	    (foreign-value "EVP_PKEY_DSA" int))
	   ((dh)
	    (foreign-value "EVP_PKEY_DH" int))
	   ((ec)
	    (foreign-value "EVP_PKEY_EC" int))
	   (else
	    (abort
	     (make-composite-condition
	      (make-property-condition
	       'exn
	       'message "invalid key type"
	       'location 'ssl-load-private-key!
	       'arguments (list obj pathname/blob rsa? asn1?))
	      (make-property-condition
	       'type)))))
	 (ssl-unwrap-context obj) pathname/blob (blob-size pathname/blob))
	(begin
	  (##sys#check-string pathname/blob)
	  (if (memq rsa? '(rsa #t))
	      ((foreign-lambda*
		int ((c-pointer ctx) (c-string path) (bool asn1))
		"return(SSL_CTX_use_RSAPrivateKey_file((SSL_CTX *)ctx, path, (asn1 ? SSL_FILETYPE_ASN1 : SSL_FILETYPE_PEM)));")
	       (ssl-unwrap-context obj) pathname/blob asn1?)
	      ((foreign-lambda*
		int ((c-pointer ctx) (c-string path) (bool asn1))
		"return(SSL_CTX_use_PrivateKey_file((SSL_CTX *)ctx, path, (asn1 ? SSL_FILETYPE_ASN1 : SSL_FILETYPE_PEM)));")
	       (ssl-unwrap-context obj) pathname/blob asn1?))))
    1)
   (ssl-abort 'ssl-load-private-key! #f pathname/blob rsa? asn1?)))

;; switch verification of peer on or off
(define (ssl-set-verify! obj v)
  ((foreign-lambda*
    void
    ((c-pointer ctx) (bool verify))
    "SSL_CTX_set_verify((SSL_CTX *)ctx,"
    " (verify ? SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT"
    " : SSL_VERIFY_NONE), NULL);\n")
   (ssl-unwrap-context obj) v))

;; load trusted root certificates into SSL context
(define (ssl-load-verify-root-certificates! obj pathname #!optional (dirname #f))
  (if pathname (##sys#check-string pathname))
  (if dirname (##sys#check-string dirname))
  (ssl-clear-error)
  (unless (eq?
	   ((foreign-lambda
	     int "SSL_CTX_load_verify_locations" c-pointer c-string c-string)
	    (ssl-unwrap-context obj)
	    (if pathname pathname #f)
	    (if dirname dirname #f))
	   1)
    (ssl-abort 'ssl-load-verify-root-certificates! #f pathname dirname)))

;; load suggested root certificates into SSL context
(define (ssl-load-suggested-certificate-authorities! obj pathname)
  (##sys#check-string pathname)
  (ssl-clear-error)
  (cond
   (((foreign-lambda c-pointer "SSL_load_client_CA_file" c-string) pathname)
    => (cut
	(foreign-lambda
	 void "SSL_CTX_set_client_CA_list" c-pointer c-pointer)
	(ssl-unwrap-context obj) <>))
   (else
    (ssl-abort 'ssl-load-suggested-certificate-authorities! #f pathname))))

;; check whether the connection peer has presented a valid certificate
(define (ssl-peer-verified? p)
  (ssl-port-startup p)
  (let ((ssl (ssl-port->ssl p)))
    (and ((foreign-lambda*
	   bool ((c-pointer ssl))
	   "C_return(SSL_get_verify_result(ssl) == X509_V_OK);")
	  ssl)
	 ((foreign-lambda*
	   bool ((c-pointer ssl))
	   "X509 *crt = SSL_get_peer_certificate(ssl);\n"
	   "X509_free(crt);\n"
	   "C_return(crt != NULL);\n")
	  ssl))))

;; obtain the subject name of the connection peer's certificate, if any
(define (ssl-peer-subject-name p)
  (ssl-port-startup p)
  ((foreign-lambda*
    c-string* ((c-pointer ssl))
    "X509 *crt = SSL_get_peer_certificate(ssl);\n"
    "if (!crt) C_return(NULL);\n"
    "char *name = X509_NAME_oneline(X509_get_subject_name(crt), NULL, -1);\n"
    "X509_free(crt);\n"
    "C_return(name);")
   (ssl-port->ssl p)))

;; obtain the issuer name of the connection peer's certificate, if any
(define (ssl-peer-issuer-name p)
  (ssl-port-startup p)
  ((foreign-lambda*
    c-string* ((c-pointer ssl))
    "X509 *crt = SSL_get_peer_certificate(ssl);\n"
    "if (!crt) C_return(NULL);\n"
    "char *name = X509_NAME_oneline(X509_get_issuer_name(crt), NULL, -1);\n"
    "X509_free(crt);\n"
    "C_return(name);")
   (ssl-port->ssl p)))

;;; wrappers with secure defaults

(define ssl-default-certificate-authority-directory
  (make-parameter
   (cond-expand
    (unix "/etc/ssl/certs")
    (else "certs"))))

(define (ssl-make-client-context* #!key (protocol 'tlsv12) (cipher-list "DEFAULT") certificate private-key (private-key-type 'rsa) private-key-asn1? certificate-authorities certificate-authority-directory (verify? #t))
  (unless (or certificate-authorities certificate-authority-directory)
    (set! certificate-authority-directory (ssl-default-certificate-authority-directory)))
  (let ((ctx (ssl-make-client-context protocol)))
    (ssl-set-cipher-list! ctx cipher-list)
    (when certificate
      (ssl-load-certificate-chain! ctx certificate)
      (ssl-load-private-key! ctx private-key private-key-type private-key-asn1?))
    (ssl-load-verify-root-certificates! ctx certificate-authorities certificate-authority-directory)
    (ssl-set-verify! ctx verify?)
    ctx))

(define (ssl-connect* #!rest args #!key hostname port)
  (ssl-connect hostname port (apply ssl-make-client-context* args)))

(define (ssl-listen* #!key hostname (port 0) (backlog 4) (protocol 'tlsv12) (cipher-list "DEFAULT") certificate private-key (private-key-type 'rsa) private-key-asn1? certificate-authorities certificate-authority-directory (verify? #f))
  (unless (or certificate-authorities certificate-authority-directory)
    (set! certificate-authority-directory (ssl-default-certificate-authority-directory)))
  (let ((ear (ssl-listen port backlog hostname protocol)))
    (ssl-set-cipher-list! ear cipher-list)
    (ssl-load-certificate-chain! ear certificate)
    (ssl-load-private-key! ear private-key private-key-type private-key-asn1?)
    (when certificate-authorities
      (ssl-load-suggested-certificate-authorities! ear certificate-authorities))
    (ssl-load-verify-root-certificates! ear certificate-authorities certificate-authority-directory)
    (ssl-set-verify! ear verify?)
    ear))

)
