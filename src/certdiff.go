/*
 * Originally written by Jan Schaumann <jschauma@netmeister.org>
 * in November 2016.
 *
 * This little tool reports the differences between the
 * given certificate and the properties specified in
 * the configuration file.
 *
 * Copyright (c) 2016, Yahoo Inc.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the
 * above copyright notice, this list of conditions and
 * the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the
 * names of its contributors may be used to endorse or
 * promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const EXIT_FAILURE = 1
const EXIT_SUCCESS = 0

const PROGNAME = "certdiff"
const VERSION = "1.2"

const CTURL = "https://crt.sh/?"

var RVAL = 0
var VERBOSITY = 0

var CERTS = make(map[*x509.Certificate]*CertInfo)
var ISSUERS = make(map[string]bool)
var INTERMEDIATES *x509.CertPool
var ROOTS *x509.CertPool
var CHAIN []*x509.Certificate

var CONFIG = map[string]string{
	"cabundle":       "/etc/pki/tls/cert.pem",
	"configFile":     "/home/y/conf/certdiff/certdiffrc",
	"ct":             "true",
	"domains":        "",
	"keyLength":      "2048",
	"keyLengthECDSA": "256",
	"keyLengthRSA":   "2048",
	"list":           "false",
	"maxValidity":    "180",
	"maxSANs":        "20",
	"maxWildcards":   "5",
	"pins":           "",
	"port":           "443",
	"rootSerials":    "",
	"server":         "",
	"sigAlgs":        "",
}

type CertInfo struct {
	CertType  string
	Chain     string
	CTlog     string
	SANs      string
	KeyLength int
	SigAlgo   string
	Validity  int
	Verified  string
}

/*
 * General Functions
 */

func argcheck(flag string, args []string, i int) {
	if len(args) <= (i + 1) {
		fail("'%v' needs an argument.", flag)
	}
}

func buildCABundle() {
	cabundle := CONFIG["cabundle"]

	ROOTS = x509.NewCertPool()
	INTERMEDIATES = x509.NewCertPool()

	if len(cabundle) < 1 {
		return
	}

	cabundle = expandTilde(cabundle)

	verbose(1, "Creating root CA bundle from '%s'...", cabundle)

	fd, err := os.Open(cabundle)
	if err != nil {
		fail("Unable to open '%s': %v", cabundle, err)
	}

	var pems []byte
	input := bufio.NewReader(fd)

	for {
		data, err := input.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Unable to read input: %v\n", err)
			}
			break
		}
		pems = append(pems, data...)
	}

	ok := ROOTS.AppendCertsFromPEM(pems)
	if !ok {
		fail("Unable to create root CA pool.")
	}

	/* Now read it again!
	 * We cannot get the actual certificates from
	 * a CertPool, so we need to re-read the
	 * bundle to populate our internal CERTS
	 * structure with all roots. */
	fd.Close()
	fd, err = os.Open(cabundle)
	if err != nil {
		fail("Unable to open '%s': %v", cabundle, err)
	}
	defer fd.Close()
	extractCertificates(fd, "root")
}

func buildChain(cert *x509.Certificate) {
	verbose(1, "Building certificate chain for %0x '%s' (leaf)...",
		cert.SerialNumber, cert.Subject.CommonName)

	CHAIN = append(CHAIN, cert)

	c := cert

	found := false
	space := "  "

	if CONFIG["list"] == "true" {
		fmt.Printf("\nLeaf cert '%s' from input:\n", cert.Subject.CommonName)
	}
	for c.Issuer.CommonName != c.Subject.CommonName {
		found = false
		verbose(2, "Looking for issuer of %0x...", c.SerialNumber)
		for _, tmp := range sortCerts() {
			if err := c.CheckSignatureFrom(tmp); err == nil {
				verbose(3, "Valid signature on %0x from %s.",
					c.SerialNumber, tmp.Subject.CommonName)
				found = true
				CHAIN = append(CHAIN, tmp)
				c = tmp

				if CONFIG["list"] == "true" {
					fmt.Printf("%ssigned by '%s' (%0x; %s; %s)\n",
						space,
						c.Subject.CommonName,
						c.SerialNumber,
						certPin(c, "sha1"),
						certPin(c, "sha256"))
				}
				space += "  "
				break
			}
		}
		if !found {
			break
		}
	}

	if !found {
		if CONFIG["list"] == "true" {
			fmt.Printf("-- incomplete --\n")
		}
		reportError("%0x '%s' (leaf): Incomplete chain or unknown root!",
			cert.SerialNumber, cert.Subject.CommonName)
		if len(CONFIG["cabundle"]) < 1 {
			fmt.Printf("Missing roots - specify 'cabundle' in config?\n")
		}
	}

}

func checkCerts() {
	verbose(1, "Checking all certificates...")

	for _, cert := range CHAIN {
		certType := CERTS[cert].CertType

		/* Some checks only make sense
		 * for the leaf certificate. */
		if certType == "leaf" {
			checkDomains(cert)
			checkValidity(cert)
			checkSANs(cert)
			verifyCert(cert)
			checkPinsAndRootSerials(cert)
		}

		/* Roots are explicitly trusted, so no
		 * need to check them. */
		if certType != "root" {
			checkCT(cert, certType)
			checkKeyLength(cert, certType)
			checkSigAlgs(cert, certType)
		}
	}
}

func checkCT(cert *x509.Certificate, certType string) {
	if CONFIG["ct"] != "true" {
		return
	}

	verbose(2, "%0x '%s' (%s): checking certificate transparency...",
		cert.SerialNumber, cert.Subject.CommonName, certType)

	serial := fmt.Sprintf("%0x", cert.SerialNumber)
	ctUrl := CTURL + "serial=" + url.QueryEscape(serial)
	if _, err := url.Parse(ctUrl); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse url '%s': %s\n", ctUrl, err)
		return
	}

	r, err := http.Get(ctUrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to get '%s': %s\n", ctUrl, err)
		return
	}
	defer r.Body.Close()

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read body of '%s': %s\n", ctUrl, err)
		return
	}

	found := false
	for _, line := range strings.Split(string(data), "\n") {
		r := regexp.MustCompile(`(?i)><a href="\?id=([0-9]+)">`)
		if m := r.FindStringSubmatch(line); len(m) > 0 {
			found = true
			verbose(3, "CT found: %s", ctUrl)
			CERTS[cert].CTlog = CTURL + "id=" + m[1]
			break
		}
	}

	if !found {
		CERTS[cert].CTlog = "not found"
		reportError("%0x '%s' (%s): CT log missing!",
			cert.SerialNumber, cert.Subject.CommonName, certType)
	}
}

func checkDomains(cert *x509.Certificate) {
	if len(CONFIG["domains"]) < 1 {
		return
	}

	verbose(2, "%0x '%s' (leaf): checking approved domains...",
		cert.SerialNumber, cert.Subject.CommonName)

	var names []string

	names = append(names, cert.Subject.CommonName)
	names = append(names, cert.DNSNames...)

	checked := map[string]bool{}

	wildcards := 0
	for i, n := range names {
		match := false

		if _, found := checked[n]; found {
			verbose(3, "Already checked '%s'...", n)
			continue
		} else {
			verbose(3, "Checking '%s'...", n)
			checked[n] = true
		}

		if strings.HasPrefix(n, "*") {
			wildcards++
		}

		for _, domain := range strings.Split(CONFIG["domains"], ",") {
			domain = strings.TrimSpace(domain)
			verbose(4, "Checking domain '%s'...", domain)
			if strings.HasSuffix(n, "."+domain) || strings.EqualFold(n, domain) {
				match = true
				break
			}
		}
		if !match {
			which := "SAN"
			if i == 0 {
				which = "SN"
			}
			reportError("%0x '%s' (leaf): %s (%s) not in list of approved domains (%s).",
				cert.SerialNumber, cert.Subject.CommonName,
				which, n, CONFIG["domains"])
		}
	}

	if len(CONFIG["maxWildcards"]) > 0 {
		maxWildcards, _ := strconv.Atoi(CONFIG["maxWildcards"])
		if wildcards > maxWildcards {
			reportError("%0x '%s' (leaf): too many wildcards (%d > %d).",
				cert.SerialNumber, cert.Subject.CommonName, wildcards, maxWildcards)
		}
	}
}

func checkKeyLength(cert *x509.Certificate, certType string) {
	if len(CONFIG["keyLength"]) < 1 &&
		len(CONFIG["keyLengthECDSA"]) < 1 &&
		len(CONFIG["keyLengthRSA"]) < 1 {
		return
	}

	var foundKeyLength int

	/* We asserted int type of config parameter
	 * above, so no need to check for errors here. */
	wantedKeyLength, _ := strconv.Atoi(CONFIG["keyLength"])

	verbose(2, "%0x '%s' (%s): checking key length >= %d...",
		cert.SerialNumber, cert.Subject.CommonName,
		certType, wantedKeyLength)

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		foundKeyLength = pub.N.BitLen()
		if len(CONFIG["keyLengthRSA"]) > 0 {
			wantedKeyLength, _ = strconv.Atoi(CONFIG["keyLengthRSA"])
		}
	case *ecdsa.PublicKey:
		foundKeyLength = pub.Params().N.BitLen()
		if len(CONFIG["keyLengthECDSA"]) > 0 {
			wantedKeyLength, _ = strconv.Atoi(CONFIG["keyLengthECDSA"])
		}
	default:
		fmt.Fprintf(os.Stderr, "%s: Unknown pubkey type.\n", cert.SerialNumber)
	}

	CERTS[cert].KeyLength = foundKeyLength

	if foundKeyLength < wantedKeyLength {
		reportError("%0x '%s' (%s): keyLength mismatch (%d < %d)",
			cert.SerialNumber, cert.Subject.CommonName,
			certType, foundKeyLength, wantedKeyLength)
	}
}

func checkPinsAndRootSerials(cert *x509.Certificate) {
	if (len(CONFIG["pins"]) < 1) && (len(CONFIG["rootSerials"]) < 1) {
		return
	}

	verbose(2, "%0x '%s' (leaf): checking pins and root serials...",
		cert.SerialNumber, cert.Subject.CommonName)

	type CertPins struct {
		Pins map[string]string
	}

	foundPins := map[string]CertPins{}

	wantedPins := map[string]string{}
	wantedSerials := map[string]bool{}

	for _, p := range strings.Split(CONFIG["pins"], ",") {
		p = strings.TrimSpace(p)
		t := strings.SplitN(p, "/", 2)
		wantedPins[p] = t[0]
	}
	for _, r := range strings.Split(CONFIG["rootSerials"], ",") {
		r = strings.TrimSpace(r)
		r = strings.ToLower(r)
		wantedSerials[r] = true
	}

	pinFound := false
	serialFound := false
	for _, c := range CHAIN {
		serial := fmt.Sprintf("%0x", c.SerialNumber)

		verbose(3, "Checking pins for %s %s...", serial, c.Subject.CommonName)

		certPins, found := foundPins[serial]
		if !found {
			certPins = CertPins{make(map[string]string)}
		}

		for pinValue, pinType := range wantedPins {
			thisPin := certPins.Pins[pinType]
			if len(thisPin) < 1 {
				thisPin = certPin(c, pinType)
				certPins.Pins[pinType] = thisPin
			}
			if thisPin == pinValue {
				pinFound = true
				break
			}
		}

		_, serialFound = wantedSerials[serial]
		if pinFound || serialFound {
			break
		}
	}

	if !pinFound && !serialFound {
		reportError("%0x '%s' (leaf): no valid pin nor root serial found.",
			cert.SerialNumber, cert.Subject.CommonName)
	}
}

func checkSANs(cert *x509.Certificate) {
	if len(CONFIG["maxSANs"]) < 1 {
		return
	}
	maxSANs, _ := strconv.Atoi(CONFIG["maxSANs"])

	verbose(2, "%0x '%s' (leaf): checking max number of SANs <= %s...",
		cert.SerialNumber, cert.Subject.CommonName, CONFIG["maxSANs"])

	if maxSANs < len(cert.DNSNames) {
		reportError("%0x '%s' (leaf): too many SANs (%d > %d)",
			cert.SerialNumber, cert.Subject.CommonName,
			len(cert.DNSNames), maxSANs)
	}
}

func checkSigAlgs(cert *x509.Certificate, certType string) {
	sig := cert.SignatureAlgorithm.String()
	CERTS[cert].SigAlgo = sig

	if len(CONFIG["sigAlgs"]) < 1 {
		return
	}

	verbose(2, "%0x '%s' (%s): checking signature algorithm %s...",
		cert.SerialNumber, cert.Subject.CommonName, certType, sig)

	found := false
	for _, s := range strings.Split(CONFIG["sigAlgs"], ",") {
		s = strings.TrimSpace(s)
		if strings.EqualFold(s, sig) {
			found = true
			break
		}
	}

	if !found {
		reportError("%0x '%s' (%s): invalid signature algorithm (%s not in [%s])",
			cert.SerialNumber, cert.Subject.CommonName, certType, sig, CONFIG["sigAlgs"])
	}
}

func checkValidity(cert *x509.Certificate) {
	days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
	CERTS[cert].Validity = int(days)

	if len(CONFIG["maxValidity"]) < 1 {
		return
	}

	verbose(2, "%0x '%s' (leaf): checking validity <= %s...",
		cert.SerialNumber, cert.Subject.CommonName, CONFIG["maxValidity"])

	maxValidity, _ := strconv.Atoi(CONFIG["maxValidity"])

	if int(days) > maxValidity {
		reportError("%0x '%s' (leaf): validity > maxValidity (%d > %d)",
			cert.SerialNumber, cert.Subject.CommonName,
			int(days), maxValidity)
	}

	valid := time.Since(cert.NotAfter).Seconds()
	if valid > 0 {
		reportError("%0x '%s' (leaf): no longer valid",
			cert.SerialNumber, cert.Subject.CommonName)
	}
}

func certPin(cert *x509.Certificate, algo string) (pin string) {

	verbose(4, "Calculating %s pin for %0x...", algo, cert.SerialNumber)

	pk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshall pubkey for %0x\n",
			cert.SerialNumber)
		return
	}

	switch algo {
	case "sha1":
		var p [sha1.Size]byte
		p = sha1.Sum(pk)
		pin = base64.StdEncoding.EncodeToString(p[:])
	case "sha256":
		var p [sha256.Size]byte
		p = sha256.Sum256(pk)
		pin = base64.StdEncoding.EncodeToString(p[:])
	default:
		fmt.Fprintf(os.Stderr, "Unsupported pin type '%s'.\n", algo)
	}

	pin = fmt.Sprintf("%s/%s", algo, pin)

	verbose(4, "%s pin for %0x is: %s", algo, cert.SerialNumber, pin)
	return
}

func expandTilde(in string) (out string) {
	out = in
	if in[0] != '~' {
		return
	}

	verbose(2, "Expanding ~ in '%s'...", in)
	if in[1] == '/' {
		if u, err := user.Current(); err == nil {
			out = u.HomeDir + in[1:]
		}
	} else {
		i := strings.Index(in, "/")
		if i > 0 {
			t := in[1:i]
			if u, err := user.Lookup(t); err == nil {
				out = u.HomeDir + in[i:]
			}
		}
	}

	return
}

func extractCertificates(input io.ReadCloser, certType string) {
	verbose(1, "Extracting certificates of type '%s' from input...", certType)

	var pemInput string
	issuers := map[string]bool{}

	seenCerts := make(map[string]bool)

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "-----END CERTIFICATE-----" {
			pemInput += line + "\n"

			block, _ := pem.Decode([]byte(pemInput))
			if block == nil {
				fail("Unable to decode certificate.")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fail("Unable to parse certificate: %s", err)
			}

			verbose(2, "Extracted: %0x '%s'", cert.SerialNumber, cert.Subject.CommonName)
			serial := fmt.Sprintf("%0x", cert.SerialNumber)
			if _, found := seenCerts[serial]; found {
				reportError("Duplicate cert in input: %s '%s'",
					serial, cert.Subject.CommonName)
				continue
			} else {
				seenCerts[serial] = true
			}

			CERTS[cert] = &CertInfo{CertType: "leaf"}
			if certType == "root" {
				CERTS[cert].CertType = "root"
			} else if cert.Issuer.CommonName != cert.Subject.CommonName {
				issuers[cert.Issuer.CommonName] = true
			} else if certType == "chain" {
				reportError("Self-signed / root certificate found in chain: %0x '%s'", cert.SerialNumber, cert.Subject.CommonName)
			}

			pemInput = ""
		}
		if line == "-----BEGIN CERTIFICATE-----" {
			pemInput = line + "\n"
		} else if len(pemInput) > 0 {
			pemInput += line + "\n"
		}
	}

	for c, _ := range CERTS {
		if _, found := issuers[c.Subject.CommonName]; found {
			if c.Subject.CommonName == c.Issuer.CommonName {
				CERTS[c].CertType = "root"
				ROOTS.AddCert(c)
			} else {
				CERTS[c].CertType = "intermediate"
				INTERMEDIATES.AddCert(c)
			}
		}

		if CERTS[c].CertType == "leaf" {
			buildChain(c)
		}
	}
}

func fail(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
	os.Exit(EXIT_FAILURE)
}

func getCertchainFromServer() {

	server := fmt.Sprintf("%s:%s", CONFIG["server"], CONFIG["port"])

	verbose(1, "Retrieving certificate chain in use on '%s'...", server)

	sclient := []string{"s_client", "-showcerts", "-connect", server}
	verbose(2, "Running openssl %s...", sclient)

	cmd := exec.Command("openssl", sclient...)
	cmd.Stdin = nil

	var cmdErr bytes.Buffer
	cmd.Stderr = &cmdErr

	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		fail("Unable to create StdoutPipe: %s", err)
	}

	if err := cmd.Start(); err != nil {
		fail("Unable to start command: %s", err)
	}

	extractCertificates(cmdOut, "chain")

	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to %s: %s\n", server, cmdErr.String())
	}

	if strings.Contains(cmdErr.String(), ":error:") {
		fmt.Fprintf(os.Stderr, "'openssl s_client' failed: %s\n", cmdErr.String())
	}
}

func getopts() {
	eatit := false
	args := os.Args[1:]
	for i, arg := range args {
		if eatit {
			eatit = false
			continue
		}
		switch arg {
		case "-V":
			printVersion()
			os.Exit(EXIT_SUCCESS)
		case "-S":
			eatit = true
			argcheck("-S", args, i)
			CONFIG["sni"] = args[i+1]
		case "-c":
			eatit = true
			argcheck("-c", args, i)
			CONFIG["configFile"] = args[i+1]
		case "-h":
			usage(os.Stdout)
			os.Exit(EXIT_SUCCESS)
		case "-l":
			CONFIG["list"] = "true"
		case "-p":
			eatit = true
			argcheck("-p", args, i)
			CONFIG["port"] = args[i+1]
		case "-s":
			eatit = true
			argcheck("-s", args, i)
			CONFIG["server"] = args[i+1]
		case "-v":
			VERBOSITY++
		default:
			fmt.Fprintf(os.Stderr, "Unexpected option or argument: %v\n", args[i])
			usage(os.Stderr)
			os.Exit(EXIT_FAILURE)
		}
	}

	if len(CONFIG["configFile"]) < 1 {
		var f string
		if u, err := user.Current(); err == nil {
			f = fmt.Sprintf("%s/.certdiffrc", u.HomeDir)
			if _, err = os.Stat(f); err == nil {
				CONFIG["configFile"] = f
			}
		}
		if len(f) < 0 {
			if _, err := os.Stat("/etc/certdiffrc"); err != nil {
				CONFIG["configFile"] = f
			}
		}
	}
}

func listCertInfo() {
	if CONFIG["list"] != "true" {
		return
	}

	for c, cinfo := range CERTS {
		if cinfo.CertType != "leaf" {
			continue
		}

		sans := c.DNSNames
		sort.Strings(sans)

		fmt.Printf("\n")
		fmt.Printf("CN         : %s\n", c.Subject.CommonName)
		fmt.Printf("Serial     : %0x\n", c.SerialNumber)
		fmt.Printf("Validity   : %d\n", cinfo.Validity)
		fmt.Printf("Verified   : %s\n", cinfo.Verified)
		fmt.Printf("SANs       : %s\n", strings.Join(sans, ", "))
		fmt.Printf("KeyLength  : %d\n", cinfo.KeyLength)
		fmt.Printf("Pins       : %s, %s\n", certPin(c, "sha1"), certPin(c, "sha256"))
		fmt.Printf("SigAlgo    : %s\n", cinfo.SigAlgo)
		fmt.Printf("CT log     : %s\n", cinfo.CTlog)
		fmt.Printf("\n")
	}
}

func parseConfig() {
	fname := CONFIG["configFile"]

	if len(fname) < 1 {
		verbose(1, "No config file found, only checking basic defaults...")
		return
	}

	verbose(1, "Parsing config file '%s'...", fname)
	fd, err := os.Open(fname)
	if err != nil {
		fail("Unable to open '%s': %v", fname, err)
	}
	defer fd.Close()

	n := 0
	input := bufio.NewReader(fd)
	for {
		data, err := input.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Unable to read input: %v\n", err)
			}
			break
		}

		/* Ignore everything after '#' */
		line := strings.Split(string(data), "#")[0]
		line = strings.TrimSpace(line)

		n++

		if len(line) == 0 {
			continue
		}

		keyval := strings.SplitN(line, "=", 2)
		if len(keyval) != 2 {
			fail("Invalid line in configuration file '%s', line %d.",
				fname, n)
		} else {
			key := strings.TrimSpace(keyval[0])
			val := strings.TrimSpace(keyval[1])
			switch key {
			case "ct":
				re := regexp.MustCompile(`(?i)(0|1|no|yes|false|true)$`)
				m := re.FindStringSubmatch(val)
				if len(m) > 0 {
					if m[1] == "0" || m[1] == "no" || m[1] == "false" {
						CONFIG["ct"] = "false"
					} else {
						CONFIG["ct"] = "true"
					}
				} else {
					fmt.Fprintf(os.Stderr, "Ignoring invalid value '%s' for 'ct' on line %d.\n",
						val, n)
				}
			case "cabundle":
				fallthrough
			case "domains":
				fallthrough
			case "pins":
				fallthrough
			case "rootSerials":
				fallthrough
			case "sigAlgs":
				CONFIG[key] = val
			case "keyLength":
				fallthrough
			case "keyLengthECDSA":
				fallthrough
			case "keyLengthRSA":
				fallthrough
			case "maxValidity":
				fallthrough
			case "maxSANs":
				fallthrough
			case "maxWildcards":
				i, err := strconv.Atoi(val)
				if err != nil || i < 0 {
					fail("Invalid value for '%s' on line %d.",
						key, n)
				}
				CONFIG[key] = val
			default:
				fmt.Fprintf(os.Stderr, "Ignoring unknown key value '%s' on line %d.\n",
					key, n)
			}
		}
	}
}

func printVersion() {
	fmt.Printf("%v version %v\n", PROGNAME, VERSION)
}

func reportError(format string, v ...interface{}) {
	if CONFIG["list"] != "true" {
		RVAL++
		fmt.Printf(format+"\n", v...)
	}
}

func sortCerts() (certs []*x509.Certificate) {
	verbose(3, "Sorting certificates by serial number...")

	var serials []string
	certsBySerial := map[string]*x509.Certificate{}

	for c, _ := range CERTS {
		s := fmt.Sprintf("%0x", c.SerialNumber)
		serials = append(serials, s)
		certsBySerial[s] = c
	}

	sort.Strings(serials)

	for _, s := range serials {
		verbose(4, "Adding (in order): %s", s)
		certs = append(certs, certsBySerial[s])
	}

	return
}

func usage(out io.Writer) {
	usage := `Usage: %v [-Vhlv] [-S sni] [-p port] [-s server] [-c configFile]
	-V         print version information and exit
	-S sni     specify the Server Name Indication to use
	-c config  read configuration from this file
	-l         list cert properties only
	-h         print this help and exit
        -p port    use this port on the server
        -s server  inspect the certificate of this server
	-v         be verbose
`
	fmt.Fprintf(out, usage, PROGNAME)
}

func verifyCert(cert *x509.Certificate) {
	verbose(2, "%0x '%s' (leaf): verifying certificate...",
		cert.SerialNumber, cert.Subject.CommonName)

	name := CONFIG["server"]
	if len(name) < 1 {
		name = cert.Subject.CommonName
	}

	if sni, found := CONFIG["sni"]; found {
		name = sni
	}

	/* We only want to verify the name and chain;
	 	 * expiration was already checked elsewhere, so
		 * we may cheat on CurrentTime. */
	opts := x509.VerifyOptions{
		CurrentTime:   cert.NotAfter,
		DNSName:       name,
		Intermediates: INTERMEDIATES,
	}

	valid := "valid"
	if _, err := cert.Verify(opts); err != nil {
		reportError("%0x '%s' (leaf): Unable to verify validity: %v",
			cert.SerialNumber, cert.Subject.CommonName, err.Error())
		valid = err.Error()
	}

	CERTS[cert].Verified = valid
}

func verbose(level int, format string, v ...interface{}) {
	if level <= VERBOSITY {
		fmt.Fprintf(os.Stderr, "%s ", time.Now().Format("2006-01-02 15:04:05"))
		for i := 0; i < level; i++ {
			fmt.Fprintf(os.Stderr, "=")
		}
		fmt.Fprintf(os.Stderr, "> "+format+"\n", v...)
	}
}

/*
 * Main
 */

func main() {
	getopts()
	parseConfig()
	buildCABundle()

	if len(CONFIG["server"]) > 0 {
		getCertchainFromServer()
	} else {
		extractCertificates(os.Stdin, "chain")
	}

	checkCerts()
	listCertInfo()
	os.Exit(RVAL)
}
