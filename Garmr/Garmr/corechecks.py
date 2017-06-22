from urlparse import urlparse, urljoin
import requests
from scanner import ActiveTest, PassiveTest, HtmlTest, Scanner

class HttpOnlyAttributePresent(PassiveTest):
    description = "Inspect the Set-Cookie: header and determine if the HttpOnly attribute is present."
    def analyze(self, response):
        cookieheader = "Set-Cookie"
        has_cookie = cookieheader in response.headers
        if has_cookie:
            if "httponly" in response.headers[cookieheader].lower():
                result = self.result("Pass", "HttpOnly is set", response.headers[cookieheader])
            else:
                result = self.result("Fail", "HttpOnly is not set", response.headers[cookieheader])
        else:
            result = self.result("Skip", "No cookie is set by this response.", None)
        return result

class SecureAttributePresent(PassiveTest):
    description = "Inspect the Set-Cookie: header and determine if the Secure attribute is present."
    def analyze(self, response):
        url = urlparse(response.url)
        cookieheader = "Set-Cookie"
        has_cookie = cookieheader in response.headers
        if has_cookie:
            if "secure" in response.headers[cookieheader].lower():
                if url.scheme == "https":
                    result = self.result("Pass", "Secure cookie attribute is set", response.headers[cookieheader])
                else:
                    result = self.result("Fail", "Secure cookie attribute should only be set for cookies sent over SSL.", response.headers[cookieheader])
            else:
                if url.scheme == "https":
                    result = self.result("Fail", "Secure cookie attribute is not set", response.headers[cookieheader])
                else:
                    result = self.result("Pass", "The secure attribute is not set (expected for HTTP)", response.headers[cookieheader])
        else:
            result = self.result("Skip", "No cookie is set by this response.", None)
        return result


class StrictTransportSecurityPresent(PassiveTest):
    secure_only = True
    description = "Check if the Strict-Transport-Security header is present in TLS requests."
    def analyze(self, response):
        stsheader = "Strict-Transport-Security"
        sts = stsheader in response.headers
        if sts == False:
            result = self.result("Fail", "Strict-Transport-Security header not found.", None)
        else:
            result = self.result("Pass", "Strict-Transport-Security header present.", response.headers[stsheader])
        return result

class XFrameOptionsPresent(PassiveTest):
    description = "Check if X-Frame-Options header is present."
    def analyze(self, response):
        xfoheader = "X-Frame-Options"
        xfo = xfoheader in response.headers
        if xfo == False:
            result = self.result("Fail", "X-Frame-Options header not found.", None)
        else:
            result = self.result("Pass", "X-Frame-Options header present.", response.headers[xfoheader])
        return result

class Http200Check(ActiveTest):
    run_passives = True
    description = "Make a GET request to the specified URL, reporting success only on a 200 response without following redirects"
    def do_test(self, url):
        sess = self.sessions[self.url]
        response = sess.get(url, allow_redirects=False)
        if response.status_code == 200:
            result = self.result("Pass", "The request returned an HTTP 200 response.", None)
        else:
            result = self.result("Fail", "The response code was %s" % response.status_code, None)
	return (result, response)

class WebTouch(ActiveTest):
     run_passives = True
     description = "Make a GET request to the specified URL, and check for a 200 response after resolving redirects."
     def do_test(self, url):
         sess = self.sessions[self.url]
         response = sess.get(url)
         if response.status_code == 200:
             result = self.result("Pass", "The request returned an HTTP 200 response.", None)
         else:
             result = self.result("Fail", "The response code was %s" % response.status_code, None)
         return (result, response)


class StsPresentCheck(ActiveTest):
    insecure_only = False
    run_passives = True
    description = "Inspect the second response in the Strict-Transport-Security redirect process according to http://tools.ietf.org/html/draft-hodges-strict-transport-sec"
    events = {}
    def do_test(self, url):
        stsheader = "Strict-Transport-Security"
        #XXX hack: we should take response isntead
        url = url.replace('http:', 'https:')
        #XXX end of hack
        sess = self.sessions[self.url]
        response = sess.get(url, allow_redirects=False)
        if stsheader in response.headers:
            result = self.result('Pass', 'Subsequential HTTPS Response for STS contained corresponding STS header', None)
        else:
            result = self.result('Fail', 'Subsequential HTTPS Response did not contain STS header', None)
        return (result, response)

class StsRedirectCheck(ActiveTest):
    insecure_only = True
    run_passives = True
    description = "Inspect the first response in the Strict-Transport-Security redirect process according to http://tools.ietf.org/html/draft-hodges-strict-transport-sec"
    events = { "Pass": StsPresentCheck,
            "Error": None,
            "Fail": None }

    def do_test(self, url):
        stsheader = "Strict-Transport-Security"
        u = urlparse(url)
        if u.scheme == "http":
            sess = self.sessions[self.url]
            response = sess.get(url, allow_redirects=False)
            invalid_header = stsheader in response.headers
            is_redirect = response.status_code == 301
            bad_redirect = False
            if is_redirect == True:
                redirect = response.headers['location']
                r = urlparse(redirect) #XXX do we need to check for same-domain? see sts draft!
                if r.scheme != 'https':
                    pass
                else:
                    bad_redirect = True

            #continue w/ Pass to see if next location contains stsheader?
            next_test = (invalid_header == False) and (is_redirect == True) and (bad_redirect == False)
            if next_test == True:
                message = "The STS upgrade occurs properly (no STS header on HTTP, a 301 redirect, and an STS header in the subsequent request."
            else:
                message = "%s%s%s" % (
                    "The initial HTTP response included an STS header (RFC violation)." if invalid_header else "",
                    "" if is_redirect else "The initial HTTP response should be a 301 redirect (RFC violation see ).",
                    "The 301 location must use the https scheme." if bad_redirect else ""
                    )
            result = self.result('Pass' if next_test else 'Fail', message, None)
            return (result, response)

        else:
            #XXX maybe just /change/ the scheme to enforce checking?
            result = self.result('Skip', 'Not checking for STS-Upgrade on already-secure connection', None)
            return result, None



class CSPHeaderCheck(ActiveTest):
    # please revise after another readthrough of https://wiki.mozilla.org/Security/CSP/Specification#Sample_Policy_Definitions necessary
    insecure_only = False
    run_passives = True
    description = "Checks if the CSP Header is present and links to a policy. If it does, we will forward to another test to check if it present"
    def do_test(self, url):
        cspheader = "Content-Security-Policy"
        csproheader = 'Content-Security-Policy-Report-Only'
        sess = self.sessions[self.url]
        response = sess.get(url, allow_redirects=False)
        if cspheader in response.headers or csproheader in response.headers:
            result = self.result('Pass', 'CSP Header present.', None)
        else:
            result = self.result('Fail', 'No %s or %s in headers' % (cspheader, csproheader), None)
        return (result, response)


class HttpsLoginForm(HtmlTest):
    description = "Check that html forms with password-type inputs point to https"
    def analyze_html(self, response, soup):
        url = urlparse(response.url)
        forms = soup.findAll('form')
        # look only at those form elements that have password type input elements as children
        forms = filter(lambda x: x.findChildren("input", type="password") ,forms)
        if len(forms) == 0:
            result = self.result("Skip", "There are no login forms on this page", None)
            return result
        failforms = []
        for form in forms:
            if url.scheme == "https":
                if form['action'].startswith('http:'):
                    failforms.append(form)
            else:
                if not form['action'].startswith('https'):
                    failforms.append(form)
        if len(failforms) == 0:
            result = self.result("Pass", "All login forms point to secure resources", forms)
        else:
            result = self.result("Fail", "There are login forms pointing to insecure locations", failforms)
        return result


class HttpsResourceOnHttpsLink(HtmlTest):
    # also called 'mixed content'
    description = "Check if all external resources are pointing to https links, when on https page"
    secure_only = True
    def analyze_html(self, response, soup):
        ''' there is a list on stackoverflow[1] which claims to contain
            all possible attributes hat may carry a URL. is
            there a way to confirm this list is exhaustive?
            I have removed attributes which are just links/pointers,
            we only want those attributes to resources, the browser
            downloads automatically
        [1] http://stackoverflow.com/questions/2725156/complete-list-of-html-tag-attributes-which-have-a-url-value/2725168#2725168
        '''
        attrlist = ['codebase', 'background', 'src', 'usemap', 'data', 'icon', 'manifest', 'poster', 'archive']
        failtags = []
        for tag in soup.findAll(True):
            for attr in attrlist:
                    if tag.has_key(attr):
                        val = tag[attr]
                        if val.startswith('http:'):
                            failtags.append(tag)
        if len(failtags) == 0:
            result = self.result("Pass", "All external resources are https", None)
        else:
            result = self.result("Fail", "There are links to insecure locations", failtags)
        return result

class InlineJS(HtmlTest):
    description = "complain about inline JS to improve migration to CSP"
    def analyze_html(self, response, soup):
        url = urlparse(response.url)
        scripts = soup.findAll('script')
        if len(scripts) == 0:
            result = self.result ("Skip", "There are no script tags.", None)
            return result
        inlinescripts = filter(lambda x: len(x.text) > 0, scripts)
        if len(inlinescripts) == 0:
            result = self.result("Pass", "No inline JavaScript found", None)
        else:
            result = self.result("Fail", "Inline JavaScript found", inlinescripts)
        return result


def configure(scanner):
    if isinstance(scanner, Scanner) == False:
        raise Exception("Cannot configure a non-scanner object!")
    scanner.register_check(Http200Check)
    scanner.register_check(WebTouch)
    scanner.register_check(StrictTransportSecurityPresent)
    scanner.register_check(XFrameOptionsPresent)
    scanner.register_check(StsRedirectCheck)
    scanner.register_check(HttpOnlyAttributePresent)
    scanner.register_check(SecureAttributePresent)
    scanner.register_check(HttpsLoginForm)
    scanner.register_check(HttpsResourceOnHttpsLink)
    scanner.register_check(InlineJS)
    scanner.register_check(CSPHeaderCheck)
