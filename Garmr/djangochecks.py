from urlparse import urlparse
import requests
from Garmr.scanner import ActiveTest, PassiveTest, Scanner, HtmlTest


class AdminAvailable(ActiveTest):
    run_passives = True
    config = {"path" : "admin"}

    def do_test(self, url):
        u = urlparse(url)
        adminurl="%s://%s/%s" % (u.scheme, u.netloc, self.config["path"])
        sess = self.sessions[self.url]
        response = sess.get(adminurl)
        if response.status_code == 200:
            result = self.result("Pass", "Django admin page is present at %s." % adminurl, response.content)
        else:
            result = self.result("Fail", "Default Django admin page is not present at %s" % adminurl, None)
        return (result, response);


class ProvokeError404(ActiveTest):
    run_passives = True # we need IsDebugModeReallyEnabled
    def do_test(self, url):
        sess = self.sessions(url)
        url += '76976cd1a3cbadaf77533a' #random garbage
        response = sess.get(url)
        result = self.result('Skip', 'This test cannot Pass or Fail, because it relies on the subsequent passive IsDebugModeReallyEnabled test', response)
        return result, response

class IsDebugModeReallyEnabled(HtmlTest):
    description = ''
    secure_only = False
    def analyze_html(self, response, soup):
        # we dont really analye the soup,  but that's ok;p
        error_str = "You're seeing this error because you have" #from django source django/views/debug.py - maybe subject to change
        if error_str in response.content:
            result = self.result('Fail', 'Typical string of echnical 404/500 error page found', None)
        else:
            result = self.result('Pass', 'Debug strings not found', response)
        return result


def configure(scanner):
    if isinstance(scanner, Scanner) == False:
        raise Exception("Cannot configure a non-scanner object!")
        raise Exception("Cannot configure a non-scanner object!")
    scanner.register_check(AdminAvailable())

