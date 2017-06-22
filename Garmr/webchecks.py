from urlparse import urlparse
import requests
from Garmr.scanner import ActiveTest, PassiveTest, Scanner


class RobotsTest(ActiveTest):
    run_passives = True
    description = "Check for the presence of a robots.txt file. If save_contents is true, the contents will be saved."
    config = {"save_contents" : "False"}
    def do_test(self, url):
        u = urlparse(url)
        roboturl="%s://%s/robots.txt" % (u.scheme, u.netloc)
        sess = self.sessions[self.url]
        response = sess.get(roboturl)
        if response.status_code == 200:
            result = self.result("Pass", "A robots.txt file is present on the server",
                                 response.content if self.config["save_contents"].lower() == "true" else None)
        else:
            result = self.result("Fail", "No robots.txt file was found.", None)
        return (result, response);

def configure(scanner):
    if isinstance(scanner, Scanner) == False:
        raise Exception("Cannot configure a non-scanner object!")
    scanner.register_check(RobotsTest())
