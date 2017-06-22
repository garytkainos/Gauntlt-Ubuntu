from urlparse import urlparse
import requests
from Garmr.scanner import ActiveTest, PassiveTest, Scanner


class SessionTest(ActiveTest):
    pass

class CaptchaTest(ActiveTest):
    pass


class LoginTest(ActiveTest):
    '''04:43:14 PM) Yvan Boily: so here is an example; this provides a basic configurable authentication check; the username and password fields are configurable, as are the username and password.
     the post data is assembled using a built in format that will work with many authentication forms, and the test assumes (naively) that a 200 response is a successful login
(04:43:27 PM) Yvan Boily: (the description needs to be updated :P)
(04:44:22 PM) Yvan Boily: the do_test method on ActiveTest could be simply extended to accept a second and third paramter:
(04:44:43 PM) Yvan Boily:    def do_test(self, url, state, preserve):
(04:45:25 PM) Yvan Boily: the state object would be passed in, and the preserve parameter indicates that the test should not modify the state object if it is set to true
(04:45:30 PM) freddy: we could just change it to do_test(self, url, *args) and be more precise in the subclass
(04:46:14 PM) Yvan Boily: it is possible to do that, but I am not a fan of that style.  I don't have a better argument than that, so if you want to go that route, feel free :D'''

    run_passives = True
    description = "check if login works"
    config = {
              "uid_field" : "username",
              "pwd_field" : "password",
              "username" : "admin",
              "password" : "admin",
              "format" : "%s=%s&%s=%s"
    }

    # eventing needs to be implemented
    events = { "Pass": SessionTest,
                "Error": CaptchaTest,
                "Fail": CaptchaTest }

    def do_test(self, url):
        u = urlparse(url)
        post_data = config['format'] % (config["uid_field"] , config["username"], config["pwd_field"], config["password"])
        response = requests.post(url, post_data)
        if "Login successful" in response.content:
            # scrape response for indicators of a successful login
            result = self.result("Pass", "Authentication was successful", None)
        else:
            result = self.result("Fail", "Authentication failed", None)
        return (result, response)





def configure(scanner):
    #if isinstance(scanner, Scanner) == False:
    #    raise Exception("Cannot configure a non-scanner object!")
    scanner.register_check(LoginTest())


