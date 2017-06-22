from datetime import datetime
from reporter import Reporter
from urlparse import urlparse
from BeautifulSoup import BeautifulSoup
import ConfigParser
import logging
import requests
import socket
import traceback
from inspect import getargspec
import subprocess
import json



def exec_helper(cmd, args=None):
    '''Use this function to call helpers, not to perform checks!
    The example use-case would a Testcase that required to get an
    authentication tokenout of a mailbox to complete a login procedure.
    The email-fetching would be done as a helper
    '''
    if not args:
        params = cmd
    else:
        params = [cmd] + args # becomes [cmd, arg1, arg2]
    try:
        output = subprocess.Popen(params, stdout=subprocess.PIPE).communicate()[0] # use Popen instead of subprocess.get_output for Python2.6 compatibility
        try:
            res = json.loads(output)
        except ValueError:
            return {"result":"Fail", "message":"Invalid JSON data", "data":""}
        if 'result' in res and 'message' in res and 'data' in res:
            return res
        else:
            return {"result":"Fail", "message":"Incomplete JSON data. Your helper should return a dict with the keys result, message and data.", "data":""}
    except subprocess.CalledProcessError as e: # raised when? for Popen?
        return {"result":"Fail", "message":"The helper script returned with a non-zero returnvalue", "data": e.output}

class PassiveTest():
    secure_only = False
    insecure_only = False

    def analyze(self, response, results):
        return None

    def result(self, state, message, data):
        return {'state' : state,  'message' : message, 'data' : data }


class ActiveTest():
    new_session = False # enable  (e.g. from cli) to enforce new session generation
    secure_only = False
    insecure_only = False
    run_passives = True
    description = "The base class for an Active Test."
    sessions = {}

    def __init__(self):
        if hasattr(self, "setup"):
            self.setup()

    #def get_url(self, url, status = True):
    #    try:
    #        sess = self.sessions[self.url]
    #    except KeyError:
    #        sess = requests.session()
    #    #print "Issue request towards %s using %s" % (url, sess.cookies)
    #    r = sess.get(url, allow_redirects = False)
    #    print url, r.status_code, status
    #    if status:
    #        r.raise_for_status()
    #    return r

    def execute(self, url, predecessor=None):
        self.url = url
        if self.url not in self.sessions or self.new_session:
            self.sessions[url] = requests.session() # Create per-target session
        try:
            if "pred" in getargspec(self.do_test).args:
                resulttuple = self.do_test(url, predecessor)
            else:
                resulttuple = self.do_test(url)
        except Exception, e:
            tb = traceback.format_exc()
            resulttuple = (ActiveTest().result("Error", e, tb), None)

        return resulttuple

    def result(self, state, message, data):
        return { 'state' : state, 'message' : message, 'data' : data, 'passive' : {}}

class HtmlTest(PassiveTest):
    description = 'allow easy analysis of html source code'
    def analyze(self, response):
        if 'text/html' in response.headers['content-type']:
            soup = BeautifulSoup(response.content)
            return self.analyze_html(response, soup)
        else:
            result = self.result("Skip", "Content-type is not html "+ response.headers['content-type'], None)
            return result

    def analyze_html(self, response, soup):
        """ implement this method in subclass"""
        pass

class Scanner():
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s')
    logger = logging.getLogger("Garmr-Scanner")
    logger.setLevel(logging.DEBUG)

    def __init__(self):
        self.resolve_target = True
        self.force_passives = False
        self._disabled_tests_ = []
        self._passive_tests_ = []
        self._active_tests_ = []
        self._finished_active_tests_ = []
        self._targets_ = []
        self._protos_ = ["http", "https"]
        Scanner.logger.debug("Scanner initialized.")
        self.reporter = Reporter()
        self.modules = []

    def do_passive_scan(self, passiveclass, is_ssl, response):
        if passiveclass.secure_only and not is_ssl:
            Scanner.logger.debug("\t\t[%s] Skip Test invalid for http scheme" % passiveclass)
            passive_result = PassiveTest().result("Skip", "This check is only applicable to SSL requests.", None)
            start = datetime.now()
            passive_result['start'] = start
            passive_result['end'] = start
            passive_result["duration"] = 0
        else:
            start = datetime.now()
            passive = passiveclass()
            passive_result = passive.analyze(response)
            end = datetime.now()
            td = end - start
            passive_result['start'] = start
            passive_result['end'] = end
            passive_result['duration'] = float((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6)) / 10**6
            Scanner.logger.info("\t\t[%s] %s %s" % (passiveclass, passive_result['state'], passive_result['message']))
        return passive_result

    def do_active_scan(self, testclass, is_ssl, target):
        ''' instantiate the class and run it against the specified target, if applicable '''
        if (testclass.secure_only and not is_ssl):
            Scanner.logger.info("\t[Skip] [%s] (reason: secure_only)" % testclass)
            result = ActiveTest().result("Skip", "This check is only applicable to SSL requests", None)
            result['start'] = datetime.now()
            result['end'] = result['start']
            result['duration'] = 0
            return result
        elif (testclass.insecure_only and is_ssl):
            Scanner.logger.info("\t[Skip] [%s] (reason: insecure_only)" % testclass)
            result = ActiveTest().result("Skip", "This check is only applicable to SSL requests", None)
            result['start'] = datetime.now()
            result['end'] = result['start']
            result['duration'] = 0
            return result
        elif str(testclass).split('.')[-1] in self._disabled_tests_:
            Scanner.logger.info("\t[Skip] [%s] (reason: disabled)" % testclass)
            result = ActiveTest().result("Skip", "This check was marked as disabled.", None)
            result['start'] = datetime.now()
            result['end'] = result['start']
            result['duration'] = 0
            return result
        start = datetime.now()
        test = testclass() # from now on we have an instance of the class
        if "pred" in getargspec(test.do_test).args:
            # Check if class accepts this parameter. avoids rewriting.
            predecessor_results = self.results[self._finished_active_tests_[-1]]
            result, response = test.execute(target, predecessor=predecessor_results)
        else:
            result, response = test.execute(target)
        end = datetime.now()
        td = end - start
        result['response'] = response
        result['start'] = start
        result['end'] = end
        result['duration'] = float((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6)) / 10**6
        Scanner.logger.info("\t[%s] %s %s" % (testclass, result['state'], result['message']))
        self.reporter.write_active(testclass, result)
        if (result['state'] == "Error"):
            Scanner.logger.error(result['data'])
        if response != None and test.run_passives:
            result['passive'] = {}
            self.reporter.start_passives()
            for passive_testclass in self._passive_tests_:
                result["passive"][passive_testclass] = self.do_passive_scan(passive_testclass, is_ssl, response)
                self.reporter.write_passive(passive_testclass, result["passive"][passive_testclass])
            self.reporter.end_passives()
        return result

    def scan_target(self, target):
        ''' iterate over registered tests and deligate for scan '''
        self.reporter.write_target(target)
        Scanner.logger.info("[%s] scanning:" % target)
        url = urlparse(target)
        is_ssl = url.scheme == "https"
        self.results = {}
        self.reporter.start_actives()
        self.active_tests_stack = self._active_tests_
        while len(self.active_tests_stack) > 0:
            testclass = self.active_tests_stack[0]
            self.active_tests_stack = self.active_tests_stack[1:]
            self.results[testclass] = self.do_active_scan(testclass, is_ssl, target)
            if hasattr(testclass, 'events'): #TODO enforce every test to have event dict present?
                events_lower = dict([(k.lower(),v) for k,v in testclass.events.items()])
                if self.results[testclass]['state'].lower() in events_lower and events_lower[self.results[testclass]['state'].lower()] != None:
                   nexttest = events_lower[self.results[testclass]['state'].lower()]
                   Scanner.logger.info("\t[%s] Instantiated because %s declares it as its successor (the event was '%s')" %  (nexttest, testclass, self.results[testclass]['state']))
                   self.active_tests_stack.append(nexttest) # we have to hand over the response!!1, # important: we hand over an instance, not the class
            self._finished_active_tests_.append(testclass)
        self.reporter.end_actives()
        return self.results

    def run_scan(self):
        ''' iterate over target and deligate to list of tests '''
        results = {}
        self.reporter.start_report()
        self.reporter.start_targets()
        if len(self._targets_) == 0:
            Scanner.logger.error('No targets configured.')
            return
        for target in self._targets_:
            try:
                results[target] = self.scan_target(target)
            except:
                Scanner.logger.error(traceback.format_exc())
        self.reporter.end_targets()
        file = open(self.output, "w")
        file.write(self.reporter.end_report())
        file.close()


    def register_target(self, url):
        ''' add target to the scanning engine '''
        u = urlparse(url)
        valid = u.netloc != "" and u.scheme in self._protos_
        reason = "%s%s" % ("[bad netloc]" if u.netloc == "" else "", "" if u.scheme in self._protos_ else "[bad scheme]")

        # todo - support ipv6 urls
        host = u.netloc.split(':')[0]
        if (self.resolve_target):
            try:
                socket.getaddrinfo(host, None)
            except socket.gaierror:
                valid = False
                reason = "%s[dns]" % reason
        else:
            valid = True
        if valid:
            self._targets_.append(url)
            Scanner.logger.debug("[target]: %s" % url)
            return
        Scanner.logger.error("%s is not a valid target (reason: %s)" % (url, reason))

    def configure_check(self, check_name, key, value):
        if check_name in map(lambda x: str(x), self._active_tests_):
            index = map(lambda x: str(x), self._active_tests_).index(check_name)
            check = self._active_tests_[index]
        if check_name in map(lambda x: str(x), self._passive_tests_):
            index = map(lambda x: str(x), self._active_tests_).index(check_name)
            check = self._active_tests_[index]
        else:
            raise Exception("The requested check is not available (%s)" % check_name)
        if hasattr(check, "config") == False:
            raise Exception("This check cannot be configured.")
        if check.config.has_key(key) == False:
            raise Exception("%s is not a valid configuration for %s", key, check_name)
        check.config[key] = value
        Scanner.logger.debug("\t%s.%s=%s" % (check_name, key, value))

    def disable_check(self, check_name):
        ''' add a previously added test to a blacklist of test that are to be skipped '''
        if check_name in map(lambda x: str(x).split('.')[-1], self._active_tests_) or check_name in map(lambda x: str(x).split('.')[-1], self._passive_tests_):
            self._disabled_tests_.append(check_name)
            Scanner.logger.debug("\t%s disabled.", check_name)
        else:
            print "The requested check is not available (%s)" % check_name  
            print "The list of available checks is %s for actives and %s for passives" % (map(lambda x: str(x).split('.')[-1], self._active_tests_), map(lambda x: str(x).split('.')[-1], self._passive_tests_))
            Scanner.logger.debug("\t%s NOT disabled, because it could not be found.", check_name)

    def register_check(self, test):
        ''' add a test to the scanner '''
        module = test.__module__

        if module not in self.modules:
            self.modules.append(module)

        if hasattr(test, "execute"):
            self._active_tests_.append( test)
            Scanner.logger.debug("Added %s to active tests." % test)
            return len(self._active_tests_)
        if hasattr(test, "analyze"):
            self._passive_tests_.append( test)
            Scanner.logger.debug("Added %s to passive tests." % test)
            return len(self._passive_tests_)
        raise Exception('test is not a valid test type')

    def save_configuration(self, path):
        pass #XXX defunct
        # write out a configuration file.
        config = ConfigParser.RawConfigParser()
        config.add_section("Garmr")
        config.set("Garmr", "force-passives", self.force_passives)
        config.set("Garmr", "module", ", ".join(self.modules))
        config.set("Garmr", "reporter", self.reporter.__class__)
        config.set("Garmr", "output", self.output)
        config.set("Garmr", "dns", self.resolve_target)

        if len(self._targets_) > 0:
            config.add_section("Targets")
            for i,target in enumerate(self._targets_):
                config.set("Targets", "%s"%i, target)

        for index, check in enumerate(self._active_tests_):
            check = str(check)
            config.add_section(check)
            if check not in self._disabled_tests_:
                config.set(check, "enabled", True)
            else:
                config.set(check, "enabled", False)
            if hasattr(self._active_tests_[index], "config"):
                for key in self._active_tests_[index].config.keys():
                    config.set(check, key, self._active_tests_[index].config[key])

        for index, check in enumerate(self._passive_tests_):
            check = str(check)
            config.add_section(str(check))
            if check not in self._disabled_tests_:
                config.set(check, "enabled", True)
            else:
                config.set(check, "enabled", False)
            if hasattr(self._passive_tests_[index], "config"):
                for key in self._passive_tests_[index].config.keys():
                    config.set(check, key, self._passive_tests_[index].config[key])


        with open(path, 'w') as configfile:
            config.write(configfile)


