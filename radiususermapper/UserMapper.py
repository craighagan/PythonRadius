
from radiusconstants import *
import re

class UserMapper(object):
    """
    rules to transform usernames from inbound radius client requests
    before shipping them off to the radius server

    """

    def __init__(self):
        self._rules = []
        
    
    def addRule(self,regular_expression,replace_string):
        """
        add a regular expression substitution rule

        @param regular_expression

        @param replace_string

        @type regular_expression regexp/string

        @type replace_string string
        
        """

        self._rules.append((re.compile(regular_expression),replace_string))
        
        

    def transformUsername(self,username):
        """
        transform the username
        base class does nothing
        """
        new_username = username
        
        for (rule,replace) in self._rules:
            new_username = rule.sub(replace,new_username)
            
        return(new_username)


class OracleUserMapper(UserMapper):
    """
    rules for transforming oracle usernames to backend
    radius usernames

    right now the rules are hardcoded, ultimately
    this should live in dynamo or similar and be cached
    locally

    """

    def __init__(self):
        super(self.__class__,self).__init__()

        self.addRule("\_(DBA|RO|ADMIN)$","")
        self.addRule("\_(\d+)$","")

    def transformUsername(self,username):
        """
        same as base, but also lowercases username
        """

        new_username = super(self.__class__,self).transformUsername(username)

        return new_username.lower()
    


