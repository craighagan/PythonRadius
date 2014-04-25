import os
import logging
import json
import re
import unittest
import tempfile
from nose.tools import assert_equal
from nose.tools import assert_not_equal
from nose.tools import assert_raises

from radiususermapper import *

class UserMapperTestCase(unittest.TestCase):

    def test_um_simple_pattern_substitution(self):
        um = UserMapper()
        um.addRule("me$","you")

        modified_username = um.transformUsername("changeme")

        assert modified_username == "changeyou"

        modified_username = um.transformUsername("changethis")

        assert modified_username == "changethis"

        modified_username = um.transformUsername("changemetoo")

        assert modified_username == "changemetoo"

        modified_username = um.transformUsername("changeMe")

        assert modified_username == "changeMe"



class OracleUserMapperTestCase(unittest.TestCase):

    def test_oum_simple_pattern_substitution(self):
        um = OracleUserMapper()

        modified_username = um.transformUsername("BOB_DBA")

        assert modified_username == "bob"

        modified_username = um.transformUsername("BOB_RO")

        assert modified_username == "bob"

        modified_username = um.transformUsername("BOB_ADMIN")

        assert modified_username == "bob"


        modified_username = um.transformUsername("BOB_USER")

        assert modified_username == "bob_user"


        modified_username = um.transformUsername("BOB_RO_USER")

        assert modified_username == "bob_ro_user"


    
if __name__ == '__main__':
    unittest.main()
