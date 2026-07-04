import os

import pytest

from passkit import testing as T
from passkit._cose import ALG_ES256, ALG_RS256

RP_ID = "login.example.mil"
ORIGIN = "https://login.example.mil"


@pytest.fixture
def rp_id():
    return RP_ID


@pytest.fixture
def origin():
    return ORIGIN


@pytest.fixture
def challenge():
    return os.urandom(32)


@pytest.fixture
def es256_registration(challenge):
    cred, att, cd = T.build_registration(RP_ID, ORIGIN, challenge, alg=ALG_ES256)
    return cred, att, cd, challenge


@pytest.fixture
def rs256_registration(challenge):
    cred, att, cd = T.build_registration(RP_ID, ORIGIN, challenge, alg=ALG_RS256)
    return cred, att, cd, challenge
