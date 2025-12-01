import os
import subprocess
import sys
import warnings

import pytest
import requests_mock
from sqlalchemy.exc import SAWarning

import zeeguu.core.nlp_pipeline.automatic_gec_tagging
from zeeguu.api.app import create_app
from zeeguu.api.test.fixtures import add_context_types, add_source_types
from zeeguu.core.model.db import db
from zeeguu.core.test.mocking_the_web import mock_requests_get

SYSTEM_UNDER_TEST_PATH = zeeguu.core.nlp_pipeline.automatic_gec_tagging.__file__
MUTATION_TESTING_DIR = "./mutation_testing"
MUTATION_BRIDGE_FILE_PATH = f"{MUTATION_TESTING_DIR}/mutation_bridge.json"
COSMIC_RAY_CONFIG = f"{MUTATION_TESTING_DIR}/cosmic_ray_gec_tagging.toml"
COSMIC_RAY_SESSION = f"{MUTATION_TESTING_DIR}/cosmic_ray_gec_tagging.sqlite"

warnings.filterwarnings('ignore', category=SAWarning)


@pytest.fixture(scope="function")
def test_env():
    print("\033[92m\n===== Test case setup started =====\n\033[0m")
    reset_gec_test()

    app = create_app(testing=True)

    with app.app_context():
        with requests_mock.Mocker() as m:
            mock_requests_get(m)

            add_context_types()
            add_source_types()

            # print("\033[92m\n===== Test case setup finished =====\n\033[0m")
            yield db

            # print("\033[92m\n===== Test case teardown started =====\n\033[0m")
            db.session.close()
            db.drop_all()
            print("\033[92m\n===== Test case teardown finished =====\n\033[0m")


def reset_gec_test():
    reset_sut_source_code()

    with open(MUTATION_BRIDGE_FILE_PATH, 'w') as file:
        file.write("")

    subprocess.run(
        [sys.executable, "-m", "cosmic_ray.cli", "init", COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION, "--force"],
        capture_output=True,
        text=True,
        cwd=os.path.abspath("."),
        timeout=10
    )


def reset_sut_source_code():
    subprocess.run(
        ["git", "restore", SYSTEM_UNDER_TEST_PATH],
        capture_output=True,
        text=True,
        cwd=os.path.abspath("."),
        timeout=10
    )
