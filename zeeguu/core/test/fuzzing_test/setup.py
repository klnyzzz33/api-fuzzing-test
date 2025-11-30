import warnings

import pytest
import requests_mock
from sqlalchemy.exc import SAWarning

from zeeguu.api.app import create_app
from zeeguu.core.model.db import db
from zeeguu.core.test.mocking_the_web import mock_requests_get
from zeeguu.api.test.fixtures import add_context_types, add_source_types

warnings.filterwarnings('ignore', category=SAWarning)


@pytest.fixture(scope="function")
def test_env():
    print("\033[92m\n===== Test case setup started =====\n\033[0m")
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
