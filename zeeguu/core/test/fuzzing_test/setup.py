import pytest
import requests_mock

from zeeguu.api.app import create_app
from zeeguu.core.model.db import db
from zeeguu.core.test.mocking_the_web import mock_requests_get
from zeeguu.api.test.fixtures import add_context_types, add_source_types


@pytest.fixture(scope="function")
def test_env():
    print("\n===== Test case setup started =====")
    app = create_app(testing=True)

    with app.app_context():
        with requests_mock.Mocker() as m:
            mock_requests_get(m)

            add_context_types()
            add_source_types()

            print("\n===== Test case setup finished =====")
            yield db

            print("\n===== Test case teardown started =====")
            db.session.close()
            db.drop_all()
            print("\n===== Test case teardown finished =====")
