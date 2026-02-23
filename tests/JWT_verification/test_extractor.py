import pytest
from flask import Flask

from src.extension.JWT_verification import BearerExtractor, MissingToken


def test_bearer_extractor_missing(app: Flask):
    extractor = BearerExtractor()

    with app.test_request_context("/", headers={}):
        with pytest.raises(MissingToken):
            extractor.extract()


def test_bearer_extractor_ok(app: Flask):
    extractor = BearerExtractor()

    with app.test_request_context("/", headers={"Authorization": "Bearer abc.def.ghi"}):
        assert extractor.extract() == "abc.def.ghi"
