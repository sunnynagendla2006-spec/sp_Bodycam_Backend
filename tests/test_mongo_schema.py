"""
Replaces the old test_migrations_postgres.py. MongoDB/Beanie has no
separate migration-tool step to verify (init_beanie creates every
collection/index idempotently at startup -- see app/database.py::init_db
and app/models.py's DOCUMENT_MODELS) -- what's actually worth asserting
here is that the schema declared in app/models.py comes up cleanly against
an empty database, and that the concurrency-critical indexes (the ones
that replaced Postgres's partial unique indexes -- see models.py's
Alert/User/Device/Incident Settings.indexes) actually exist afterward.
"""
import pytest

from app import models


async def _index_names(document_cls) -> set:
    indexes = await document_cls.get_motor_collection().index_information()
    return set(indexes.keys())


async def test_init_beanie_succeeds_against_empty_database(mongo_db):
    # The mongo_db fixture itself already calls init_beanie against a fresh,
    # empty, uniquely-named database -- getting here at all is the check.
    assert await models.User.find_all().count() == 0


async def test_open_battery_alert_partial_unique_index_exists(mongo_db):
    indexes = await models.Alert.get_motor_collection().index_information()
    battery_index = indexes.get("uq_open_battery_alert_per_device")
    assert battery_index is not None
    assert battery_index.get("unique") is True
    assert "partialFilterExpression" in battery_index


async def test_open_alert_per_device_and_type_partial_unique_index_exists(mongo_db):
    indexes = await models.Alert.get_motor_collection().index_information()
    generic_index = indexes.get("uq_open_alert_per_device_and_type")
    assert generic_index is not None
    assert generic_index.get("unique") is True
    assert "partialFilterExpression" in generic_index


@pytest.mark.parametrize(
    "document_cls,field",
    [
        (models.PoliceStation, "location"),
        (models.PoliceStation, "jurisdiction"),
        (models.Incident, "location"),
    ],
)
async def test_2dsphere_geo_indexes_exist(mongo_db, document_cls, field):
    indexes = await document_cls.get_motor_collection().index_information()
    matching = [
        spec for spec in indexes.values()
        if spec.get("key") == [(field, "2dsphere")]
    ]
    assert matching, f"no 2dsphere index found on {document_cls.__name__}.{field}"


async def test_unique_indexes_exist_on_natural_keys(mongo_db):
    device_indexes = await models.Device.get_motor_collection().index_information()
    assert any(
        spec.get("unique") and spec.get("key") == [("device_identifier", 1)]
        for spec in device_indexes.values()
    )

    incident_indexes = await models.Incident.get_motor_collection().index_information()
    assert any(
        spec.get("unique") and spec.get("key") == [("display_id", 1)]
        for spec in incident_indexes.values()
    )
