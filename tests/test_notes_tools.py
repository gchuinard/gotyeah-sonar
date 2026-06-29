"""Tests de la logique pure de `mcp_remote.notes_tools` (MCP v2 databases/records).

On ne teste PAS les appels réseau (fines enveloppes httpx) mais la traduction
"par nom" exposée à l'IA : nom de propriété -> id, nom d'option select -> id, et
routage de la propriété "title" vers le champ `title` du record.
"""
import pytest

from mcp_remote import notes_tools as nt


# Schéma type d'une database : title + texte + select + multiselect.
SCHEMA = [
    {"id": "p_title", "name": "Titre", "type": "title", "config": {"type": "title"}},
    {"id": "p_notes", "name": "Notes", "type": "text", "config": {"type": "text"}},
    {
        "id": "p_status",
        "name": "Statut",
        "type": "select",
        "config": {
            "type": "select",
            "options": [
                {"id": "o_todo", "name": "À faire", "color": "blue"},
                {"id": "o_doing", "name": "En cours", "color": "green"},
            ],
        },
    },
    {
        "id": "p_tags",
        "name": "Tags",
        "type": "multiselect",
        "config": {
            "type": "multiselect",
            "options": [
                {"id": "o_urgent", "name": "Urgent", "color": "red"},
                {"id": "o_perso", "name": "Perso", "color": "pink"},
            ],
        },
    },
]


def test_resolve_routes_title_to_field_not_properties():
    title, props = nt.resolve_record_properties(SCHEMA, {"Titre": "Ma tâche"})
    assert title == "Ma tâche"
    assert props == {}


def test_resolve_maps_property_names_to_ids():
    title, props = nt.resolve_record_properties(SCHEMA, {"Notes": "bla"})
    assert title is None
    assert props == {"p_notes": "bla"}


def test_resolve_select_option_name_to_id():
    _, props = nt.resolve_record_properties(SCHEMA, {"Statut": "En cours"})
    assert props == {"p_status": "o_doing"}


def test_resolve_multiselect_list_of_names_to_ids():
    _, props = nt.resolve_record_properties(SCHEMA, {"Tags": ["Urgent", "Perso"]})
    assert props == {"p_tags": ["o_urgent", "o_perso"]}


def test_resolve_null_is_deletion_sentinel():
    _, props = nt.resolve_record_properties(SCHEMA, {"Notes": None})
    assert props == {"p_notes": None}


def test_resolve_is_case_insensitive_on_names():
    _, props = nt.resolve_record_properties(SCHEMA, {"statut": "en cours"})
    assert props == {"p_status": "o_doing"}


def test_resolve_unknown_property_raises_with_valid_names():
    with pytest.raises(ValueError) as exc:
        nt.resolve_record_properties(SCHEMA, {"Inexistant": "x"})
    assert "Inexistant" in str(exc.value)
    assert "Statut" in str(exc.value)  # liste les noms valides


def test_resolve_unknown_option_raises_with_valid_options():
    with pytest.raises(ValueError) as exc:
        nt.resolve_record_properties(SCHEMA, {"Statut": "Terminé"})
    assert "Terminé" in str(exc.value)
    assert "En cours" in str(exc.value)


def test_resolve_multiselect_requires_list():
    with pytest.raises(ValueError):
        nt.resolve_record_properties(SCHEMA, {"Tags": "Urgent"})


def test_resolve_empty_or_none_is_noop():
    assert nt.resolve_record_properties(SCHEMA, None) == (None, {})
    assert nt.resolve_record_properties(SCHEMA, {}) == (None, {})


def test_build_config_select_generates_option_ids():
    cfg = nt._build_property_config("select", options=["A", "B"])
    assert cfg["type"] == "select"
    assert [o["name"] for o in cfg["options"]] == ["A", "B"]
    ids = [o["id"] for o in cfg["options"]]
    assert all(ids) and len(set(ids)) == 2  # ids non vides et uniques


def test_build_config_number_and_date_and_plain():
    assert nt._build_property_config("number", number_format="percent") == {
        "type": "number", "format": "percent"
    }
    assert nt._build_property_config("date", date_include_time=True) == {
        "type": "date", "includeTime": True
    }
    assert nt._build_property_config("text") == {"type": "text"}
