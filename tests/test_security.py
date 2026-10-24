import io
import os
import tempfile
import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-only-for-tests")
os.environ.setdefault("AUDIT_HMAC_KEY", "test-audit-key-only-for-tests")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import app as trustvault


@pytest.fixture()
def client(tmp_path, monkeypatch):
    trustvault.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SQLALCHEMY_DATABASE_URI="sqlite://",
        SECRET_KEY="test-secret-only-for-tests",
    )
    monkeypatch.setattr(trustvault, "STORAGE_DIR", tmp_path)
    with trustvault.app.app_context():
        trustvault.db.drop_all()
        trustvault.db.create_all()
        alice = trustvault.User(name="Alice", email="alice@example.test", role="owner")
        alice.set_password("AlicePassword123!")
        bob = trustvault.User(name="Bob", email="bob@example.test", role="owner")
        bob.set_password("BobPassword123!")
        viewer = trustvault.User(name="Viewer", email="viewer@example.test", role="viewer")
        viewer.set_password("ViewerPassword123!")
        trustvault.db.session.add_all([alice, bob, viewer])
        trustvault.db.session.commit()
        # A small valid PDF signature for the test fixture.
        storage_key = "bob-private-test-key"
        (tmp_path / storage_key).write_bytes(b"%PDF-1.4\nTrustVault test file\n%%EOF")
        doc = trustvault.Document(
            owner_id=bob.id, name="secret.pdf", category="Confidential",
            storage_key=storage_key, mime_type="application/pdf",
            size_bytes=(tmp_path / storage_key).stat().st_size,
            sha256="testhash",
        )
        trustvault.db.session.add(doc)
        trustvault.db.session.commit()
        doc_id = doc.id
        trustvault.db.session.remove()
    with trustvault.app.test_client() as test_client:
        yield test_client, doc_id


def login(client, email, password):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def test_ungranted_user_cannot_download(client):
    c, doc_id = client
    login(c, "alice@example.test", "AlicePassword123!")
    response = c.get(f"/documents/{doc_id}/download")
    assert response.status_code == 404


def test_owner_can_download(client):
    c, doc_id = client
    login(c, "bob@example.test", "BobPassword123!")
    response = c.get(f"/documents/{doc_id}/download")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF-")


def test_read_grant_allows_download_but_not_edit(client):
    c, doc_id = client
    with trustvault.app.app_context():
        alice = trustvault.User.query.filter_by(email="alice@example.test").first()
        bob = trustvault.User.query.filter_by(email="bob@example.test").first()
        trustvault.db.session.add(trustvault.Permission(
            document_id=doc_id, user_id=alice.id, permission="read", granted_by=bob.id
        ))
        trustvault.db.session.commit()
    login(c, "alice@example.test", "AlicePassword123!")
    assert c.get(f"/documents/{doc_id}/download").status_code == 200
    with trustvault.app.app_context():
        alice = trustvault.User.query.filter_by(email="alice@example.test").first()
        doc = trustvault.db.session.get(trustvault.Document, doc_id)
        assert not trustvault.can_access_document(alice, doc, "edit")


def test_revoked_grant_denies_next_download(client):
    c, doc_id = client
    with trustvault.app.app_context():
        alice = trustvault.User.query.filter_by(email="alice@example.test").first()
        bob = trustvault.User.query.filter_by(email="bob@example.test").first()
        grant = trustvault.Permission(
            document_id=doc_id, user_id=alice.id, permission="read", granted_by=bob.id
        )
        trustvault.db.session.add(grant)
        trustvault.db.session.commit()
        grant_id = grant.id
        doc = trustvault.db.session.get(trustvault.Document, doc_id)
        grant.revoked_at = trustvault.utcnow()
        trustvault.db.session.commit()
    login(c, "alice@example.test", "AlicePassword123!")
    assert c.get(f"/documents/{doc_id}/download").status_code == 404


def test_audit_chain_detects_modified_event(client):
    _c, _doc_id = client
    with trustvault.app.app_context():
        trustvault.audit("TEST_EVENT", "allowed", details={"test": True})
        trustvault.db.session.commit()
        assert trustvault.verify_audit_chain()
        event = trustvault.AuditEvent.query.first()
        event.details_json = '{"tampered":true}'
        trustvault.db.session.commit()
        assert not trustvault.verify_audit_chain()
