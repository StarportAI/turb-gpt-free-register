# -*- coding: utf-8 -*-
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db


class LoginCredentialImportTests(unittest.TestCase):
    def test_parse_and_import_password_and_totp(self):
        text = "\n".join([
            "# comment",
            "user@example.com----secret-pass----JBSWY3DPEHPK3PXP",
            "bad-line",
            "user@example.com----secret-pass----JBSWY3DPEHPK3PXP",
            "otp@example.com----pw----otpauth://totp/Demo?secret=JBSWY3DPEHPK3PXP&issuer=Demo",
        ])
        records, errors = db.parse_login_credential_text(text)
        self.assertEqual([row["email"] for row in records], ["user@example.com", "user@example.com", "otp@example.com"])
        self.assertEqual(records[0]["registration_password"], "secret-pass")
        self.assertEqual(records[0]["totp_secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(records[2]["totp_secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(errors[0]["line"], 3)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts_path = root / "accounts.json"
            accounts_path.write_text("[]", encoding="utf-8")
            with patch.object(db, "_ACCOUNTS_JSON", accounts_path), \
                 patch.object(db, "_LEGACY_ACCOUNTS_JSON", root / "legacy_accounts.json"), \
                 patch.object(db, "_ACCOUNTS_TXT", root / "accounts.txt"), \
                 patch.object(db, "_TOKENS_TXT", root / "tokens.txt"), \
                 patch.object(db, "_VIEWER_HTML", root / "viewer.html"), \
                 patch.object(db, "_SQLITE_READY", False):
                inserted, skipped = db.import_login_credential_accounts(records)
                self.assertEqual((inserted, skipped), (2, 1))
                again_inserted, again_skipped = db.import_login_credential_accounts(records)
                self.assertEqual((again_inserted, again_skipped), (0, 3))
                saved = db.get_account_by_email("user@example.com")
                extra = json.loads(saved["extra_json"])
                self.assertEqual(extra["registration_password"], "secret-pass")
                self.assertEqual(saved["totp_secret"], "JBSWY3DPEHPK3PXP")
                self.assertEqual(saved["email_source"], "已导入")
                self.assertEqual(db._extract_registration_password(saved), "secret-pass")


class Sub2ImportProfileTests(unittest.TestCase):
    def test_callback_sets_gpt_luna_profile(self):
        from core import codex_oauth as oauth

        captured = []

        def fake_request(method, path, body=None):
            captured.append((method, path, body))
            if method == "POST":
                return {"data": {"id": 9}}
            if method == "GET":
                return {"data": {"id": 9, "platform": "openai", "type": "oauth", "credentials": {"access_token": "x"}, "extra": {}}}
            return {"ok": True}

        with patch.object(oauth, "_sub2_codex_request_json", side_effect=fake_request):
            result = oauth._submit_sub2_callback(
                "http://localhost:1455/auth/callback?code=abc&state=xyz",
                session_id="sess",
                email="a@test.com",
            )
        post = next(item for item in captured if item[0] == "POST")
        self.assertEqual(post[2]["name"], "a@test.com")
        self.assertEqual(post[2]["concurrency"], 5)
        self.assertEqual(post[2]["priority"], 1)
        put = next(item for item in captured if item[0] == "PUT")
        self.assertEqual(put[2]["group_ids"], [68, 2, 3, 8, 33, 75, 86, 87])
        self.assertEqual(put[2]["proxy_id"], 29)
        self.assertEqual(put[2]["concurrency"], 5)
        self.assertEqual(put[2]["priority"], 1)
        self.assertEqual(put[2]["extra"]["codex_fingerprint_mode"], "full")
        self.assertEqual(put[2]["credentials"]["model_mapping"], {"gpt-5.6-luna": "gpt-5.6-luna"})
        self.assertEqual(put[2]["credentials"]["access_token"], "x")
        self.assertEqual(result["import_profile"]["account_id"], 9)


if __name__ == "__main__":
    unittest.main()
