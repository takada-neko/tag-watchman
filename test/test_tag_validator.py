"""
test_tag_validator.py
─────────────────────
tag_validator のユニットテスト

テストケース:
  - 必須タグが全て揃っている → 違反なし
  - タグキーが不足 → 違反
  - 値が空文字 → 違反
  - Env の値が許可値以外 → 違反
  - Project が前方一致 → OK
  - Project が前方一致しない → 違反
  - Owned は値が自由（空文字以外はOK）
  - tagwatchman:* タグは判定から除外
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))


# lru_cache をリセットするためにモジュールを毎回リロード
@pytest.fixture(autouse=True)
def reload_validator():
    import importlib
    import tag_validator
    importlib.reload(tag_validator)
    yield


def _get_validator():
    import tag_validator
    return tag_validator


def mock_ssm_values(allowed="Env:prod|stg|test,Project:my-project", mode="Env:exact,Project:prefix", required="Env,Project,Owned"):
    """SSM の値をモックする"""
    def side_effect(name):
        mapping = {
            "required-tags": required,
            "tag-allowed-values": allowed,
            "tag-match-mode": mode,
        }
        return mapping.get(name.split("/")[-1], "")
    return side_effect


class TestValidateTags:

    def test_all_tags_valid(self):
        """全タグが正しい値 → 違反なし"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "prod",
                "Project": "my-project-api",
                "Owned": "backend",
            })
        assert result == []

    def test_missing_tag_key(self):
        """タグキーが不足 → 違反"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "prod",
                "Project": "my-project",
                # Owned が欠落
            })
        assert "Owned" in result

    def test_empty_value(self):
        """値が空文字 → 違反"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "prod",
                "Project": "my-project",
                "Owned": "",  # 空文字
            })
        assert "Owned" in result

    def test_env_invalid_value(self):
        """Env の値が許可値以外 → 違反"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "production",  # prod|stg|test 以外
                "Project": "my-project",
                "Owned": "backend",
            })
        assert "Env" in result

    def test_env_valid_values(self):
        """Env の値が許可値 → 違反なし"""
        tv = _get_validator()
        for env in ["prod", "stg", "test"]:
            with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
                result = tv.validate_tags({
                    "Env": env,
                    "Project": "my-project",
                    "Owned": "backend",
                })
            assert result == [], f"Env={env} should be valid"

    def test_project_prefix_match(self):
        """Project が前方一致 → 違反なし"""
        tv = _get_validator()
        for project in ["my-project", "my-project-api", "my-project-v2", "my-project-batch"]:
            with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
                result = tv.validate_tags({
                    "Env": "prod",
                    "Project": project,
                    "Owned": "backend",
                })
            assert result == [], f"Project={project} should be valid"

    def test_project_prefix_no_match(self):
        """Project が前方一致しない → 違反"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "prod",
                "Project": "other-project",  # my-project で始まらない
                "Owned": "backend",
            })
        assert "Project" in result

    def test_owned_any_value_allowed(self):
        """Owned はどんな値でもOK（空文字以外）"""
        tv = _get_validator()
        for owned in ["Takada", "backend", "infra", "my-team-123"]:
            with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
                result = tv.validate_tags({
                    "Env": "prod",
                    "Project": "my-project",
                    "Owned": owned,
                })
            assert result == [], f"Owned={owned} should be valid"

    def test_tagwatchman_tags_excluded(self):
        """tagwatchman:* タグは判定から除外される"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "prod",
                "Project": "my-project",
                "Owned": "backend",
                "tagwatchman:quarantined": "true",
                "tagwatchman:original-sgs": '["sg-123"]',
            })
        assert result == []

    def test_multiple_violations(self):
        """複数タグが違反 → 全て検出"""
        tv = _get_validator()
        with patch.object(tv, "_get_ssm_value", side_effect=mock_ssm_values()):
            result = tv.validate_tags({
                "Env": "invalid",
                "Project": "wrong-project",
                "Owned": "",
            })
        assert "Env" in result
        assert "Project" in result
        assert "Owned" in result
