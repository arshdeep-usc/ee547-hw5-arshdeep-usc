import functools
import os
import re
import threading
import time
from datetime import datetime, timezone

import boto3
import jwt
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from flask import Flask, jsonify, redirect, request


AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "arxiv-papers")
SECRET_KEY = "D8q+UH3LI+0hbgJСРMoSgHyRC1XSyz95xxIRXs7"
TOKEN_EXP_SECONDS = 3600

USERS = {
    "admin": "secret",
    "viewer": "readonly",
}

app = Flask(__name__)
START_TIME = time.time()

_stats_lock = threading.Lock()
_request_stats = {
    "total": 0,
    "by_status": {},
}

_dynamodb_resource = boto3.resource("dynamodb", region_name=AWS_REGION)
_table = _dynamodb_resource.Table(DYNAMODB_TABLE)


def _increment_request_count(status_code: int) -> None:
    with _stats_lock:
        _request_stats["total"] += 1
        code = str(int(status_code))
        _request_stats["by_status"][code] = _request_stats["by_status"].get(code, 0) + 1


@app.after_request
def _track_response(response):
    _increment_request_count(response.status_code)
    return response


def _json_error(message: str, status_code: int):
    return jsonify({"error": message}), status_code


@app.errorhandler(400)
def _handle_400(_error):
    return _json_error("Missing or invalid parameters", 400)


@app.errorhandler(401)
def _handle_401(_error):
    return _json_error("Missing or invalid token", 401)


@app.errorhandler(404)
def _handle_404(_error):
    return _json_error("Resource not found", 404)


@app.errorhandler(500)
def _handle_500(_error):
    return _json_error("Server error", 500)


def normalize_keyword(text: str) -> str:
    text = (text or "").lower()
    return re.sub(r"[^a-z0-9_\-]", "", text)


def _normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _item_summary(item):
    return {
        "arxiv_id": str(item.get("arxiv_id", "")),
        "title": item.get("title", ""),
        "authors": _normalize_list(item.get("authors")),
        "published": str(item.get("published", "")),
    }


def _item_detail(item):
    return {
        "arxiv_id": str(item.get("arxiv_id", "")),
        "title": item.get("title", ""),
        "authors": _normalize_list(item.get("authors")),
        "abstract": item.get("abstract", ""),
        "categories": _normalize_list(item.get("categories")),
        "published": str(item.get("published", "")),
    }


def _parse_limit(value, default=20):
    if value is None or value == "":
        return default
    try:
        limit = int(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid limit")
    if limit <= 0:
        raise ValueError("Invalid limit")
    return limit


def _parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        raise ValueError("Invalid date")


def _start_bound(date_obj):
    return f"{date_obj.isoformat()}#"


def _end_bound(date_obj):
    return f"{date_obj.isoformat()}#￿"


def _query_items(**kwargs):
    try:
        response = _table.query(**kwargs)
        return response.get("Items", [])
    except (ClientError, BotoCoreError, NoCredentialsError) as exc:
        raise RuntimeError(str(exc)) from exc


def _paper_pk(category: str) -> str:
    return f"CATEGORY#{category}"


def _author_pk(author_name: str) -> str:
    return f"AUTHOR#{author_name}"


def _keyword_pk(keyword: str) -> str:
    return f"KEYWORD#{normalize_keyword(keyword)}"


def _paper_id_pk(arxiv_id: str) -> str:
    return f"ARXIV#{arxiv_id}"


def _paper_sk(published: str, arxiv_id: str) -> str:
    pubdate = (published or "1970-01-01T00:00:00Z")[:10]
    return f"{pubdate}#{arxiv_id}"


@app.route("/api/stats", methods=["GET"])
def api_stats():
    with _stats_lock:
        snapshot = {
            "total": _request_stats["total"],
            "by_status": dict(_request_stats["by_status"]),
        }
    return jsonify(
        {
            "status": "healthy",
            "uptime_seconds": int(time.time() - START_TIME),
            "region": AWS_REGION,
            "table": DYNAMODB_TABLE,
            "requests": snapshot,
        }
    )


def create_token(username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + TOKEN_EXP_SECONDS,
        "role": "admin" if username == "admin" else "viewer",
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return _json_error("Invalid credentials", 401)

    if USERS.get(username) != password:
        return _json_error("Invalid credentials", 401)

    return jsonify({"token": create_token(username), "expires_in": TOKEN_EXP_SECONDS})


def require_auth(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return _json_error("Missing or invalid token", 401)

        token = header.split(" ", 1)[1].strip()
        if not token:
            return _json_error("Missing or invalid token", 401)

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return _json_error("Missing or invalid token", 401)

        request.jwt_payload = payload  # type: ignore[attr-defined]
        return view_func(*args, **kwargs)

    return wrapper


@app.route("/api/papers", methods=["GET"])
@require_auth
def api_papers_by_category():
    category = request.args.get("category")
    if not category:
        return _json_error("Missing or invalid parameters", 400)

    try:
        limit = _parse_limit(request.args.get("limit"), default=20)
    except ValueError:
        return _json_error("Missing or invalid parameters", 400)

    try:
        items = _query_items(
            KeyConditionExpression=Key("PK").eq(_paper_pk(category)),
            ScanIndexForward=False,
            Limit=limit,
        )
    except RuntimeError:
        return _json_error("Server error", 500)

    papers = [_item_summary(item) for item in items[:limit] if item.get("type") == "category_item"]
    return jsonify({"category": category, "papers": papers, "count": len(papers)})


@app.route("/api/papers/<path:author_name>", methods=["GET"])
@require_auth
def _avoid_route_conflict(author_name):
    # This placeholder is never used directly because the concrete routes below
    # are defined in a way that avoids ambiguity.
    return _json_error("Resource not found", 404)


@app.route("/api/papers/author/<path:author_name>", methods=["GET"])
@require_auth
def api_papers_by_author(author_name):
    try:
        items = _query_items(
            IndexName="AuthorIndex",
            KeyConditionExpression=Key("GSI1PK").eq(_author_pk(author_name)),
            ScanIndexForward=False,
        )
    except RuntimeError:
        return _json_error("Server error", 500)

    papers = [_item_summary(item) for item in items if item.get("type") == "author_item"]
    return jsonify({"author": author_name, "papers": papers, "count": len(papers)})


@app.route("/api/papers/search", methods=["GET"])
@require_auth
def api_papers_search():
    category = request.args.get("category")
    start = request.args.get("start")
    end = request.args.get("end")

    if not category or not start or not end:
        return _json_error("Missing or invalid parameters", 400)

    try:
        start_date = _parse_date(start)
        end_date = _parse_date(end)
    except ValueError:
        return _json_error("Missing or invalid parameters", 400)

    if start_date > end_date:
        return _json_error("Missing or invalid parameters", 400)

    try:
        items = _query_items(
            KeyConditionExpression=(
                Key("PK").eq(_paper_pk(category))
                & Key("SK").between(_start_bound(start_date), _end_bound(end_date))
            ),
            ScanIndexForward=False,
        )
    except RuntimeError:
        return _json_error("Server error", 500)

    papers = [_item_summary(item) for item in items if item.get("type") == "category_item"]
    return jsonify(
        {
            "category": category,
            "start": start,
            "end": end,
            "papers": papers,
            "count": len(papers),
        }
    )


@app.route("/api/papers/keyword/<path:keyword>", methods=["GET"])
@require_auth
def api_papers_by_keyword(keyword):
    try:
        limit = _parse_limit(request.args.get("limit"), default=20)
    except ValueError:
        return _json_error("Missing or invalid parameters", 400)

    normalized = normalize_keyword(keyword)
    if not normalized:
        return _json_error("Missing or invalid parameters", 400)

    try:
        items = _query_items(
            IndexName="KeywordIndex",
            KeyConditionExpression=Key("GSI3PK").eq(_keyword_pk(keyword)),
            ScanIndexForward=False,
            Limit=limit,
        )
    except RuntimeError:
        return _json_error("Server error", 500)

    papers = [_item_summary(item) for item in items[:limit] if item.get("type") == "keyword_item"]
    return jsonify({"keyword": keyword, "papers": papers, "count": len(papers)})


@app.route("/api/papers/<arxiv_id>", methods=["GET"])
@require_auth
def api_paper_by_id(arxiv_id):
    try:
        items = _query_items(
            IndexName="PaperIdIndex",
            KeyConditionExpression=Key("GSI2PK").eq(_paper_id_pk(arxiv_id)),
            Limit=1,
        )
    except RuntimeError:
        return _json_error("Server error", 500)

    if not items:
        return jsonify({"error": "Paper not found", "arxiv_id": arxiv_id}), 404

    return jsonify(_item_detail(items[0]))


@app.route("/api/papers/<arxiv_id>/arxiv", methods=["GET"])
def api_paper_arxiv_redirect(arxiv_id):
    try:
        items = _query_items(
            IndexName="PaperIdIndex",
            KeyConditionExpression=Key("GSI2PK").eq(_paper_id_pk(arxiv_id)),
            Limit=1,
        )
    except RuntimeError:
        return _json_error("Server error", 500)

    if not items:
        return jsonify({"error": "Paper not found", "arxiv_id": arxiv_id}), 404

    return redirect(f"https://arxiv.org/abs/{arxiv_id}", code=302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
