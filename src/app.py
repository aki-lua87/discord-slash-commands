"""Discord `/clear-ch-message` slash command handler.

Single Lambda function used two ways:
  * Synchronously by API Gateway to handle the Discord Interaction webhook
    (signature verification, channel/permission checks, deferred response).
  * Asynchronously (self-invoked, InvocationType=Event) as a background
    worker that actually purges channel messages, then posts the result as a
    public followup message (on success) or patches the ephemeral deferred
    response with an error (on failure).
"""

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.request

import boto3
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_EPOCH_MS = 1420070400000
BULK_DELETE_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000
BULK_DELETE_SAFETY_MARGIN_MS = 60 * 1000  # avoid edge-of-window 400s from clock/processing drift

TARGET_COMMAND_NAME = "clear-ch-message"
EPHEMERAL_FLAG = 1 << 6  # 64

PERMISSION_ADMINISTRATOR = 0x8
PERMISSION_MANAGE_MESSAGES = 0x2000

WORKER_FLAG_KEY = "invocation_source"
WORKER_FLAG_VALUE = "async_worker"

ALLOWED_CHANNEL_IDS_ENV_VAR = "ALLOWED_CHANNEL_IDS"

INTERACTION_TYPE_PING = 1
INTERACTION_TYPE_APPLICATION_COMMAND = 2

INTERACTION_RESPONSE_TYPE_PONG = 1
INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE = 4
INTERACTION_RESPONSE_TYPE_DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE = 5


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    if event.get(WORKER_FLAG_KEY) == WORKER_FLAG_VALUE:
        return handle_worker(event)
    return handle_interaction(event, context)


# ---------------------------------------------------------------------------
# Interaction handling (synchronous, called via API Gateway)
# ---------------------------------------------------------------------------

def handle_interaction(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    signature = headers.get("x-signature-ed25519")
    timestamp = headers.get("x-signature-timestamp")
    raw_body = _get_raw_body(event)

    public_key = os.environ["DISCORD_PUBLIC_KEY"]
    if not signature or not timestamp or not _verify_discord_signature(signature, timestamp, raw_body, public_key):
        logger.warning("rejected request with invalid discord signature")
        return _build_response(401, {"message": "invalid request signature"})

    try:
        interaction = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        logger.warning("failed to parse interaction payload")
        return _build_response(400, {"message": "invalid payload"})

    interaction_type = interaction.get("type")

    if interaction_type == INTERACTION_TYPE_PING:
        return _build_response(200, {"type": INTERACTION_RESPONSE_TYPE_PONG})

    if interaction_type == INTERACTION_TYPE_APPLICATION_COMMAND:
        return _handle_application_command(interaction, context)

    logger.info("ignoring unsupported interaction type=%s", interaction_type)
    return _build_response(400, {"message": "unsupported interaction type"})


def _handle_application_command(interaction, context):
    command_name = (interaction.get("data") or {}).get("name")
    channel_id = interaction.get("channel_id")
    guild_id = interaction.get("guild_id")
    member = interaction.get("member")

    logger.info("received command name=%s channel_id=%s guild_id=%s", command_name, channel_id, guild_id)

    if command_name != TARGET_COMMAND_NAME:
        return _build_response(200, {
            "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
            "data": {"content": "未対応のコマンドだよ。", "flags": EPHEMERAL_FLAG},
        })

    if not _is_channel_allowed(channel_id):
        logger.info("channel not allowed channel_id=%s", channel_id)
        return _build_response(200, {
            "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
            "data": {
                "content": "このチャンネルでは `/clear-ch-message` を実行できないよ。",
                "flags": EPHEMERAL_FLAG,
            },
        })

    if not _has_manage_messages_permission(member):
        user_id = ((member or {}).get("user") or {}).get("id")
        logger.info("permission denied channel_id=%s user_id=%s", channel_id, user_id)
        return _build_response(200, {
            "type": INTERACTION_RESPONSE_TYPE_CHANNEL_MESSAGE_WITH_SOURCE,
            "data": {
                "content": "このコマンドの実行には「メッセージの管理」権限が必要だよ。",
                "flags": EPHEMERAL_FLAG,
            },
        })

    application_id = interaction.get("application_id")
    interaction_token = interaction.get("token")

    _invoke_worker_async(context, {
        WORKER_FLAG_KEY: WORKER_FLAG_VALUE,
        "channel_id": channel_id,
        "application_id": application_id,
        "interaction_token": interaction_token,
    })

    return _build_response(200, {
        "type": INTERACTION_RESPONSE_TYPE_DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE,
        "data": {"flags": EPHEMERAL_FLAG},
    })


def _is_channel_allowed(channel_id):
    allowed_ids = _get_allowed_channel_ids()
    if not allowed_ids:
        # Allow-list not configured => no restriction beyond the permission check.
        return True
    return channel_id in allowed_ids


def _get_allowed_channel_ids():
    raw = os.environ.get(ALLOWED_CHANNEL_IDS_ENV_VAR, "")
    return {channel_id.strip() for channel_id in raw.split(",") if channel_id.strip()}


def _has_manage_messages_permission(member):
    if not member:
        return False
    permissions_raw = member.get("permissions")
    if permissions_raw is None:
        return False
    try:
        permissions = int(permissions_raw)
    except (TypeError, ValueError):
        return False
    return bool(permissions & PERMISSION_ADMINISTRATOR) or bool(permissions & PERMISSION_MANAGE_MESSAGES)


def _invoke_worker_async(context, payload):
    lambda_client = boto3.client("lambda")
    lambda_client.invoke(
        FunctionName=context.invoked_function_arn,
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
    )


def _get_raw_body(event):
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body).decode("utf-8")
    return body


def _verify_discord_signature(signature_hex, timestamp, raw_body, public_key_hex):
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(f"{timestamp}{raw_body}".encode("utf-8"), bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError):
        return False


def _build_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


# ---------------------------------------------------------------------------
# Worker (asynchronous, self-invoked)
# ---------------------------------------------------------------------------

def handle_worker(event):
    channel_id = event.get("channel_id")
    application_id = event.get("application_id")
    interaction_token = event.get("interaction_token")

    logger.info("worker start channel_id=%s", channel_id)

    bot_token = None
    deleted_count = None
    try:
        bot_token = os.environ["DISCORD_BOT_TOKEN"]
        deleted_count = _purge_channel_messages(channel_id, bot_token)
        logger.info("worker deleted messages channel_id=%s deleted_count=%s", channel_id, deleted_count)
    except Exception:
        logger.exception("worker failed to purge channel_id=%s", channel_id)

    # Always attempt to notify Discord, even if something above raised unexpectedly,
    # so the deferred "thinking..." state never gets stuck forever. Each Discord call
    # below is independent, so one failing must not skip the others.
    if deleted_count is None:
        # Error case: only the invoking user needs to know: close out the
        # ephemeral deferred placeholder with the error, nothing public.
        try:
            _patch_original_response(application_id, interaction_token, "メッセージの削除中にエラーが発生したよ。")
        except Exception:
            logger.exception("worker failed to patch original response channel_id=%s", channel_id)
    else:
        # Success case: the result should be visible to everyone. A webhook
        # followup message can't be used for this - once the initial response is
        # deferred as ephemeral, Discord forces every followup for that same
        # interaction to stay ephemeral too, with no way to override it. So this
        # posts a normal bot message instead (independent of the interaction's
        # ephemeral state), sent after the purge so it's the only message left.
        try:
            _post_channel_message(channel_id, bot_token, f"{deleted_count}件のメッセージを削除したよ。")
        except Exception:
            logger.exception("worker failed to post result message channel_id=%s", channel_id)
        try:
            _patch_original_response(application_id, interaction_token, "削除が完了したよ。")
        except Exception:
            logger.exception("worker failed to patch original response channel_id=%s", channel_id)

    logger.info("worker end channel_id=%s", channel_id)
    return {"ok": True}


def _purge_channel_messages(channel_id, bot_token):
    deleted_total = 0
    before = None

    while True:
        messages = _fetch_messages(channel_id, bot_token, before)
        if not messages:
            break

        message_ids = [message["id"] for message in messages]
        before = message_ids[-1]  # oldest message in this page; keep paging further back

        now_ms = _current_epoch_ms()
        recent_ids = [mid for mid in message_ids if _is_within_bulk_delete_window(mid, now_ms)]
        old_ids = [mid for mid in message_ids if mid not in recent_ids]

        deleted_total += _delete_recent_batch(channel_id, bot_token, recent_ids)
        deleted_total += _delete_old_messages_individually(channel_id, bot_token, old_ids)

        if len(messages) < 100:
            break

    return deleted_total


def _delete_recent_batch(channel_id, bot_token, message_ids):
    if not message_ids:
        return 0
    if len(message_ids) == 1:
        return 1 if _delete_message(channel_id, bot_token, message_ids[0]) else 0
    return _bulk_delete_messages(channel_id, bot_token, message_ids)


def _delete_old_messages_individually(channel_id, bot_token, message_ids):
    deleted = 0
    for message_id in message_ids:
        if _delete_message(channel_id, bot_token, message_id):
            deleted += 1
        time.sleep(0.3)  # individual deletes are rate-limited more strictly than bulk delete
    return deleted


def _current_epoch_ms():
    return int(time.time() * 1000)


def _snowflake_to_timestamp_ms(snowflake_id):
    return (int(snowflake_id) >> 22) + DISCORD_EPOCH_MS


def _is_within_bulk_delete_window(message_id, now_ms):
    message_ms = _snowflake_to_timestamp_ms(message_id)
    age_ms = now_ms - message_ms
    return age_ms < (BULK_DELETE_MAX_AGE_MS - BULK_DELETE_SAFETY_MARGIN_MS)


# ---------------------------------------------------------------------------
# Discord REST API client (urllib only, no third-party HTTP client)
# ---------------------------------------------------------------------------

def _discord_api_request(method, path, bot_token=None, body=None, max_retries=5):
    url = f"{DISCORD_API_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Content-Type": "application/json",
        # Discord's edge (Cloudflare) blocks requests with generic HTTP client
        # User-Agents (e.g. urllib's default) with an opaque 403 - a descriptive
        # UA per Discord's API docs is required, not just a nice-to-have.
        "User-Agent": "DiscordBot (https://github.com/aki-lua87/discord-slash-commands, 1.0)",
    }
    if bot_token:
        headers["Authorization"] = f"Bot {bot_token}"

    attempt = 0
    while True:
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                parsed = json.loads(raw) if raw else None
                return response.status, parsed
        except urllib.error.HTTPError as error:
            raw = error.read()
            parsed = None
            if raw:
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = None

            if error.code == 429 and attempt < max_retries:
                retry_after = 1.0
                if isinstance(parsed, dict) and "retry_after" in parsed:
                    try:
                        retry_after = float(parsed["retry_after"])
                    except (TypeError, ValueError):
                        retry_after = 1.0
                logger.warning("discord api rate limited path=%s retry_after=%s", path, retry_after)
                time.sleep(retry_after + 0.1)
                attempt += 1
                continue

            logger.error("discord api error method=%s path=%s status=%s body=%s", method, path, error.code, parsed)
            return error.code, parsed
        except urllib.error.URLError:
            logger.exception("discord api network error method=%s path=%s", method, path)
            raise


def _fetch_messages(channel_id, bot_token, before=None):
    path = f"/channels/{channel_id}/messages?limit=100"
    if before:
        path += f"&before={before}"
    status, body = _discord_api_request("GET", path, bot_token=bot_token)
    if status != 200 or not isinstance(body, list):
        logger.error("failed to fetch messages channel_id=%s status=%s", channel_id, status)
        return []
    return body


def _bulk_delete_messages(channel_id, bot_token, message_ids):
    status, _ = _discord_api_request(
        "POST",
        f"/channels/{channel_id}/messages/bulk-delete",
        bot_token=bot_token,
        body={"messages": message_ids},
    )
    if status == 204:
        return len(message_ids)
    logger.error("bulk delete failed channel_id=%s status=%s count=%s", channel_id, status, len(message_ids))
    return 0


def _delete_message(channel_id, bot_token, message_id):
    status, _ = _discord_api_request("DELETE", f"/channels/{channel_id}/messages/{message_id}", bot_token=bot_token)
    if status == 204:
        return True
    logger.error("delete message failed channel_id=%s message_id=%s status=%s", channel_id, message_id, status)
    return False


def _patch_original_response(application_id, interaction_token, content):
    path = f"/webhooks/{application_id}/{interaction_token}/messages/@original"
    status, body = _discord_api_request("PATCH", path, body={"content": content})
    if status != 200:
        logger.error("failed to patch original interaction response status=%s body=%s", status, body)


def _post_channel_message(channel_id, bot_token, content):
    # A plain bot message via the Bot Token, independent of the interaction's
    # ephemeral state - unlike a webhook followup, this is always visible to
    # everyone in the channel. Requires the bot to have Send Messages permission.
    path = f"/channels/{channel_id}/messages"
    status, body = _discord_api_request("POST", path, bot_token=bot_token, body={"content": content})
    if status not in (200, 201):
        logger.error("failed to post result message channel_id=%s status=%s body=%s", channel_id, status, body)
