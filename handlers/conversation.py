import logging
import time
from telegram import Update
from telegram.ext import (
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from datetime import datetime, timedelta, timezone
from handlers.decorators import (
    only_target_group,
    admin_only,
    is_user_admin,
    self_destruct,
    send_self_destructing_message,
    GROUP_ANONYMOUS_BOT_ID,
    TELEGRAM_SERVICE_USER_ID,
)

logger = logging.getLogger("telegram_bot")


@only_target_group
async def show_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display the current settings."""
    # janitor_status = context.chat_data.get("janitorEnabled", False)  # DISABLED
    # channel_filter_status = context.chat_data.get("channelFilterEnabled", False)  # DISABLED
    fsp_status = context.chat_data.get("forwardSpamProtectionEnabled", False)
    lmp_status = context.chat_data.get("longMessageProtectionEnabled", False)
    lmp_limit = context.chat_data.get("longMessageLimit", 400)
    
    # Count filter patterns - DISABLED since filters are disabled
    # filter_count = 0
    # if "filter_patterns" in context.chat_data and context.chat_data["filter_patterns"]:
    #     filter_count = len(context.chat_data["filter_patterns"])
    
    # janitor_text = "enabled" if janitor_status else "disabled"  # DISABLED
    # channel_filter_text = "enabled" if channel_filter_status else "disabled"  # DISABLED
    fsp_text = "enabled" if fsp_status else "disabled"
    lmp_text = "enabled" if lmp_status else "disabled"
    
    status_text = f"""
*Current settings for this chat:*

🔁 *Forward Spam Protection:* {fsp_text}
📝 *Long Message Protection:* {lmp_text} (limit: {lmp_limit} chars)

*Available Commands:*
• `/forward_spam` - Toggle forward spam protection (delete repeated forwards within 24h)
• `/message_cap` - Toggle long message protection (delete messages above character limit)
• `/set_message_cap <number>` - Set character limit for long message protection (default: 400)
    """
    
    await update.message.reply_text(status_text, parse_mode="Markdown")
    logger.info(f"Settings displayed for chat {update.effective_chat.id}")


@only_target_group
@admin_only
@self_destruct(seconds=10)
async def toggle_forward_spam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Toggle forward spam protection for the chat."""
    current_state = context.chat_data.get("forwardSpamProtectionEnabled", False)
    new_state = not current_state
    context.chat_data["forwardSpamProtectionEnabled"] = new_state

    # Ensure data is marked for persistence
    await context.application.update_persistence()

    status = "enabled" if new_state else "disabled"
    emoji = "✅" if new_state else "❌"

    response = await update.message.reply_text(
        f"{emoji} Forward spam protection has been {status}.\n\n"
        f"When enabled, any specific forwarded message repeated within 24 hours will be deleted."
    )

    logger.info(
        f"Forward spam protection {status} in chat {update.effective_chat.id} by user {update.effective_user.id}"
    )
    return response


@only_target_group
@admin_only
@self_destruct(seconds=10)
async def toggle_long_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Toggle long message protection for the chat."""
    current_state = context.chat_data.get("longMessageProtectionEnabled", False)
    new_state = not current_state
    context.chat_data["longMessageProtectionEnabled"] = new_state
    limit = context.chat_data.get("longMessageLimit", 400)

    # Ensure data is marked for persistence
    await context.application.update_persistence()

    status = "enabled" if new_state else "disabled"
    emoji = "✅" if new_state else "❌"

    response = await update.message.reply_text(
        f"{emoji} Long message protection has been {status}.\n\n"
        f"When enabled, any message with text/caption above {limit} characters will be deleted."
    )

    logger.info(
        f"Long message protection {status} in chat {update.effective_chat.id} by user {update.effective_user.id}"
    )
    return response


@only_target_group
@admin_only
@self_destruct(seconds=10)
async def set_long_message_limit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set the character limit for long message protection."""
    if not context.args or len(context.args) < 1:
        current_limit = context.chat_data.get("longMessageLimit", 400)
        response = await update.message.reply_text(
            f"Current long message limit: {current_limit} characters.\n\n"
            f"Usage: /setmessagecap <number>\n"
            f"Example: /setmessagecap 500"
        )
        return response
    
    try:
        new_limit = int(context.args[0])
        if new_limit < 1:
            response = await update.message.reply_text("❌ Limit must be at least 1 character.")
            return response
        
        context.chat_data["longMessageLimit"] = new_limit
        await context.application.update_persistence()
        
        response = await update.message.reply_text(
            f"✅ Long message limit set to {new_limit} characters.\n\n"
            f"Messages with text/caption above this limit will be deleted when protection is enabled."
        )
        
        logger.info(
            f"Long message limit set to {new_limit} in chat {update.effective_chat.id} by user {update.effective_user.id}"
        )
        return response
    except ValueError:
        response = await update.message.reply_text("❌ Invalid number. Please provide a valid integer.")
        return response


def _cleanup_fsp_cache(cache: dict) -> None:
    """Remove cache entries older than 24 hours."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    stale_keys = [key for key, first_seen in cache.items() if first_seen < cutoff]
    for key in stale_keys:
        del cache[key]


def _make_forward_key(message) -> str | None:
    """Create a stable key representing the original forwarded message.

    Combines multiple signals for robust identification.
    Returns None if a safe key cannot be determined.
    """
    # Channel post forwards: best signal - has actual message ID
    # Support both old API (forward_from_chat) and new API (forward_origin)
    if getattr(message, "forward_from_chat", None) and getattr(message, "forward_from_message_id", None):
        origin_chat_id = message.forward_from_chat.id
        origin_msg_id = message.forward_from_message_id
        return f"chat:{origin_chat_id}:msg:{origin_msg_id}"
    
    # New API: Check forward_origin for channel
    if getattr(message, "forward_origin", None):
        origin = message.forward_origin
        # MessageOriginChannel
        if hasattr(origin, "chat") and hasattr(origin, "message_id"):
            return f"chat:{origin.chat.id}:msg:{origin.message_id}"
        # MessageOriginUser
        elif hasattr(origin, "sender_user"):
            origin_user_id = origin.sender_user.id
            key_parts = [f"user:{origin_user_id}"]
            
            # Add forward date as additional discriminator
            if hasattr(origin, "date"):
                key_parts.append(f"date:{int(origin.date.timestamp())}")
            
            # Add text/caption content if available
            content = (message.text or message.caption or "").strip()
            if content:
                key_parts.append(f"text:{hash(content)}")
            
            # Add media file_unique_id for different media types
            media_id = None
            if getattr(message, "photo", None) and message.photo and len(message.photo) > 0:
                media_id = f"photo:{message.photo[-1].file_unique_id}"
            elif getattr(message, "document", None):
                media_id = f"doc:{message.document.file_unique_id}"
            elif getattr(message, "video", None):
                media_id = f"video:{message.video.file_unique_id}"
            elif getattr(message, "audio", None):
                media_id = f"audio:{message.audio.file_unique_id}"
            elif getattr(message, "voice", None):
                media_id = f"voice:{message.voice.file_unique_id}"
            elif getattr(message, "sticker", None):
                media_id = f"sticker:{message.sticker.file_unique_id}"
            elif getattr(message, "animation", None):
                media_id = f"animation:{message.animation.file_unique_id}"
            elif getattr(message, "video_note", None):
                media_id = f"videonote:{message.video_note.file_unique_id}"
            
            if media_id:
                key_parts.append(media_id)
            
            # Only create key if we have date and (content or media)
            if len(key_parts) >= 2:
                return ":".join(key_parts)

    # Old API: User forwards
    if getattr(message, "forward_from", None):
        origin_user_id = message.forward_from.id
        key_parts = [f"user:{origin_user_id}"]
        
        # Add text/caption content if available
        content = (message.text or message.caption or "").strip()
        if content:
            key_parts.append(f"text:{hash(content)}")
        
        # Add media file_unique_id for different media types
        media_id = None
        if getattr(message, "photo", None) and message.photo and len(message.photo) > 0:
            media_id = f"photo:{message.photo[-1].file_unique_id}"
        elif getattr(message, "document", None):
            media_id = f"doc:{message.document.file_unique_id}"
        elif getattr(message, "video", None):
            media_id = f"video:{message.video.file_unique_id}"
        elif getattr(message, "audio", None):
            media_id = f"audio:{message.audio.file_unique_id}"
        elif getattr(message, "voice", None):
            media_id = f"voice:{message.voice.file_unique_id}"
        elif getattr(message, "sticker", None):
            media_id = f"sticker:{message.sticker.file_unique_id}"
        elif getattr(message, "animation", None):
            media_id = f"animation:{message.animation.file_unique_id}"
        elif getattr(message, "video_note", None):
            media_id = f"videonote:{message.video_note.file_unique_id}"
        
        if media_id:
            key_parts.append(media_id)
        
        # Only create key if we have content or media
        if len(key_parts) > 1:
            return ":".join(key_parts)

    # Anonymous/hidden sender name forwards or cases with no reliable key
    return None


async def should_skip_message_protection(update: Update, message) -> bool:
    """Check if a message should be skipped by protection handlers.
    
    Returns True if the message should be excluded from protection (admin, linked channel, etc.)
    """
    # Skip if the user is an admin
    if await is_user_admin(update):
        return True
    
    # Skip messages from GroupAnonymousBot
    if update.effective_user.id == GROUP_ANONYMOUS_BOT_ID:
        return True
    
    # Skip automatic forwards from linked channels
    if getattr(message, "is_automatic_forward", False) is True:
        return True
    
    # Skip forwards from Telegram service (777000) - linked channel posts
    if getattr(message, "forward_from", None) and message.forward_from.id == TELEGRAM_SERVICE_USER_ID:
        return True
    
    # Skip messages directly from Telegram service (777000) - linked channel posts
    if update.effective_user.id == TELEGRAM_SERVICE_USER_ID:
        return True
    
    return False


async def handle_forward_spam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Delete forwarded messages repeated within 24 hours when protection is enabled."""
    try:
        if not context.chat_data.get("forwardSpamProtectionEnabled", False):
            return

        if not update.effective_message or not update.effective_chat or not update.effective_user:
            return

        message = update.effective_message
        
        # Check if message should be skipped (admin, linked channel, etc.)
        if await should_skip_message_protection(update, message):
            logger.debug(f"FSP: Skipping forward from user {update.effective_user.id} in chat {update.effective_chat.id}")
            return

        # Prepare cache in chat_data
        cache: dict = context.chat_data.setdefault("fsp_cache", {})
        _cleanup_fsp_cache(cache)

        key = _make_forward_key(message)
        if key is None:
            return  # Cannot safely identify origin; skip

        # Measure cache read time
        cache_read_start = time.time()
        now = datetime.now(timezone.utc)
        first_seen: datetime | None = cache.get(key)
        cache_read_time = (time.time() - cache_read_start) * 1000  # Convert to milliseconds
        
        # Track cache read performance (store last read time)
        context.bot_data["last_cache_read_time_ms"] = cache_read_time

        if first_seen is None:
            cache[key] = now
            # Optionally persist
            await context.application.update_persistence()
            logger.info(f"FSP: Tracking new forward key={key} in chat {update.effective_chat.id} from user {update.effective_user.id}")
            return

        # If seen before within 24 hours, delete this message
        if now - first_seen <= timedelta(hours=24):
            try:
                delta = now - first_seen
                logger.info(
                    f"FSP trigger: user={update.effective_user.id} chat={update.effective_chat.id} "
                    f"key={key} first_seen={first_seen.isoformat()} now={now.isoformat()} "
                    f"delta_seconds={int(delta.total_seconds())}"
                )
                await message.delete()
                
                # Increment total deleted messages counter
                total_deleted = context.bot_data.setdefault("total_deleted_messages", 0)
                context.bot_data["total_deleted_messages"] = total_deleted + 1
                
                logger.info(
                    f"FSP: Deleted repeated forward key {key} in chat {update.effective_chat.id}"
                )

                # Notify and auto-delete the notice after 6 seconds
                user = update.effective_user
                who = (
                    f"@{user.username}" if getattr(user, "username", None) else str(user.id)
                )
                # Compute remaining time until 24h window expires
                remaining = timedelta(hours=24) - delta
                if remaining.total_seconds() < 0:
                    remaining = timedelta(seconds=0)
                total_secs = int(remaining.total_seconds())
                hours, rem = divmod(total_secs, 3600)
                minutes, seconds = divmod(rem, 60)
                parts = []
                if hours > 0:
                    parts.append(f"{hours}h")
                if minutes > 0 or hours > 0:
                    parts.append(f"{minutes}m")
                parts.append(f"{seconds}s")
                remaining_str = " ".join(parts)
                await send_self_destructing_message(
                    chat_id=update.effective_chat.id,
                    text=f"🧹 Removed repeated forwarded message from {who} (within 24h). "
                         f"Try again in {remaining_str}.",
                    context=context,
                    seconds=6
                )
            except Exception as del_err:
                logger.error(f"FSP: Failed to delete message: {del_err}")
        else:
            # Older than 24h: reset the window to now
            cache[key] = now
            await context.application.update_persistence()
            logger.info(f"FSP: Reset tracking for forward key={key} in chat {update.effective_chat.id} from user {update.effective_user.id} (previous: {first_seen.isoformat()})")
    except Exception as e:
        logger.error(f"Error in handle_forward_spam: {e}")


async def handle_long_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Delete messages with text/caption above the character limit when protection is enabled."""
    try:
        if not context.chat_data.get("longMessageProtectionEnabled", False):
            return

        if not update.effective_message or not update.effective_chat or not update.effective_user:
            return

        message = update.effective_message
        
        # Check if message should be skipped (admin, linked channel, etc.)
        if await should_skip_message_protection(update, message):
            logger.debug(f"LMP: Skipping long message from user {update.effective_user.id} in chat {update.effective_chat.id}")
            return

        # Get text or caption
        text = message.text or message.caption or ""
        text_length = len(text)
        
        # Skip if no text or below limit
        if text_length == 0:
            return
        
        limit = context.chat_data.get("longMessageLimit", 400)
        
        if text_length <= limit:
            return
        
        # Message exceeds limit, delete it
        try:
            logger.info(
                f"LMP trigger: user={update.effective_user.id} chat={update.effective_chat.id} "
                f"text_length={text_length} limit={limit}"
            )
            await message.delete()
            
            # Increment total deleted messages counter
            total_deleted = context.bot_data.setdefault("total_deleted_messages", 0)
            context.bot_data["total_deleted_messages"] = total_deleted + 1
            
            logger.info(
                f"LMP: Deleted long message ({text_length} chars, limit: {limit}) in chat {update.effective_chat.id}"
            )

            # Notify and auto-delete the notice after 6 seconds
            user = update.effective_user
            who = (
                f"@{user.username}" if getattr(user, "username", None) else str(user.id)
            )
            await send_self_destructing_message(
                chat_id=update.effective_chat.id,
                text=f"🧹 Removed message from {who} (exceeded {limit} character limit: {text_length} chars).",
                context=context,
                seconds=6
            )
        except Exception as del_err:
            logger.error(f"LMP: Failed to delete message: {del_err}")
    except Exception as e:
        logger.error(f"Error in handle_long_message: {e}")


@only_target_group
@self_destruct(seconds=4)
async def check_admin_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Debug command to check if a user is an admin, using the best available display name."""
    try:
        if not update.effective_user or not update.effective_chat or not update.message:
            logger.error("check_admin_status called with missing attributes")
            return
        
        user = update.effective_user
        
        who = (
            f"@{user.username}"
            if user.username
            else (str(user.id))
        )

        is_admin = await is_user_admin(update)

        if is_admin:
            response = await update.message.reply_text(f"✅ {who} is an admin in this chat.")
        else:
            response = await update.message.reply_text(f"❌ {who} is NOT an admin in this chat.")

        logger.info(f"Admin status check: {who} ({user.id}) in chat {update.effective_chat.id} is admin: {is_admin}")
        return response
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        if update.message and context.job_queue:
            await send_self_destructing_message(
                chat_id=update.effective_chat.id,
                text="Error checking admin status.",
                context=context,
                seconds=5
            )



@admin_only
@self_destruct(seconds=15)
async def check_all_permissions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Debug command to check all permissions for the bot in the current chat."""
    try:
        if not update.effective_chat or not update.message:
            logger.error("check_all_permissions called with missing attributes")
            return
        
        chat_id = update.effective_chat.id
        chat_type = update.effective_chat.type
        bot_id = context.bot.id
        
        # For private chats, bot has all permissions
        if chat_type == "private":
            response = await update.message.reply_text(
                "✅ *Private Chat - Bot has all permissions*\n\n"
                "In private chats, the bot can perform all actions.",
                parse_mode="Markdown"
            )
            logger.info(f"Bot permission check: Bot {bot_id} in private chat - all permissions granted")
            return response
        
        # Get bot's member info in the chat
        try:
            bot_member = await update.effective_chat.get_member(bot_id)
            status = bot_member.status
            
            # Build permission report for the bot
            permission_text = f"*Bot Permission Report*\n\n"
            permission_text += f"**Chat:** {update.effective_chat.title or 'Unknown'}\n"
            permission_text += f"**Chat Type:** {chat_type}\n"
            permission_text += f"**Bot Status:** {status}\n"
            permission_text += f"**Bot ID:** {bot_id}\n\n"
            
            if status == "administrator":
                # Check specific admin permissions for the bot
                bot_perms = []
                
                # Critical permissions for bot functionality
                if hasattr(bot_member, 'can_delete_messages') and bot_member.can_delete_messages:
                    bot_perms.append("✅ Can delete messages")
                else:
                    bot_perms.append("❌ **Cannot delete messages** (CRITICAL)")
                
                if hasattr(bot_member, 'can_restrict_members') and bot_member.can_restrict_members:
                    bot_perms.append("✅ Can restrict members")
                else:
                    bot_perms.append("❌ Cannot restrict members")
                
                if hasattr(bot_member, 'can_change_info') and bot_member.can_change_info:
                    bot_perms.append("✅ Can change chat info")
                else:
                    bot_perms.append("❌ Cannot change chat info")
                
                if hasattr(bot_member, 'can_invite_users') and bot_member.can_invite_users:
                    bot_perms.append("✅ Can invite users")
                else:
                    bot_perms.append("❌ Cannot invite users")
                
                if hasattr(bot_member, 'can_pin_messages') and bot_member.can_pin_messages:
                    bot_perms.append("✅ Can pin messages")
                else:
                    bot_perms.append("❌ Cannot pin messages")
                
                if hasattr(bot_member, 'can_manage_chat') and bot_member.can_manage_chat:
                    bot_perms.append("✅ Can manage chat")
                else:
                    bot_perms.append("❌ Cannot manage chat")
                
                if hasattr(bot_member, 'can_manage_video_chats') and bot_member.can_manage_video_chats:
                    bot_perms.append("✅ Can manage video chats")
                else:
                    bot_perms.append("❌ Cannot manage video chats")
                
                permission_text += "🤖 **BOT IS ADMINISTRATOR**\n\n"
                permission_text += "**Bot Permissions:**\n"
                permission_text += "\n".join(bot_perms)
                
                # Check if bot can perform its core functions
                can_delete = hasattr(bot_member, 'can_delete_messages') and bot_member.can_delete_messages
                
                permission_text += "\n\n**Bot Functionality Status:**\n"
                if can_delete:
                    permission_text += "✅ Forward spam protection will work"
                else:
                    permission_text += "❌ **Forward spam protection will NOT work**\n\n"
                    permission_text += "⚠️ **Bot needs 'Delete Messages' permission to function properly!**"
                
            elif status == "member":
                permission_text += "👤 **BOT IS REGULAR MEMBER**\n\n"
                permission_text += "❌ **Bot has NO admin permissions**\n"
                permission_text += "❌ **Cannot delete messages**\n"
                permission_text += "❌ **Forward spam protection will NOT work**\n\n"
                permission_text += "⚠️ **Bot needs to be promoted to administrator with 'Delete Messages' permission!**"
                
            elif status == "restricted":
                permission_text += "🚫 **BOT IS RESTRICTED**\n\n"
                permission_text += "❌ **Bot has restricted permissions**\n"
                permission_text += "❌ **Most bot functions will NOT work**"
                
            elif status == "left":
                permission_text += "👻 **BOT HAS LEFT THE CHAT**\n\n"
                permission_text += "❌ **Bot is not in this chat**"
                
            elif status == "kicked":
                permission_text += "🚫 **BOT IS BANNED**\n\n"
                permission_text += "❌ **Bot has been kicked from this chat**"
            
            response = await update.message.reply_text(permission_text, parse_mode="Markdown")
            logger.info(f"Bot permission check completed for chat {chat_id}: status={status}")
            return response
            
        except Exception as member_error:
            logger.error(f"Error getting bot member info: {member_error}")
            response = await update.message.reply_text(
                f"❌ **Error checking bot permissions**\n\n"
                f"Could not retrieve bot member information.\n"
                f"Error: {str(member_error)}",
                parse_mode="Markdown"
            )
            return response
            
    except Exception as e:
        logger.error(f"Error in check_all_permissions: {str(e)}")
        if update.message:
            response = await update.message.reply_text("❌ Error checking bot permissions.")
            return response


def register_conversation_handlers(application):
    """Register command handlers with the application."""
    # Add command handlers
    # Janitor commands disabled
    # application.add_handler(CommandHandler("enable_janitor", enable_janitor))
    # application.add_handler(CommandHandler("disable_janitor", disable_janitor))
    application.add_handler(CommandHandler("status", show_settings))
    application.add_handler(CommandHandler("amiadmin", check_admin_status))
    application.add_handler(CommandHandler("botperms", check_all_permissions))
    application.add_handler(CommandHandler("forwardspam", toggle_forward_spam))
    application.add_handler(CommandHandler("messagecap", toggle_long_message))
    application.add_handler(CommandHandler("setmessagecap", set_long_message_limit))
    # Message handler to enforce forward spam protection
    application.add_handler(MessageHandler(filters.FORWARDED & (~filters.StatusUpdate.ALL) & (~filters.COMMAND), handle_forward_spam))
    # Message handler to enforce long message protection
    application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & (~filters.StatusUpdate.ALL) & (~filters.COMMAND), handle_long_message))
    
    logger.info("Settings handlers registered (janitor features disabled)") 
    logger.info(
        "Command categories: ADMIN-ONLY => ['/amiadmin','/botperms','/forwardspam','/messagecap','/setmessagecap']"
    )
    logger.info(
        "Command categories: ACTIVE FEATURES => ['forward spam protection (message handler)','long message protection (message handler)']"
    )
