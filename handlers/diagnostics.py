import logging
import sys
import time
from datetime import datetime
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler
from telegram.constants import ParseMode
from handlers.decorators import self_destruct

logger = logging.getLogger("telegram_bot")


from handlers.decorators import ADMIN_USER_IDS

# Throttling constants
LAST_ACTIVITY_UPDATE_INTERVAL = 60  # Update last_activity every 60 seconds
MEMBER_COUNT_UPDATE_INTERVAL = 300  # Update member count every 5 minutes (300 seconds)

def is_admin(user_id):
    """Check if a user is authorized to use admin commands."""
    return user_id in ADMIN_USER_IDS

async def track_chat(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Track chats the bot is added to with throttled updates."""
    chat = update.effective_chat
    
    if not chat:
        return
    
    # Initialize bot_data structure if not exists
    if "tracked_chats" not in context.bot_data:
        context.bot_data["tracked_chats"] = {}
    
    now = datetime.now()
    chat_id = chat.id
    
    # Check if chat is already tracked
    existing_chat = context.bot_data["tracked_chats"].get(chat_id)
    
    # Determine if we need to update last_activity (throttled)
    should_update_activity = False
    if not existing_chat:
        should_update_activity = True
    else:
        last_activity_str = existing_chat.get("last_activity")
        if last_activity_str:
            try:
                last_activity = datetime.fromisoformat(last_activity_str)
                time_since_last = (now - last_activity).total_seconds()
                if time_since_last >= LAST_ACTIVITY_UPDATE_INTERVAL:
                    should_update_activity = True
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not parse last_activity for chat {chat_id}: {e}")
                should_update_activity = True
        else:
            should_update_activity = True
    
    # Determine if we need to update member count (throttled, only for groups/supergroups)
    should_update_member_count = False
    member_count = existing_chat.get("members", "Unknown") if existing_chat else "Unknown"
    
    if chat.type in ["group", "supergroup"]:
        if not existing_chat or existing_chat.get("members") == "Unknown":
            should_update_member_count = True
        else:
            last_member_update_str = existing_chat.get("last_member_count_update")
            if last_member_update_str:
                try:
                    last_member_update = datetime.fromisoformat(last_member_update_str)
                    time_since_last_update = (now - last_member_update).total_seconds()
                    if time_since_last_update >= MEMBER_COUNT_UPDATE_INTERVAL:
                        should_update_member_count = True
                except (ValueError, TypeError) as e:
                    logger.debug(f"Could not parse last_member_count_update for chat {chat_id}: {e}")
                    should_update_member_count = True
            else:
                should_update_member_count = True
    
    # Update member count if needed
    if should_update_member_count and chat.type in ["group", "supergroup"]:
        try:
            member_count = await context.bot.get_chat_member_count(chat.id)
        except Exception as e:
            # Log as warning for expected failures (private chats, permission issues)
            # Only log as error for unexpected failures
            if chat.type in ["group", "supergroup"]:
                logger.warning(f"Could not get member count for chat {chat.id} (may not have permission): {e}")
            else:
                logger.debug(f"Member count not available for chat type {chat.type}: {e}")
            # Keep existing member count or use "Unknown"
            member_count = existing_chat.get("members", "Unknown") if existing_chat else "Unknown"
    
    # Build chat info dict
    chat_info = {
        "chat_id": chat_id,
        "title": chat.title or (f"Private chat with {update.effective_user.first_name}" if chat.type == "private" and update.effective_user else "Unknown"),
        "type": chat.type,
        "username": chat.username,
    }
    
    # Update fields conditionally
    if should_update_activity:
        chat_info["last_activity"] = now.isoformat()
    elif existing_chat and "last_activity" in existing_chat:
        chat_info["last_activity"] = existing_chat["last_activity"]
    
    if should_update_member_count or not existing_chat:
        chat_info["members"] = member_count
        if chat.type in ["group", "supergroup"]:
            chat_info["last_member_count_update"] = now.isoformat()
    elif existing_chat:
        chat_info["members"] = existing_chat.get("members", "Unknown")
        if "last_member_count_update" in existing_chat:
            chat_info["last_member_count_update"] = existing_chat["last_member_count_update"]
    
    # Store or update chat info
    context.bot_data["tracked_chats"][chat_id] = chat_info


async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show bot statistics and diagnostics (admin only)."""
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        from handlers.decorators import send_self_destructing_message
        await send_self_destructing_message(
            chat_id=update.effective_chat.id,
            text="⛔ You are not authorized to use this command.",
            context=context,
            seconds=5
        )
        logger.warning(f"Unauthorized access attempt to admin command by user {user_id}")
        return
    
    # Gather statistics
    total_chats = 0
    private_chats = 0
    groups = 0
    supergroups = 0
    channels = 0
    
    if "tracked_chats" in context.bot_data:
        for chat_id, chat in context.bot_data["tracked_chats"].items():
            total_chats += 1
            chat_type = chat.get("type", "unknown")
            if chat_type == "private":
                private_chats += 1
            elif chat_type == "group":
                groups += 1
            elif chat_type == "supergroup":
                supergroups += 1
            elif chat_type == "channel":
                channels += 1
            
            # Count filters - DISABLED since filters are disabled
            # chat_data = context.application.chat_data.get(chat_id, {})
            # filters_count = len(chat_data.get("filter_patterns", []))
            # total_filters += filters_count
    
    # Bot uptime
    bot_start_time = context.bot_data.get("start_time")
    uptime_str = "Unknown"
    
    # If no start_time exists, initialize it now as a fallback
    if not bot_start_time:
        logger.warning("No start_time found in bot_data, initializing now")
        current_time = datetime.now()
        context.bot_data["start_time"] = current_time.isoformat()
        bot_start_time = current_time.isoformat()
        try:
            await context.application.update_persistence()
            logger.info("Initialized start_time and updated persistence")
        except Exception as e:
            logger.error(f"Failed to update persistence with new start_time: {e}")
    
    if bot_start_time:
        try:
            # Handle both string and datetime objects
            if isinstance(bot_start_time, str):
                start_time = datetime.fromisoformat(bot_start_time)
            else:
                start_time = bot_start_time
                
            uptime = datetime.now() - start_time
            days = uptime.days
            hours, remainder = divmod(uptime.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
            logger.info(f"Calculated uptime: {uptime_str}")
        except Exception as e:
            logger.error(f"Error calculating uptime: {e}")
            logger.error(f"Start time value: {bot_start_time}, type: {type(bot_start_time)}")
            uptime_str = "Error calculating"
    
    # Format statistics
    stats_text = (
        f"*🤖 Bot Statistics*\n\n"
        f"*Chats:*\n"
        f"• Total chats: {total_chats}\n"
        f"• Private chats: {private_chats}\n"
        f"• Groups: {groups}\n"
        f"• Supergroups: {supergroups}\n"
        f"• Channels: {channels}\n\n"
        # f"*Filters:*\n"
        # f"• Total filter patterns: {total_filters}\n\n"
        f"*Performance:*\n"
        f"• Bot uptime: {uptime_str}\n"
    )
    
    await update.message.reply_text(
        stats_text,
        parse_mode=ParseMode.MARKDOWN
    )
    logger.info(f"Admin {user_id} requested bot statistics")

@self_destruct(seconds=10)
async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show cache statistics, ping, and deletion count (admin only)."""
    try:
        if not update.effective_user or not update.message:
            logger.error("admin_cache_stats called with missing effective_user or message")
            return
        
        user_id = update.effective_user.id
        
        if not is_admin(user_id):
            from handlers.decorators import send_self_destructing_message
            await send_self_destructing_message(
                chat_id=update.effective_chat.id,
                text="⛔ You are not authorized to use this command.",
                context=context,
                seconds=5
            )
            logger.warning(f"Unauthorized access attempt to admin command by user {user_id}")
            return
        
        # Get cache from chat_data (only one chat)
        cache_entries = 0
        cache_size_bytes = 0
        cache = None
        
        # Find the cache in chat_data
        for chat_id, chat_data in context.application.chat_data.items():
            if isinstance(chat_data, dict) and "fsp_cache" in chat_data:
                cache = chat_data["fsp_cache"]
                if isinstance(cache, dict):
                    cache_entries = len(cache)
                    # Calculate approximate cache size: sum of key sizes + datetime sizes
                    total_size = sys.getsizeof(cache)  # Base dict overhead
                    for key, value in cache.items():
                        total_size += sys.getsizeof(key)  # String key
                        total_size += sys.getsizeof(value)  # Datetime value
                    cache_size_bytes = total_size
                    break  # Only one chat
        
        # Measure cache read time directly (average of multiple reads)
        cache_read_time = None
        if cache and cache_entries > 0:
            # Measure multiple cache reads and average for accuracy
            cache_keys = list(cache.keys())
            num_samples = min(10, len(cache_keys))  # Sample up to 10 reads
            total_read_time = 0
            
            for i in range(num_samples):
                cache_read_start = time.time()
                _ = cache.get(cache_keys[i % len(cache_keys)])
                total_read_time += (time.time() - cache_read_start) * 1000  # Convert to milliseconds
            
            cache_read_time = total_read_time / num_samples
        
        # Measure API ping (Telegram API response time)
        api_ping_start = time.time()
        try:
            await context.bot.get_me()
            api_ping_time = (time.time() - api_ping_start) * 1000  # Convert to milliseconds
        except Exception as e:
            logger.error(f"Error measuring API ping: {e}")
            api_ping_time = None
        
        # Get pending updates count
        pending_updates = 0
        try:
            # Check if application has an update_queue attribute
            if hasattr(context.application, 'update_queue'):
                update_queue = context.application.update_queue
                if hasattr(update_queue, 'qsize'):
                    pending_updates = update_queue.qsize()
                elif hasattr(update_queue, '_queue'):
                    # Fallback for different queue implementations
                    pending_updates = len(update_queue._queue) if hasattr(update_queue._queue, '__len__') else 0
        except Exception as e:
            logger.debug(f"Could not get pending updates count: {e}")
        
        # Format the stats response
        stats_text = f"*Entries:* {cache_entries}\n"
        stats_text += f"*Size:* {cache_size_bytes} bytes\n"
        
        if cache_read_time is not None:
            stats_text += f"*Read time:* {cache_read_time:.3f}ms\n"
        else:
            stats_text += f"*Read time:* N/A (cache empty)\n"
        
        if api_ping_time is not None:
            stats_text += f"*Ping:* {api_ping_time:.2f}ms\n"
        else:
            stats_text += f"*Ping:* Error\n"
        
        stats_text += f"*Pending updates:* {pending_updates}\n"
        
        response = await update.message.reply_text(
            stats_text,
            parse_mode=ParseMode.MARKDOWN
        )
        logger.info(f"Admin {user_id} requested cache statistics")
        return response
    except Exception as e:
        logger.error(f"Error in admin_cache_stats: {e}", exc_info=True)
        if update.message:
            try:
                from handlers.decorators import send_self_destructing_message
                await send_self_destructing_message(
                    chat_id=update.effective_chat.id,
                    text="❌ An error occurred while processing the ping command.",
                    context=context,
                    seconds=5
                )
            except:
                pass

def register_diagnostic_handlers(application):
    """Register diagnostic handlers with the application."""
    # Admin commands
    application.add_handler(CommandHandler("ping", ping))

    application.add_handler(CommandHandler("stats", stats))
    
    logger.info("Diagnostic handlers registered")
