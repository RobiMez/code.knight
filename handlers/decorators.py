import logging
from functools import wraps
from telegram import Update, Message
from telegram.ext import ContextTypes

logger = logging.getLogger("telegram_bot")

# Target group restriction
TARGET_GROUP_USERNAME = "robispamgroup"

# List of admin user IDs - move to config in production
ADMIN_USER_IDS = [352475318]  # Replace with actual admin user IDs

# Special Telegram user IDs
GROUP_ANONYMOUS_BOT_ID = 1087968824  # @GroupAnonymousBot
TELEGRAM_SERVICE_USER_ID = 777000  # Telegram service (linked channel posts)


async def is_user_admin(update: Update) -> bool:
    """Check if the user is an admin in the chat."""
    try:
        if not update.effective_user or not update.effective_chat:
            logger.error("is_user_admin called with missing effective_user or effective_chat")
            return False
        
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id
        
        # For private chats, consider the user as admin
        if update.effective_chat.type == "private":
            logger.debug(f"User {user_id} automatically admin in private chat")
            return True
            
        # Get chat administrators
        chat_admins = await update.effective_chat.get_administrators()
        admin_ids = [admin.user.id for admin in chat_admins]
        
        is_admin = user_id in admin_ids
        logger.debug(f"Admin check for user {user_id} in chat {chat_id}: {is_admin}")
        logger.debug(f"Admin IDs in chat: {admin_ids}")
        
        return is_admin
    except Exception as e:
        logger.error(f"Error checking admin status: {str(e)}")
        # Default to not admin if there's an error
        return False


def only_target_group(func):
    """Decorator: allow execution only in the target group @robispamgroup."""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        try:
            chat = update.effective_chat
            if not chat:
                return
            chat_username = getattr(chat, "username", None)
            if chat_username and chat_username.lower() == TARGET_GROUP_USERNAME.lower():
                return await func(update, context, *args, **kwargs)
            target_id = context.application.bot_data.get("target_group_id")
            if target_id is None and TARGET_GROUP_USERNAME:
                try:
                    target_chat = await context.bot.get_chat(f"@{TARGET_GROUP_USERNAME}")
                    context.application.bot_data["target_group_id"] = target_chat.id
                    target_id = target_chat.id
                except Exception as e:
                    logger.error(f"Failed to resolve target group id: {e}")
            if target_id is not None and chat.id == target_id:
                return await func(update, context, *args, **kwargs)
            # Only reply if we have a message to reply to
            if update.message:
                await send_self_destructing_message(
                    chat_id=update.effective_chat.id,
                    text=f"Sorry im built for @{TARGET_GROUP_USERNAME}. Go there to use me.",
                    context=context,
                    seconds=5
                )
            logger.debug(
                f"Ignored command in non-target chat id={chat.id}, username={chat_username}"
            )
            return
        except Exception as e:
            logger.error(f"Error in only_target_group wrapper: {e}")
            return
    return wrapped


def admin_only(func):
    """Decorator to restrict commands to admins only."""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        try:
            if not update.effective_user or not update.effective_chat:
                logger.error("admin_only called with missing effective_user or effective_chat")
                return
            
            if not await is_user_admin(update):
                logger.warning(f"Unauthorized access attempt by user {update.effective_user.id} in chat {update.effective_chat.id}")
                if update.message:
                    await send_self_destructing_message(
                        chat_id=update.effective_chat.id,
                        text="⚠️ This command is restricted to admins only.",
                        context=context,
                        seconds=5
                    )
                return
            logger.info(f"Admin access granted to user {update.effective_user.id} in chat {update.effective_chat.id}")
            return await func(update, context, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error in admin_only wrapper: {str(e)}")
            if update.message:
                await send_self_destructing_message(
                    chat_id=update.effective_chat.id,
                    text="An error occurred while checking permissions.",
                    context=context,
                    seconds=5
                )
    return wrapped


def admin_required(func):
    """Decorator to restrict commands to admin users only."""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id not in ADMIN_USER_IDS:
            await send_self_destructing_message(
                chat_id=update.effective_chat.id,
                text="Sorry, this command is restricted to admins.",
                context=context,
                seconds=5
            )
            logger.warning(f"Non-admin user {user_id} attempted to use admin command")
            return
        return await func(update, context)
    return wrapper


async def _delete_message_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """JobQueue task to delete a specific message."""
    try:
        job = context.job
        data = getattr(job, "data", {}) or {}
        chat_id = data.get("chat_id")
        message_id = data.get("message_id")
        if chat_id and message_id:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
            logger.debug(f"Auto-deleted message {message_id} in chat {chat_id}")
    except Exception as e:
        logger.error(f"Failed to auto-delete message: {e}")


async def send_self_destructing_message(
    chat_id: int,
    text: str,
    context: ContextTypes.DEFAULT_TYPE,
    seconds: int = 6
) -> None:
    """Send a message that will be automatically deleted after a specified time.
    
    Args:
        chat_id: The chat ID where the message should be sent
        text: The message text to send
        context: The bot context with job_queue
        seconds: Time in seconds before the message is deleted (default: 6)
    """
    try:
        notice = await context.bot.send_message(chat_id=chat_id, text=text)
        
        if context.job_queue:
            context.job_queue.run_once(
                _delete_message_job,
                when=seconds,
                data={"chat_id": notice.chat_id, "message_id": notice.message_id},
            )
    except Exception as e:
        logger.error(f"Failed to send self-destructing message: {e}")


def self_destruct(seconds: int = 5):
    """Decorator to automatically delete bot messages after a specified time.
    
    Args:
        seconds: Time in seconds before the message is deleted (default: 5)
    
    Usage:
        @self_destruct(seconds=10)
        async def my_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            message = await update.message.reply_text("This will be deleted in 10 seconds")
            return message  # Return the message object for auto-deletion
    """
    def decorator(func):
        @wraps(func)
        async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            # Call the original handler
            result = await func(update, context, *args, **kwargs)
            
            # If the handler returned a Message object, schedule it for deletion
            if isinstance(result, Message) and context.job_queue:
                try:
                    context.job_queue.run_once(
                        _delete_message_job,
                        when=seconds,
                        data={
                            "chat_id": result.chat_id,
                            "message_id": result.message_id
                        }
                    )
                    logger.debug(f"Scheduled message {result.message_id} for auto-deletion in {seconds} seconds")
                except Exception as e:
                    logger.error(f"Failed to schedule message auto-deletion: {e}")
            
            return result
        return wrapped
    return decorator

