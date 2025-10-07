import logging
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from handlers.conversation import only_target_group

logger = logging.getLogger("telegram_bot")

@only_target_group
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    logger.info(f"User {user.id} started the bot")
    await update.message.reply_text(f'Hello {user.first_name}! I\'m code knight, use /help to get started.')


@only_target_group
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    help_text = """
Available commands:
/start - Start the bot
/help - Show this help message

Admin-only commands:

/toggle_forward_spam - Toggle forward spam protection (deletes repeats within 24h)
/status - Display current chat settings

    """
    await update.message.reply_text(help_text)

def register_basic_handlers(application):
    """Register basic command handlers to the application."""
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    
    logger.info("Basic handlers registered") 