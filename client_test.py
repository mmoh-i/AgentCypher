import os
import requests
import logging
from telegram import Update, Bot
from telegram.ext import Application, filters, CommandHandler, MessageHandler, ContextTypes
from langchain_cohere import ChatCohere
# from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
import base64

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Initialize groq model
api_key = os.getenv("COHERE_API_KEY")
if not api_key:
    raise ValueError("COHERE_API_KEY environment variable not set")
model = ChatCohere(model="command-r-plus", api_key=api_key)

# VirusTotal API key
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
if not virustotal_api_key:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable not set")

# Telegram Bot token
telegram_bot_token = os.getenv("TELEGRAM_TOKEN")
if not telegram_bot_token:
    raise ValueError("TELEGRAM_BOT_TOKEN environment variable not set")

bot = Bot(token=telegram_bot_token)

# In-memory dictionary to store user conversations
user_memory = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a welcome message when the /start command is issued."""
    user = update.effective_user
    user_memory[user.id] = []  # Initialize memory for the user
    await update.message.reply_text(
        f"Hi {user.first_name}! I'm AgentCypher 🤖. I can help you check scams, verify tokens, and scan URLs. Just send a message or use a command. For help, use /help to view the available commands!"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a help message when the /help command is issued."""
    await update.message.reply_text(
        "Commands:\n"
        "/check_scam <text> - Check if a text is a scam.\n"
        "/verified_tokens - Get a list of recently verified tokens.\n"
        "/scan_url - scan a suspicious url.\n"
        "You can also chat with me directly!"
    )

async def check_scam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check if input text is a scam."""
    if len(context.args) == 0:
        await update.message.reply_text("Please provide the text to check. Usage: /check_scam <text>")
        return

    text = " ".join(context.args)
    try:
        # Show typing indicator
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
        
        system_message = SystemMessage(
            content="You are a scam detector. Respond with 'Scam:' or 'Not a Scam:' and provide a brief explanation."
            "especially given your advantage of efficeint twitter data, you can quite know well scam related messages to give justice when detecting scam "
        )
        human_message = HumanMessage(content=f"Analyze this: {text}")
        response = model(messages=[system_message, human_message])

        reply = f"🕵️ Analysis result:\n{response.content}\n\nWhat else can I assist you with?"
        await update.message.reply_text(reply)
    except Exception as e:
        logger.error(f"Error checking scam: {e}")
        await update.message.reply_text("Sorry, I couldn't process your request at the moment.")

async def verified_tokens(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch recently verified tokens."""
    try:
        # Show typing indicator
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
        
        url = "https://api.rugcheck.xyz/v1/stats/verified"
        response = requests.get(url, headers={"Accept": "application/json"})
        if response.status_code == 200:
            tokens = response.json()
            reply = f"✅ Token status:\n{tokens}\n\nLet me know if you need help with anything else!"
            await update.message.reply_text(reply)
        else:
            await update.message.reply_text(
                "❌ Could not fetch verification status for the tokens at this time. Please try again later."
            )
    except Exception as e:
        logger.error(f"Error fetching token verification status: {e}")
        await update.message.reply_text("An error occurred while fetching token verification status.")

async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Scan a URL."""
    # Show typing indicator
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    
    if len(context.args) == 0:
        await update.message.reply_text("Please provide a URL to scan. Usage: /scan_url <url>")
        return

    url = " ".join(context.args)
    await process_url_scan(update, url)

async def process_url_scan(update: Update, url: str) -> None:
    """Process URL scanning logic."""
    try:
        # Encode the URL for VirusTotal's database lookup
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_data = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": virustotal_api_key},
        ).json()

        if "error" not in url_data:
            stats = url_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            reply = (
                f"🔍 URL Analysis Results\n\n"
                f"  Harmless: {stats.get('harmless', 0)}\n"
                f"  Malicious: {stats.get('malicious', 0)}\n"
                f"  Suspicious: {stats.get('suspicious', 0)}\n"
                f"  Undetected: {stats.get('undetected', 0)}\n\n"
                f"Risk Summary:\n"
                f"  Total Malicious or Suspicious Reports: {stats.get('malicious', 0) + stats.get('suspicious', 0)}\n"
                f"  Risk Score: {round((stats.get('malicious', 0) + stats.get('suspicious', 0)) / max(sum(stats.values()), 1) * 100, 2)}%\n"
            )
            await update.message.reply_text(reply)
        else:
            await update.message.reply_text("URL not found in the VirusTotal database. Submitted for scanning. Try again after a few minutes.")
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        await update.message.reply_text("An error occurred while scanning the URL.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle user messages and generate conversational responses."""
    user = update.effective_user
    user_message = update.message.text

    # Check if the message is about scanning a URL
    if user_message.lower().startswith("scan url"):
        url = user_message[8:].strip()
        if url:
            await process_url_scan(update, url)
            return

    # Show typing indicator
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")

    # Retrieve user memory and update it
    conversation = user_memory.get(user.id, [])
    
    try:
        # Create message history for context
        messages = [
            SystemMessage(
                content="""You are AgentCypher, a helpful AI assistant that specializes in:
                1. Detecting crypto and web3 scams
                2. Analyzing suspicious URLs
                3. Verifying tokens and smart contracts
                4. Providing general blockchain security advice
                
                Keep your responses concise and focused on helping users with security-related queries.
                If you're unsure about something, be honest about it."""
            )
        ]
        
        # Add conversation history
        if conversation:
            messages.extend([HumanMessage(content=msg) for msg in conversation[-4:]])  # Last 2 exchanges
            
        # Add current message
        messages.append(HumanMessage(content=user_message))
        
        # Get response from model
        response = model.invoke(messages)
        
        # Update conversation memory
        conversation.append(user_message)
        conversation.append(response.content)
        user_memory[user.id] = conversation[-10:]  # Keep last 10 messages
        
        # Send response
        await update.message.reply_text(response.content)
        
    except Exception as e:
        logger.error(f"Error handling message: {str(e)}")
        logger.error(f"User message was: {user_message}")
        await update.message.reply_text("I'm currently experiencing some technical difficulties. Please try using specific commands like /check_scam or /scan_url for now.")

def main() -> None:
    """Start the bot."""
    application = Application.builder().token(telegram_bot_token).build()

    # Command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("check_scam", check_scam))
    application.add_handler(CommandHandler("verified_tokens", verified_tokens))
    application.add_handler(CommandHandler("scan_url", scan_url))

    # Message handler for general messages (including URL scanning)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Start the bot
    application.run_polling()

if __name__ == "__main__":
    main()