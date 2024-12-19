import os
import logging
import string
import re
from datetime import datetime
from telegram import Update, ChatMember, ChatMemberAdministrator, ChatPermissions
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters, ChatMemberHandler
from telegram.constants import ParseMode
from dotenv import load_dotenv
import importlib.util
import joblib
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
import sqlite3
import json

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

# Import app.py dynamically
spec = importlib.util.spec_from_file_location("app", "app.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

# Load environment variables
load_dotenv()

# Initialize Gemini
app.init_gemini()

# Load the spam detection model
try:
    spam_model = joblib.load("c:\\Users\\HP\\Downloads\\spam.joblib")
    SPAM_DETECTION_ENABLED = True
except:
    logger.warning("Spam detection model not found. Spam detection will be disabled.")
    SPAM_DETECTION_ENABLED = False

# Database setup
def setup_database():
    conn = sqlite3.connect('bot_data.db')
    c = conn.cursor()
    
    # Create groups table
    c.execute('''CREATE TABLE IF NOT EXISTS groups
                 (group_id INTEGER PRIMARY KEY,
                  settings TEXT,
                  joined_date TEXT,
                  last_activity TEXT)''')
    
    # Create spam_log table
    c.execute('''CREATE TABLE IF NOT EXISTS spam_log
                 (message_id INTEGER,
                  group_id INTEGER,
                  user_id INTEGER,
                  message_type TEXT,
                  detection_type TEXT,
                  timestamp TEXT)''')
    
    conn.commit()
    conn.close()

# Group settings management
class GroupSettings:
    def __init__(self, group_id):
        self.group_id = group_id
        self.settings = self.load_settings()
    
    def load_settings(self):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute('SELECT settings FROM groups WHERE group_id = ?', (self.group_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return json.loads(result[0])
        return {
            'delete_spam': False,
            'notify_admins': True,
            'sensitivity': 'medium',
            'scan_links': True,
            'scan_messages': True,
            'whitelist': [],
            'blacklist': []
        }
    
    def save_settings(self):
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        settings_json = json.dumps(self.settings)
        c.execute('''INSERT OR REPLACE INTO groups (group_id, settings, last_activity) 
                     VALUES (?, ?, ?)''', (self.group_id, settings_json, datetime.now().isoformat()))
        conn.commit()
        conn.close()

async def log_spam_detection(message_id, group_id, user_id, message_type, detection_type):
    conn = sqlite3.connect('bot_data.db')
    c = conn.cursor()
    c.execute('''INSERT INTO spam_log (message_id, group_id, user_id, message_type, detection_type, timestamp)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (message_id, group_id, user_id, message_type, detection_type, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def process_text(message):
    """Process text for spam detection with enhanced feature preservation"""
    # Convert to lowercase but preserve special patterns
    text = message.lower()
    
    # Count special patterns before removing them
    patterns = {
        'exclamation': text.count('!'),
        'dollar': text.count('$'),
        'urgent': 'urgent' in text.lower(),
        'limited': 'limited' in text.lower(),
        'offer': 'offer' in text.lower(),
        'congratulations': 'congratulations' in text.lower(),
        'winner': 'winner' in text.lower(),
        'bitcoin': 'bitcoin' in text.lower() or 'western union' in text.lower(),
        'investment': 'investment' in text.lower(),
        'contact': 'contact' in text.lower(),
        'opportunity': 'opportunity' in text.lower(),
        'discount': 'discount' in text.lower(),
        'free': 'free' in text.lower(),
        'guaranteed': 'guaranteed' in text.lower(),
        'prize': 'prize' in text.lower(),
        'earn': 'earn' in text.lower(),
        # Romance scam patterns
        'model': 'model' in text.lower(),
        'private_email': 'private email' in text.lower() or 'my email' in text.lower(),
        'instant_connection': 'instant connection' in text.lower() or 'felt connection' in text.lower(),
        'dear': 'dear' in text.lower(),
        'profile': 'profile' in text.lower() or 'saw you' in text.lower(),
        'surprise': 'surprise' in text.lower() or 'special' in text.lower(),
        'love': 'love' in text.lower() or 'relationship' in text.lower(),
        'beautiful': 'beautiful' in text.lower() or 'handsome' in text.lower(),
        'emoji_hearts': '😘' in text or '❤' in text or '💕' in text,
        # Existing patterns...
        'donation': 'donation' in text.lower() or 'donate' in text.lower(),
        'victims': 'victims' in text.lower() or 'disaster' in text.lower(),
        'help_needed': 'help needed' in text.lower(),
        'alert': 'alert' in text.lower(),
        'security': 'security' in text.lower(),
        'infected': 'infected' in text.lower() or 'malware' in text.lower(),
        'technician': 'technician' in text.lower() or 'technical support' in text.lower(),
        'risk': 'risk' in text.lower() or 'at risk' in text.lower(),
        'act_fast': 'act fast' in text.lower() or 'immediately' in text.lower(),
        'emergency': 'emergency' in text.lower(),
        'funds': 'funds' in text.lower(),
        'personal_data': 'personal data' in text.lower() or 'data loss' in text.lower()
    }
    
    # Process text while preserving structure
    text_split = text.split()
    texts = [word.strip(string.punctuation.replace('!', '').replace('$', '')) for word in text_split]
    texts = [word for word in texts if word]
    
    # Add pattern indicators to the processed text
    if patterns['exclamation'] > 2:
        texts.append('multiple_exclamations')
    if patterns['dollar'] or patterns['bitcoin']:
        texts.append('money_transfer')
    if patterns['urgent'] or patterns['emergency']:
        texts.append('urgency_flag')
    if patterns['donation'] or patterns['victims']:
        texts.append('charity_scam')
    if patterns['infected'] or patterns['security'] or patterns['technician']:
        texts.append('tech_support_scam')
    # Romance scam indicators
    if (patterns['model'] or patterns['beautiful']) and (patterns['contact'] or patterns['private_email']):
        texts.append('romance_scam')
    if patterns['instant_connection'] or (patterns['profile'] and patterns['love']):
        texts.append('romance_scam')
    if patterns['dear'] and patterns['surprise'] and patterns['emoji_hearts']:
        texts.append('romance_scam')
    if sum(patterns.values()) > 3:
        texts.append('spam_patterns')
    
    # Remove stop words but keep important spam-related words
    spam_related_words = {'urgent', 'limited', 'offer', 'congratulations', 'winner', 'bitcoin', 
                         'investment', 'contact', 'opportunity', 'discount', 'free', 'guaranteed',
                         'prize', 'earn', 'donation', 'victims', 'alert', 'security', 'infected',
                         'technician', 'risk', 'emergency', 'funds', 'malware', 'western', 'union',
                         'model', 'beautiful', 'love', 'dear', 'profile', 'surprise', 'special',
                         'connection', 'private', 'email'}
    texts = [word for word in texts if word not in ENGLISH_STOP_WORDS or word in spam_related_words]
    
    return ' '.join(texts)

def predict_spam(text):
    """Predict if a message is spam with enhanced detection"""
    if not SPAM_DETECTION_ENABLED:
        return False
        
    # Skip very short messages
    if len(text.split()) <= 3:
        return False
        
    # Skip URLs
    if text.startswith(('http://', 'https://')):
        return False
    
    try:
        processed_text = process_text(text)
        # Skip if processed text is too short
        if len(processed_text.split()) <= 2:
            return False
            
        # Check for obvious spam patterns
        obvious_spam_patterns = {
            'urgent': 'urgent' in processed_text.lower() or 'urgency_flag' in processed_text.lower(),
            'money_transfer': 'money_transfer' in processed_text.lower(),
            'charity_scam': 'charity_scam' in processed_text.lower(),
            'tech_support_scam': 'tech_support_scam' in processed_text.lower(),
            'romance_scam': 'romance_scam' in processed_text.lower(),
            'multiple_exclamations': 'multiple_exclamations' in processed_text.lower(),
            'bitcoin': 'bitcoin' in processed_text.lower() or 'western union' in processed_text.lower(),
            'emergency': 'emergency' in processed_text.lower(),
            'risk': 'risk' in processed_text.lower(),
            'security': 'security' in processed_text.lower(),
            'spam_patterns': 'spam_patterns' in processed_text.lower(),
            'private_contact': 'private' in processed_text.lower() and 'email' in processed_text.lower(),
            'model_contact': 'model' in processed_text.lower() and 'contact' in processed_text.lower()
        }
        
        # Romance scam specific check
        romance_indicators = [
            'model' in processed_text.lower(),
            'beautiful' in processed_text.lower(),
            'love' in processed_text.lower(),
            'private' in processed_text.lower(),
            'email' in processed_text.lower(),
            'surprise' in processed_text.lower(),
            'dear' in processed_text.lower(),
            'connection' in processed_text.lower()
        ]
        
        # If multiple romance indicators or any two spam patterns are found, mark as spam
        if sum(romance_indicators) >= 2 or sum(obvious_spam_patterns.values()) >= 2:
            return True
            
        # Use the model for more nuanced detection
        prediction = spam_model.predict([processed_text])[0]
        return prediction == 1
    except Exception as e:
        logger.error(f"Error in spam prediction: {str(e)}")
        return False

async def handle_group_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages in groups"""
    if not update.message or not update.effective_chat or not update.effective_chat.id:
        return
        
    # Load group settings
    group_settings = GroupSettings(update.effective_chat.id)
    
    # Skip if message is from whitelisted user
    if update.effective_user.id in group_settings.settings['whitelist']:
        return
        
    # Check if message contains URL
    message_text = update.message.text or update.message.caption or ""
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message_text)
    
    is_spam = False
    detection_type = None
    
    try:
        # Check URLs if enabled
        if urls and group_settings.settings['scan_links']:
            processing_message = None
            if group_settings.settings.get('notify_admins', True):
                processing_message = await update.message.reply_text(
                    "🔍 Analyzing link...",
                    reply_to_message_id=update.message.message_id
                )
            
            for url in urls:
                # Get scan results
                vt_results = app.check_virustotal(url)
                gsb_results = app.check_google_safe_browsing(url)
                urlscan_results = app.check_urlscan(url)
                
                # Calculate threat score
                threat_score = 0
                threat_details = []
                
                # Check VirusTotal results
                if not vt_results.get('error'):
                    malicious_count = vt_results.get('malicious', 0)
                    suspicious_count = vt_results.get('suspicious', 0)
                    reputation = vt_results.get('reputation', 0)
                    
                    if malicious_count > 0:
                        threat_score += 40
                        threat_details.append(f"{malicious_count} security vendors flagged this URL as malicious")
                    if suspicious_count > 0:
                        threat_score += 20
                        threat_details.append(f"{suspicious_count} vendors found suspicious behavior")
                    if reputation < 0:
                        threat_score += 10
                        threat_details.append("URL has negative reputation score")
                
                # Check Google Safe Browsing results
                if not gsb_results.get('error'):
                    threats = gsb_results.get('threats_found', 0)
                    if threats > 0:
                        threat_score += 40
                        threat_details.append("Google Safe Browsing detected threats")
                        threat_details.extend([f"- {match.get('threatType', 'Unknown threat')}" 
                                            for match in gsb_results.get('details', [])])
                
                # Check URLScan results
                if not urlscan_results.get('error'):
                    if urlscan_results.get('malicious', False):
                        threat_score += 30
                        threat_details.append("URLScan.io detected malicious behavior")
                
                # Determine if URL is malicious based on threat score
                if threat_score >= 40:  # Threshold for marking as malicious
                    is_spam = True
                    detection_type = 'phishing_link'
                    break
            
            if processing_message:
                await processing_message.delete()
        
        # Check message content if enabled and no phishing detected yet
        if not is_spam and group_settings.settings['scan_messages']:
            is_spam = predict_spam(message_text)
            if is_spam:
                detection_type = 'spam_message'
        
        # Handle spam detection
        if is_spam:
            # Log the detection
            await log_spam_detection(
                update.message.message_id,
                update.effective_chat.id,
                update.effective_user.id,
                'url' if urls else 'text',
                detection_type
            )
            
            # Prepare warning message
            warning = (
                f"🛡 Security Alert\n"
                f"Type: {detection_type.replace('_', ' ').title()}\n"
                f"User: {update.effective_user.mention_html()}\n\n"
            )
            
            # Add details based on detection type
            if detection_type == 'phishing_link':
                warning += "This message contains potentially harmful links that may compromise security.\n"
                if threat_details:
                    warning += "\nDetection details:\n• " + "\n• ".join(threat_details)
            else:
                warning += "This message matches patterns associated with malicious content.\n"
            
            warning += "\nℹ️ Group admins have been notified."
            
            # Send warning
            await update.message.reply_text(
                warning,
                reply_to_message_id=update.message.message_id,
                parse_mode=ParseMode.HTML
            )
            
            # Delete message if enabled and bot has permission
            if group_settings.settings['delete_spam']:
                try:
                    await update.message.delete()
                except Exception as e:
                    logger.error(f"Failed to delete spam message: {e}")
            
            # Notify admins if enabled
            if group_settings.settings['notify_admins']:
                admins = await update.effective_chat.get_administrators()
                admin_msg = (
                    f"🚨 Admin Alert\n"
                    f"Spam detected in {update.effective_chat.title}\n"
                    f"User: {update.effective_user.mention_html()}\n"
                    f"Type: {detection_type.replace('_', ' ')}\n"
                )
                if threat_details:
                    admin_msg += "\nDetection details:\n• " + "\n• ".join(threat_details)
                
                for admin in admins:
                    try:
                        await context.bot.send_message(
                            admin.user.id,
                            admin_msg,
                            parse_mode=ParseMode.HTML
                        )
                    except Exception as e:
                        logger.error(f"Failed to notify admin {admin.user.id}: {e}")
    
    except Exception as e:
        logger.error(f"Error in group message handler: {e}")

async def handle_group_join(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle bot joining a group"""
    if update.my_chat_member and update.my_chat_member.new_chat_member:
        new_member = update.my_chat_member.new_chat_member
        if new_member.status in ['member', 'administrator']:
            # Initialize group in database
            group_settings = GroupSettings(update.effective_chat.id)
            group_settings.save_settings()
            
            # Send welcome message
            welcome_msg = (
                "👋 Hello! I'm your new security bot.\n\n"
                "I'll help protect this group from:\n"
                "• Spam messages\n"
                "• Phishing links\n"
                "• Suspicious content\n\n"
                "I'll work silently and only alert when threats are detected.\n"
                "Admins can use /settings to configure my behavior."
            )
            await context.bot.send_message(
                update.effective_chat.id,
                welcome_msg
            )

async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /settings command"""
    if not update.effective_chat.id:
        return
        
    # Check if user is admin
    user_member = await update.effective_chat.get_member(update.effective_user.id)
    if not isinstance(user_member, ChatMemberAdministrator):
        await update.message.reply_text("⚠️ Only group administrators can change settings.")
        return
    
    group_settings = GroupSettings(update.effective_chat.id)
    
    # Parse command arguments
    if not context.args:
        # Show current settings
        settings_msg = (
            "*Current Settings:*\n"
            f"🗑 Delete Spam: `{group_settings.settings['delete_spam']}`\n"
            f"👮 Notify Admins: `{group_settings.settings['notify_admins']}`\n"
            f"🎚 Sensitivity: `{group_settings.settings['sensitivity']}`\n"
            f"🔗 Scan Links: `{group_settings.settings['scan_links']}`\n"
            f"💬 Scan Messages: `{group_settings.settings['scan_messages']}`\n\n"
            "Use `/settings <option> <value>` to change settings.\n"
            "Example: `/settings delete_spam true`"
        )
        await update.message.reply_text(settings_msg, parse_mode=ParseMode.MARKDOWN)
        return
    
    # Handle setting changes
    if len(context.args) >= 2:
        setting = context.args[0]
        value = context.args[1].lower()
        
        if setting in group_settings.settings:
            if value in ['true', 'false']:
                group_settings.settings[setting] = value == 'true'
            elif setting == 'sensitivity':
                if value in ['low', 'medium', 'high']:
                    group_settings.settings[setting] = value
            
            group_settings.save_settings()
            await update.message.reply_text(f"✅ Setting `{setting}` updated to `{value}`", parse_mode=ParseMode.MARKDOWN)
        else:
            await update.message.reply_text("❌ Invalid setting. Use /settings to see available options.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a message when the command /start is issued."""
    welcome_message = (
        "👋 Welcome to the Advanced Security Bot!\n\n"
        "I can help you:\n"
        "• Analyze URLs for phishing threats\n"
        "• Detect spam messages\n"
        "• Provide AI-powered security advice\n\n"
        "Commands:\n"
        "/start - Show this welcome message\n"
        "/help - Show help information\n"
        "/suiguard [question] - Ask AI about cybersecurity\n"
        "/check [url] - Analyze a specific URL\n"
    )
    await update.message.reply_text(welcome_message)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a message when the command /help is issued."""
    help_text = (
        "🔍 How to use this bot:\n\n"
        "1. Send any URL to check if it's potentially malicious\n"
        "2. Send any message to check if it's spam\n"
        "3. Use /suiguard followed by your question to get AI-powered cybersecurity advice\n"
        "4. Use /check followed by a URL to analyze it\n\n"
        "Examples:\n"
        "• Simply paste a URL to analyze it\n"
        "• /suiguard What are common signs of phishing emails?\n"
        "• /check https://example.com\n"
    )
    await update.message.reply_text(help_text)

async def analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze a URL for potential phishing threats and check the message for spam."""
    message_text = update.message.text.strip()
    
    # Check if the message contains a URL
    if message_text.startswith(('http://', 'https://')):
        processing_message = await update.message.reply_text("🔍 Analyzing the URL... Please wait.")
        
        try:
            # Collect results from all services
            vt_results = app.check_virustotal(message_text)
            gsb_results = app.check_google_safe_browsing(message_text)
            urlscan_results = app.check_urlscan(message_text)
            
            # Prepare the response message
            response = "🔒 URL Analysis Results:\n\n"
            
            # VirusTotal results
            if "error" not in vt_results:
                response += f"VirusTotal:\n"
                response += f"- Positives: {vt_results.get('positives', 'N/A')}\n"
                response += f"- Total Scans: {vt_results.get('total', 'N/A')}\n\n"
            
            # Google Safe Browsing results
            if gsb_results and "error" not in gsb_results:
                response += f"Google Safe Browsing:\n"
                if len(gsb_results.get('matches', [])) > 0:
                    response += "⚠️ Threats detected!\n"
                    for match in gsb_results['matches']:
                        response += f"- {match.get('threatType', 'Unknown threat')}\n"
                else:
                    response += "✅ No threats detected\n\n"
            
            # URLScan results
            if urlscan_results and "error" not in urlscan_results:
                response += f"URLScan.io:\n"
                response += f"- Score: {urlscan_results.get('score', 'N/A')}\n"
                if 'malicious' in urlscan_results:
                    response += f"- Malicious: {'Yes' if urlscan_results['malicious'] else 'No'}\n\n"
            
            await processing_message.edit_text(response)
            
        except Exception as e:
            await processing_message.edit_text(f"❌ Error analyzing URL: {str(e)}")
    else:
        # Only check for spam if it's not a URL
        if SPAM_DETECTION_ENABLED and len(message_text.split()) > 3:  # Only check messages with more than 3 words
            try:
                is_spam = predict_spam(message_text)
                if is_spam:
                    await update.message.reply_text("⚠️ Warning: This message has been detected as potential spam!")
            except Exception as e:
                logger.error(f"Error in spam detection: {str(e)}")

async def handle_ai_question(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle AI-related questions about cybersecurity."""
    if not context.args:
        await update.message.reply_text("Please provide a question after /suiguard")
        return
    
    question = ' '.join(context.args)
    processing_message = await update.message.reply_text("🤔 Thinking...")
    
    try:
        response = app.ask_assistant_helper(question)
        await processing_message.edit_text(response)
    except Exception as e:
        await processing_message.edit_text(f"❌ Error: {str(e)}")

async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle the /check command for URL analysis"""
    if not context.args:
        await update.message.reply_text("Please provide a URL to check. Usage: /check <url>")
        return

    url = context.args[0]
    if not url.startswith(('http://', 'https://')):
        await update.message.reply_text("Please provide a valid URL starting with http:// or https://")
        return

    # Use the existing analyze_url function with a modified message
    update.message.text = url
    await analyze_url(update, context)

def main():
    """Start the bot."""
    # Setup database
    setup_database()
    
    # Get the token from environment variable
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        print("Error: TELEGRAM_BOT_TOKEN not found in environment variables")
        return

    # Create the Application
    application = Application.builder().token(token).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("suiguard", handle_ai_question))
    application.add_handler(CommandHandler("check", check_command))
    application.add_handler(CommandHandler("settings", settings_command))
    
    # Add group message handler
    application.add_handler(MessageHandler(
        filters.ChatType.GROUPS & filters.TEXT & ~filters.COMMAND,
        handle_group_message
    ))
    
    # Add group join handler
    application.add_handler(ChatMemberHandler(handle_group_join, ChatMemberHandler.MY_CHAT_MEMBER))

    # Start the Bot
    print("Starting bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
