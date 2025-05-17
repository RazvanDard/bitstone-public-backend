import os
import io
import base64
import traceback
import json
import re
import zipfile
import tempfile
import uuid
import gc
import jwt
import hashlib
import concurrent.futures
from dotenv import load_dotenv
from flask import Flask, request, jsonify, Response, make_response
from flask_cors import CORS
from PIL import Image
import google.generativeai as genai
import boto3
from pymongo import MongoClient
from datetime import datetime, timedelta
from bson import ObjectId

# Load environment variables
load_dotenv()

# --- Helper Function for GPS Conversion ---
def _convert_gps_to_decimal(gps_coords, gps_ref):
    """
    Converts GPS coordinates from EXIF (DMS - Degrees, Minutes, Seconds) format to decimal degrees.

    Args:
        gps_coords (tuple): A tuple of three rational numbers (degree, minute, second).
                            Each rational number is itself a tuple (numerator, denominator).
        gps_ref (str): The reference direction ('N', 'S', 'E', 'W').

    Returns:
        float: The coordinate in decimal degrees, or None if conversion fails.
               Returns negative for 'S' latitude and 'W' longitude.
    """
    try:
        # Convert IFDRational objects (or potentially already floats) directly
        degrees = float(gps_coords[0])
        minutes = float(gps_coords[1])
        seconds = float(gps_coords[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if gps_ref in ['S', 'W']:
            decimal = -decimal
        return decimal
    except (IndexError, TypeError, ZeroDivisionError, ValueError) as e:
        app.logger.error(f"Failed to convert GPS coordinates: {e}. Coords: {gps_coords}, Ref: {gps_ref}")
        return None
# --- End Helper Function ---

# Configure Google Generative AI
api_key = os.getenv("GOOGLE_API_KEY")
print(f"API Key available: {'Yes' if api_key else 'No'}")
genai.configure(api_key=api_key)

debug = False
# AWS S3 setup
s3 = boto3.client(
    "s3",
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

# Flask app setup
app = Flask(__name__)
# Configure CORS to cache preflight responses, allow required methods, and limit headers
CORS(app,
     resources={r"/api/*": {"origins": "*"}},
     supports_credentials=True,
     methods=["GET", "POST", "PATCH", "HEAD", "OPTIONS", "DELETE"],
     allow_headers=["Content-Type", "Authorization"],
     expose_headers=["Content-Length", "Access-Control-Allow-Origin"],
     max_age=86400  # Cache preflight for 24 hours
)

# MongoDB setup using configuration and 'urban-issues' collection
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
mongo = MongoClient(app.config['MONGO_URI'])
database = mongo.get_database("delusion-client")
issues_col = database.get_collection("urban-issues")

# SECRET_KEY is essential for JWT
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-default-super-secret-key-for-dev-only')

# Accounts collection (user changed to bitstone-accounts)
if 'database' in locals():
    accounts = database.get_collection("bitstone-accounts")
else:
    # Fallback if 'database' is not found - indicates a structural issue with app setup
    # This requires user to ensure 'database' is correctly initialized before this point.
    app.logger.error("CRITICAL: 'database' object not found for MongoDB. Auth routes will likely fail.")
    # Attempting a temporary connection to allow app to load, but this is not a fix.
    mongo_client_temp = MongoClient(os.getenv('MONGO_URI'))
    db_temp = mongo_client_temp.get_database("delusion-client") # Defaulting, user should check DB name
    accounts = db_temp.get_collection("bitstone-accounts")
    app.logger.warning("Auth: 'accounts' collection was initialized with a fallback. Review MongoDB setup.")

# Dummy Limiter if Flask-Limiter is not set up
if 'limiter' not in locals():
    app.logger.info("Auth: 'limiter' not found. Creating a dummy limiter. Install/configure Flask-Limiter for rate limiting.")
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

# --- Placeholder/Stub functions REQUIRED by user's snippets ---

def generate_token(user_identifier): # Renamed to user_identifier for clarity (can be email or username)
    payload = {
        "user_id": user_identifier, # This will store email if email is passed
        "exp": datetime.now() + timedelta(hours=2),
        "iat": datetime.now().timestamp(),
        "jti": str(uuid.uuid4()),
        "nbf": datetime.now().timestamp()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

def get_user_by_token(token):
    if not token:
        return None
    try:
        if token.startswith("Bearer "):
            token = token.split("Bearer ", 1)[1]
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_identifier = decoded_token.get("user_id") # This is the email
        return accounts.find_one({"email": user_identifier}) # Query by email
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        app.logger.warning(f"JWT Error: {str(e)}")
        return None

@app.route('/api/register', methods=['POST', 'OPTIONS'])
# @limiter.limit("3 per day") # User had this, but needs Flask-Limiter setup
def register():
    if request.method == 'OPTIONS':
        return make_response(jsonify({"message": "OPTIONS request handled"}), 200)

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        email = str(data.get('email', '')).strip().lower() # Standardize to lower
        password = str(data.get('password', ''))

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        # Basic email validation (can be improved with regex)
        if "@" not in email or "." not in email:
            return jsonify({"error": "Invalid email format"}), 400

        # IMPORTANT: User removed verify_turnstile, generate_verification_token, etc.
        # These are critical for security and UX (e.g. preventing spam, email verification)
        # For now, proceeding with the minimal structure the user seems to have left.

        if accounts.find_one({"email": email}):
            return jsonify({"error": "Email already exists"}), 400
        
        # SECURITY WARNING: Storing plain passwords or client-side hashes is highly insecure.
        # Implement server-side hashing with Werkzeug or passlib.
        user_doc = {
            "email": email,
            "admin": False,
            "password": password, # Storing password as is, per user's current code structure.
            "created_at": datetime.now() # Added a creation timestamp
        }
        # All other fields from original user snippets (username, referral, etc.) were removed by user.

        accounts.insert_one(user_doc)
        # Generate token using email as the identifier
        token = generate_token(email)
        
        app.logger.info(f"User registered successfully: {email}")
        return jsonify({
            "message": "User registered successfully",
            "token": token
        }), 201

    except Exception as e:
        app.logger.error(f"Registration error: {str(e)} - Traceback: {traceback.format_exc()}")
        return jsonify({"error": "Registration failed due to an server error. Please try again later."}), 500

@app.route('/api/login', methods=['POST', 'OPTIONS'])
# @limiter.limit("10 per minute") # User had this, but needs Flask-Limiter setup
def login():
    if request.method == 'OPTIONS':
        return make_response(jsonify({"message": "OPTIONS request handled"}), 200)
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = str(data.get('email', '')).strip().lower()
        password = str(data.get('password', ''))

        if not email or not password:
             return jsonify({"code": 1, "error": "Email and password required"}), 400

        # IMPORTANT: User removed verify_turnstile call

        user = accounts.find_one({"email": email, "password": password})
        if user:
            # IMPORTANT: User removed banned check
            # Generate token using email as the identifier
            token = generate_token(user["email"]) 
                
            app.logger.info(f"User '{email}' logged in successfully.")
            return jsonify({"code": 0, "token": token})
        
        app.logger.warning(f"Invalid login credentials for email: {email}")

        return jsonify({"code": 1, "error": "Invalid credentials"}), 401
    except Exception as e:
        app.logger.error(f"Login error: {str(e)} - Traceback: {traceback.format_exc()}")
        return jsonify({"error": "Login failed due to a server error. Please try again later."}), 500

# --- User's Authentication Code Integration ENDS HERE ---

def upload_to_s3(img_bytes, key):
    s3.put_object(
        Bucket=os.getenv("S3_BUCKET_NAME"),
        Key=key,
        Body=img_bytes,
        ContentType="image/jpeg"
    )
    return f"https://{os.getenv('S3_BUCKET_NAME')}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/{key}"

# Define urban issues to detect
URBAN_ISSUES = [
    "potholes", 
    "graffiti", 
    "overflowing_trash_bins", 
    "illegally_parked_cars",
    "broken_sidewalks",
    "damaged_street_signs",
    "poor_lighting",
    "abandoned_vehicles",
    "dirty_streets",
    "broken_urban_furniture",
    "incorrect_signage",
    "broken_playground_equipment",
    "street_flooding",
    "cars_occupying_multiple_spots",
    "sidewalk_occupied_by_construction",
    "dead_animals",
    "dead_trees",
    "dangerous_animals_or_outside_habitat",
    "peeling_paint_off_buildings_or_damaged_facades",
    "too_many_birds_on_electric_lines"
]

# Common function to analyze a single image
def analyze_single_image(img_bytes, filename="unknown"):
    extracted_location_data = None # Initialize variable to store EXIF location
    try:
        print(f"Processing image: {filename}")
        
        # Read and process the image
        img = Image.open(io.BytesIO(img_bytes))
        print(f"Image opened successfully: {img.format}, {img.size}, {img.mode}")
        
        # --- EXIF GPS Extraction ---
        try:
            exif_data = img._getexif()
            if exif_data:
                # GPSInfo tag ID is 34853
                gps_info = exif_data.get(34853)
                if gps_info:
                    # Standard GPS Tags:
                    # 1: LatitudeRef (N/S)
                    # 2: Latitude (DMS)
                    # 3: LongitudeRef (E/W)
                    # 4: Longitude (DMS)
                    gps_latitude_ref = gps_info.get(1)
                    gps_latitude = gps_info.get(2)
                    gps_longitude_ref = gps_info.get(3)
                    gps_longitude = gps_info.get(4)

                    if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
                        lat_decimal = _convert_gps_to_decimal(gps_latitude, gps_latitude_ref)
                        lon_decimal = _convert_gps_to_decimal(gps_longitude, gps_longitude_ref)

                        if lat_decimal is not None and lon_decimal is not None:
                            extracted_location_data = {"lat": lat_decimal, "lng": lon_decimal, "source": "exif"}
                            app.logger.info(f"Extracted EXIF GPS for {filename}: {extracted_location_data}")
                        else:
                            app.logger.warning(f"Could not convert EXIF GPS data for {filename}.")
                    else:
                        app.logger.info(f"Partial EXIF GPS data found for {filename}, but not enough to form coordinates.")
                else:
                    app.logger.info(f"No GPSInfo tag in EXIF data for {filename}.")
            else:
                app.logger.info(f"No EXIF data found for {filename}.")
        except Exception as exif_error:
            app.logger.error(f"Error reading EXIF data for {filename}: {exif_error}")
        # --- End EXIF GPS Extraction ---
        
        # Convert image to RGB if it's in RGBA mode (e.g., PNG screenshots with transparency)
        if img.mode == 'RGBA':
            print("Converting RGBA image to RGB")
            img = img.convert('RGB')
        
        # Analysis with Gemini 2.0 Flash
        generation_config = genai.types.GenerationConfig(temperature=0.5)
        model = genai.GenerativeModel(
            'gemini-2.0-flash',
            generation_config=generation_config
        )

        
        # Convert image to MIME-compatible format for Gemini
        buffered = io.BytesIO()
        img.save(buffered, format="JPEG")
        img_b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
        mime_type = "image/jpeg"
        print("Image converted to base64 successfully")
        
        # Prepare the prompt for Gemini to return structured JSON
        prompt = """
        Analyze this urban image and identify if any of the following issues are present:
        - Potholes
        - Unauthorized graffiti
        - Overflowing trash bins
        - Illegally parked cars (cars parked on the road / on the sidewalk / where there is no parking sign)
        - Broken sidewalks
        - Damaged street signs
        - Poor lighting
        - Abandoned vehicles
        - Dirty streets (litter, debris, spills)
        - Broken urban furniture (benches, bus stops, fountains)
        - Incorrect signage (wrong directions, misleading information, damaged/illegible signs)
        - Broken playground equipment (damaged swings, slides, or other play structures)
        - Street flooding (excessive water on street surfaces, indicating potential sewage or drainage problems)
        - Cars occupying multiple parking spots (a single vehicle taking up more than one designated parking space)
        - Dead animals (dead dogs, cats, birds, etc.)
        - Sidewalk occupied by construction (construction materials, workers, etc.)
        - Dead trees
        - Dangerous animals or outside habitat (wildlife, predators, etc.)
        - Peeling paint off buildings or damaged facades
        - Too many birds on electric lines

        If something looks suspicious, like a animal lying in a weird position, err on the side of caution and detect it as a dead animal. 
        If furniture doesn't look fully intact, so like a swing is not sitting vertically on the pole or a bench is on the ground or a bench is missing a part, err on the side of caution and detect it as a broken urban furniture.

        Also identify any well-maintained elements like clean streets, intact urban furniture, or correct signage.
        
        For each detected issue, please provide:
        1. A brief description of the problem
        2. A practical solution or recommendation to fix the issue

        IMPORTANT GUIDELINES:
        - Base your analysis STRICTLY on visible elements in the image. Avoid speculative or hallucinatory statements.
        - If you are not confident about an issue, err on the side of not detecting it.
        
        IMPORTANT NOTES ON ILLEGALLY PARKED CARS:
        - Identify cars as illegally parked if there is evidence they are on a sidewalk, on the road, or where there is no parking sign
        - You should flag as illegaly parked even if there is only one or two cars out of the whole image
        
        - Look for parking markings on the ground, parking signs, or designated parking areas
        - Cars should be considered legally parked if they are in marked parking spots or areas clearly designated for parking
        - Cars parked on sidewalks, blocking driveways, crosswalks, bike lanes, or in no-parking zones should be identified as illegally parked
        - Do not mark cars as illegally parked unless you can confidently determine they are not in a designated parking area
        - Cars parked on the street should only be considered illegal if there are visible no-parking signs or markings
        
        Return your response in this exact JSON format:
        ```json
        {
          "issues": {
            "potholes": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "graffiti": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "overflowing_trash_bins": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "illegally_parked_cars": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "broken_sidewalks": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "damaged_street_signs": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "poor_lighting": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "abandoned_vehicles": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "dirty_streets": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "broken_urban_furniture": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "incorrect_signage": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "broken_playground_equipment": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "street_flooding": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "cars_occupying_multiple_spots": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "sidewalk_occupied_by_construction": {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            }
            "dead_animals" : 
            {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            },
            "dead_trees" : 
            {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            }
            "dangerous_animals_or_outside_habitat" : 
            {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            }
            "peeling_paint_off_buildings_or_damaged_facades" : 
            {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            }
            "too_many_birds_on_electric_lines" : 
            {
              "detected": "Yes/No",
              "description": "Brief description if detected",
              "solution": "Recommended solution if detected"
            }


          },
          "well_maintained_elements": {
            "bike_lanes": "Yes/No and provide brief explanation",
            "bus_lanes": "Yes/No and provide brief explanation",
            "green_spaces": "Yes/No and provide brief explanation",
            "clean_streets": "Yes/No and provide brief explanation",
            "intact_urban_furniture": "Yes/No and provide brief explanation",
            "correct_signage": "Yes/No and provide brief explanation",
            "other_positive ( use name here )": "Yes/No and provide brief explanation"
          },
          "analysis": "Overall analysis of the urban area in the image. Highlight the positives aspects as well. If the image is not relevant urban thing so it's like a random image just say that it's not relevant."
        }
        ```
        
        Be very precise about the JSON format. Start with "Yes" only if you are certain the issue exists; otherwise, respond with "No".
        For detected issues, always provide both a description and a practical solution. Use proper capitalization and punctuation.
        """
        
        # Call Gemini API with the image
        print("Calling Gemini API...")
        response = model.generate_content([prompt, {"mime_type": mime_type, "data": img_b64}])
        analysis_text = response.text
        print("Gemini API response received successfully")
        
        # Explicitly delete large image-related objects now that they are no longer needed
        try:
            del img_b64
            del buffered
            del img
            gc.collect() # Suggest garbage collection
            print("Cleaned up in-memory image objects after LLM call")
        except NameError:
            # Should not happen if objects were defined, but good practice for del
            pass
        
        # Extract JSON from the response text
        json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', analysis_text)
        if json_match:
            json_str = json_match.group(1)
            analysis_json = json.loads(json_str)
            print("Successfully parsed JSON response")
        else:
            print("Could not extract JSON, using full text response")
            analysis_json = {"issues": {}, "well_maintained_elements": {}, "analysis": analysis_text}
        
        # Process the response to extract structured data
        results = {
            "urban_issues": {},
            "additional_details": ""
        }
        
        # Set default values for all issues
        for issue in URBAN_ISSUES:
            results["urban_issues"][issue] = {
                "detected": False,
                "description": "",
                "solution": ""
            }
        
        # Map issues from the JSON response
        if "issues" in analysis_json:
            for issue_key in URBAN_ISSUES:
                # Try various forms of the key that might be in the JSON
                possible_keys = [
                    issue_key,  # e.g., "potholes"
                    issue_key.replace('_', ' '),  # e.g., "overflowing trash bins"
                    issue_key.title(),  # e.g., "Potholes"
                    issue_key.replace('_', ' ').title(),  # e.g., "Overflowing Trash Bins"
                    issue_key.replace('_', '-'), # e.g., "dirty-streets"
                    issue_key.replace('_', '-').title() # e.g., "Dirty-Streets"
                ]
                
                for key in possible_keys:
                    if key in analysis_json["issues"]:
                        issue_data = analysis_json["issues"][key]
                        
                        # Check if the response is in the new format or old format
                        if isinstance(issue_data, dict) and "detected" in issue_data:
                            # New format
                            results["urban_issues"][issue_key] = {
                                "detected": issue_data["detected"].lower().startswith("yes"),
                                "description": issue_data.get("description", ""),
                                "solution": issue_data.get("solution", "")
                            }
                        else:
                            # Old format or unexpected format - try to handle gracefully
                            detected = False
                            if isinstance(issue_data, str):
                                detected = issue_data.lower().startswith("yes")
                            elif isinstance(issue_data, dict) and "detected" in issue_data:
                                detected = issue_data["detected"].lower().startswith("yes")
                            
                            results["urban_issues"][issue_key] = {
                                "detected": detected,
                                "description": issue_data.get("description", str(issue_data) if isinstance(issue_data, str) else ""),
                                "solution": issue_data.get("solution", "")
                            }
                        break
        
        # Add well_maintained_elements to results
        results["well_maintained_elements"] = {}
        if "well_maintained_elements" in analysis_json:
            for element_key, element_value in analysis_json["well_maintained_elements"].items():
                results["well_maintained_elements"][element_key] = element_value

        # Add the full analysis as additional details
        if "analysis" in analysis_json:
            results["additional_details"] = analysis_json["analysis"]
        else:
            results["additional_details"] = analysis_text
        
        print("Analysis results processed successfully")
        return {
            "success": True,
            "filename": filename,
            "results": results,
            "extracted_location_data": extracted_location_data # Return extracted location
        }
        
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"Error processing image {filename}: {str(e)}")
        print(f"Traceback: {error_traceback}")
        return {
            "success": False,
            "filename": filename,
            "error": str(e),
            "extracted_location_data": None # Ensure this key is present on error too
        }

@app.route('/api/analyze', methods=['POST'])
def analyze_image():
    try:
        # Check if image was uploaded
        if 'image' not in request.files:
            return jsonify({'error': 'No image uploaded'}), 400
        
        image_file = request.files['image']
        if image_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        # Parse optional location fields
        location_data = None
        if 'lat' in request.form and 'lng' in request.form:
            try:
                lat = float(request.form['lat'])
                lng = float(request.form['lng'])
                location_data = {'lat': lat, 'lng': lng}
            except ValueError:
                pass  # invalid coordinates, ignore
        elif 'address' in request.form or 'street_name' in request.form:
            addr = request.form.get('address') or request.form.get('street_name')
            if addr:
                location_data = {'address': addr}
        
        # Process the image
        img_bytes = image_file.read()
        # Upload image to S3
        s3_key = f"images/{uuid.uuid4()}.jpg"
        image_url = upload_to_s3(img_bytes, s3_key)
        analysis_result = analyze_single_image(img_bytes, image_file.filename)
        
        final_location_data = location_data # Prioritize request location data
        if analysis_result.get("extracted_location_data") and not final_location_data:
            final_location_data = analysis_result["extracted_location_data"]
            app.logger.info(f"Using EXIF location for {image_file.filename} as no request location was provided.")

        if analysis_result["success"]:
            results = analysis_result["results"]
            # Update: Use final_location_data which might be from EXIF
            if final_location_data:
                results['location'] = final_location_data # Add to results if not already part of it from previous structure
            
            # Persist analysis to MongoDB
            doc = {
                "filename": image_file.filename,
                "s3_key": s3_key,
                "image_url": image_url,
                "analysis": results, # Results now might contain location from EXIF via final_location_data
                "location": final_location_data, # Store the definitive location
                "created_at": datetime.utcnow()
            }
            inserted = issues_col.insert_one(doc)
            # Build JSON response only with serializable fields
            response_body = {
                "id": str(inserted.inserted_id),
                "filename": doc["filename"],
                "s3_key": doc["s3_key"],
                "image_url": doc["image_url"],
                "analysis": doc["analysis"],
                "location": doc.get("location")
            }
            return jsonify(response_body), 200
        else:
            return jsonify({'error': analysis_result["error"]}), 500
    
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"Unhandled error: {str(e)}")
        print(f"Traceback: {error_traceback}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET', 'HEAD'])
def health_check():
    """Simple health check endpoint to verify the API is running"""
    return jsonify({"status": "ok", "service": "urban-issue-detection-api"}), 200

@app.route('/api/analyze/batch', methods=['POST', 'HEAD', 'GET'])
def analyze_batch():
    # For HEAD/GET requests, just return OK status (useful for health checks)
    if request.method == 'HEAD' or request.method == 'GET':
        return jsonify({"status": "endpoint available", "endpoint": "batch-analysis"}), 200
        
    try:
        # Check if a ZIP file was uploaded
        if 'zip_file' not in request.files:
            return jsonify({'error': 'No ZIP file uploaded'}), 400
        
        zip_file = request.files['zip_file']
        # Parse optional location fields for batch
        location_data = None
        if 'lat' in request.form and 'lng' in request.form:
            try:
                lat = float(request.form['lat'])
                lng = float(request.form['lng'])
                location_data = {'lat': lat, 'lng': lng}
            except ValueError:
                pass
        elif 'address' in request.form or 'street_name' in request.form:
            addr = request.form.get('address') or request.form.get('street_name')
            if addr:
                location_data = {'address': addr}
        
        if zip_file.filename == '' or not zip_file.filename.lower().endswith('.zip'):
            return jsonify({'error': 'Invalid ZIP file'}), 400
        
        print(f"Processing ZIP file: {zip_file.filename}")
        
        # Create a temporary directory to extract files
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_bytes = zip_file.read()
            zip_path = os.path.join(temp_dir, "uploaded.zip")
            
            # Save the uploaded ZIP file
            with open(zip_path, 'wb') as f:
                f.write(zip_bytes)
            
            # Collect image processing tasks
            processing_tasks = []
            valid_extensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp']
            
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # List all files in the ZIP
                    file_list = zip_ref.namelist()
                    print(f"Found {len(file_list)} files in ZIP")
                    
                    # Extract files that are images
                    image_files = []
                    
                    for file_name in file_list:
                        # Check if the file has a valid image extension
                        if any(file_name.lower().endswith(ext) for ext in valid_extensions):
                            try:
                                # Extract the image data
                                with zip_ref.open(file_name) as file:
                                    img_bytes = file.read()
                                    
                                # Store the image data and filename for processing
                                image_files.append({
                                    "file_name": file_name,
                                    "img_bytes": img_bytes
                                })
                                
                            except Exception as extract_error:
                                print(f"Error extracting {file_name}: {str(extract_error)}")
                                processing_tasks.append({
                                    "success": False,
                                    "filename": file_name,
                                    "error": f"Error extracting file: {str(extract_error)}"
                                })
                    
                    print(f"Found {len(image_files)} valid image files to process")
            except zipfile.BadZipFile as zip_error:
                error_msg = f"Invalid ZIP file: {str(zip_error)}"
                print(error_msg)
                return jsonify({'error': error_msg}), 400
                
            # Process images in parallel
            batch_results = []
            
            # Function to process a single image that can be run in a thread
            def process_image(image_data, request_location_data): # Pass request location
                try:
                    # Upload image to S3
                    img_bytes = image_data["img_bytes"]
                    filename = image_data["file_name"]
                    s3_key = f"images/{uuid.uuid4()}_{filename}"
                    image_url = upload_to_s3(img_bytes, s3_key)
                    # Perform analysis
                    result = analyze_single_image(img_bytes, filename)
                    
                    final_location_data = request_location_data # Prioritize request location
                    if result.get("extracted_location_data") and not final_location_data:
                         final_location_data = result["extracted_location_data"]
                         app.logger.info(f"Using EXIF location for batch image {filename}.")

                    if result["success"]:
                        analysis = result["results"]
                        # Update: Use final_location_data
                        if final_location_data:
                             analysis['location'] = final_location_data
                        # Persist to MongoDB
                        doc = {
                            "filename": filename,
                            "s3_key": s3_key,
                            "image_url": image_url,
                            "analysis": analysis,
                            "location": final_location_data, # Store definitive location
                            "created_at": datetime.utcnow()
                        }
                        inserted = issues_col.insert_one(doc)
                        return {
                            "success": True,
                            "id": str(inserted.inserted_id),
                            "filename": filename,
                            "s3_key": s3_key,
                            "image_url": image_url,
                            "analysis": analysis,
                            "location": final_location_data # Return definitive location
                        }
                    else:
                        return {"success": False, "filename": filename, "error": result.get("error", "Analysis failed")}
                except Exception as proc_error:
                    error_traceback = traceback.format_exc()
                    print(f"Error processing {image_data['file_name']}: {str(proc_error)}")
                    print(f"Traceback: {error_traceback}")
                    return {
                        "success": False,
                        "filename": image_data["file_name"],
                        "error": str(proc_error)
                    }
            
            # Use ThreadPoolExecutor to process images in parallel
            max_workers = min(50, len(image_files))  # Limit to 8 workers max to avoid overloading API
            if max_workers > 0:
                print(f"Processing {len(image_files)} images with {max_workers} workers")
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                        # Submit all image processing tasks
                        future_to_image = {
                            executor.submit(process_image, image_data, location_data): image_data["file_name"] # Pass location_data
                            for image_data in image_files
                        }
                        
                        # Collect results as they complete
                        for future in concurrent.futures.as_completed(future_to_image):
                            filename = future_to_image[future]
                            try:
                                result = future.result()
                                batch_results.append(result)
                                print(f"Completed processing {filename}")
                            except Exception as exc:
                                error_traceback = traceback.format_exc()
                                print(f"Image processing generated an exception: {exc}")
                                print(f"Traceback: {error_traceback}")
                                batch_results.append({
                                    "success": False,
                                    "filename": filename,
                                    "error": f"Processing error: {str(exc)}"
                                })
                except Exception as executor_error:
                    error_traceback = traceback.format_exc()
                    print(f"Error in thread executor: {str(executor_error)}")
                    print(f"Traceback: {error_traceback}")
                    return jsonify({'error': f"Error processing batch: {str(executor_error)}"}), 500
            
            # Add any extraction errors to the results
            batch_results.extend(processing_tasks)
        
        # Prepare the response
        succeeded = [r for r in batch_results if r["success"]]
        failed = [r for r in batch_results if not r["success"]]
        
        response = {
            "total": len(batch_results),
            "succeeded": len(succeeded),
            "failed": len(failed),
            "results": batch_results
        }
        
        return jsonify(response)
    
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"Unhandled error in batch processing: {str(e)}")
        print(f"Traceback: {error_traceback}")
        return jsonify({'error': str(e)}), 500

# Endpoints to fetch persisted issues
@app.route('/api/issues', methods=['GET'])
def get_issues():
    try:
        issues = list(issues_col.find({}))
        for issue in issues:
            issue['_id'] = str(issue['_id'])
            # Serve image via backend proxy
            issue['image_url'] = f"{request.host_url}api/images/{issue.get('s3_key')}"
        return jsonify(issues), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/issues/<issue_id>', methods=['GET'])
def get_issue(issue_id):
    try:
        from bson import ObjectId
        issue = issues_col.find_one({"_id": ObjectId(issue_id)})
        if not issue:
            return jsonify({'error': 'Not found'}), 404
        issue['_id'] = str(issue['_id'])
        # Serve image via backend proxy
        issue['image_url'] = f"{request.host_url}api/images/{issue.get('s3_key')}"
        return jsonify(issue), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/issues/<issue_id>', methods=['PATCH'])
def update_issue(issue_id):
    # 2. Proceed with existing update logic if admin check passes
    from bson import ObjectId
    print("Updating issue")
    try:
        data = request.get_json() or {}
        fields = {}
        if 'solved' in data:
            fields['solved'] = bool(data['solved'])
            print(f"Updating issue {issue_id} solved status to {fields['solved']}")
        if 'location' in data:
            fields['location'] = data['location']
            print(f"Updating issue {issue_id} location to {fields['location']}")
        if fields:
            result = issues_col.update_one({'_id': ObjectId(issue_id)}, {'$set': fields})
            print(f"MongoDB update result: matched={result.matched_count}, modified={result.modified_count}")
            issue = issues_col.find_one({'_id': ObjectId(issue_id)})
            if not issue:
                return jsonify({'error': 'Not found'}), 404
            issue['_id'] = str(issue['_id'])
            issue['image_url'] = f"{request.host_url}api/images/{issue.get('s3_key')}"
            return jsonify(issue), 200
        else:
            return jsonify({'error': 'No fields to update'}), 400
    except Exception as e:
        app.logger.error(f"Error updating issue {issue_id} by admin: {e} - Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

# Proxy images from S3 through the backend for CORS reliability
@app.route('/api/images/<path:key>', methods=['GET'])
def get_image(key):
    try:
        obj = s3.get_object(Bucket=os.getenv("S3_BUCKET_NAME"), Key=key)
        return Response(obj['Body'].read(), mimetype=obj.get('ContentType', 'image/jpeg'))
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/api/check_admin', methods=['GET'])
def check_admin_status():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Authorization header missing", "is_admin": False}), 401

    token_parts = auth_header.split()
    if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
        return jsonify({"error": "Invalid token format. Expected 'Bearer <token>'", "is_admin": False}), 401

    token = token_parts[1]
    current_user = get_user_by_token(token)

    if not current_user:
        return jsonify({"error": "Invalid or expired token", "is_admin": False}), 401

    # Check if the 'admin' field is explicitly True
    is_admin = current_user.get("admin") is True
    
    # if is_admin:
    #     app.logger.info(f"Admin status check for user '{current_user.get('email')}': IS ADMIN")
    # else:
    #     app.logger.info(f"Admin status check for user '{current_user.get('email')}': IS NOT ADMIN (admin field value: {current_user.get('admin')})")

    return jsonify({"is_admin": is_admin}), 200

@app.route('/api/issues/<issue_id>', methods=['DELETE'])
# @limiter.limit("...") # Add rate limiting if desired
def delete_issue(issue_id):
    # 1. Token Verification and Admin Check
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        app.logger.warning(f"Delete attempt on issue {issue_id} without Authorization header.")
        return jsonify({"error": "Authorization header missing"}), 401

    token_parts = auth_header.split()
    if len(token_parts) != 2 or token_parts[0].lower() != 'bearer':
        app.logger.warning(f"Delete attempt on issue {issue_id} with malformed Authorization header: {auth_header}")
        return jsonify({"error": "Invalid token format. Expected 'Bearer <token>'"}), 401

    token = token_parts[1]
    current_user = get_user_by_token(token)

    if not current_user:
        app.logger.warning(f"Delete attempt on issue {issue_id} with invalid/expired token.")
        return jsonify({"error": "Invalid or expired token"}), 401

    # Using safer admin check as discussed
    if current_user.get("admin") is not True: 
        app.logger.warning(f"User '{current_user.get('email')}': IS NOT ADMIN (admin field value: {current_user.get('admin')})")
        return jsonify({"error": "Admin privileges required to delete issues"}), 403
    
    admin_email = current_user.get("email") # Get admin email for logging
    app.logger.info(f"Admin user '{admin_email}' attempting to delete issue {issue_id}.")

    # 2. Validate Issue ID
    try:
        oid = ObjectId(issue_id)
    except Exception: 
        return jsonify({'error': 'Invalid issue ID format'}), 400

    # 3. Fetch Issue, Attempt S3 Deletion, then Delete from DB
    try:
        # Fetch the document first to get the s3_key
        issue_doc = issues_col.find_one({'_id': oid})
        
        if not issue_doc:
            app.logger.warning(f"Delete attempt failed for issue {issue_id} by admin '{admin_email}'. Issue not found.")
            return jsonify({'error': 'Issue not found'}), 404

        s3_key = issue_doc.get('s3_key')
        bucket_name = os.getenv("S3_BUCKET_NAME")

        # Attempt to delete from S3 if key and bucket name are present
        if s3_key and bucket_name:
            try:
                app.logger.info(f"Attempting to delete S3 object: Bucket={bucket_name}, Key={s3_key} for issue {issue_id}")
                s3.delete_object(Bucket=bucket_name, Key=s3_key)
                app.logger.info(f"S3 object {s3_key} deleted successfully (or did not exist). Issue {issue_id}")
            except Exception as s3_error:
                # Log the S3 error but proceed with DB deletion
                app.logger.error(f"Failed to delete S3 object {s3_key} from bucket {bucket_name} for issue {issue_id}: {s3_error} - Traceback: {traceback.format_exc()}")
                # Optionally, you could flag the issue for manual S3 cleanup if needed
        elif not bucket_name:
             app.logger.warning(f"S3_BUCKET_NAME environment variable not set. Cannot delete S3 object for issue {issue_id} (key: {s3_key}).")
        else: # s3_key is None or empty
            app.logger.warning(f"No s3_key found for issue {issue_id}. Skipping S3 deletion.")

        # Proceed to delete from MongoDB
        result = issues_col.delete_one({'_id': oid})
        
        if result.deleted_count == 1:
            app.logger.info(f"Issue {issue_id} DB record deleted successfully by admin '{admin_email}'.")
            return jsonify({"message": f"Issue {issue_id} deleted successfully"}), 200 
        else:
            # This case should ideally not be reached if find_one succeeded, but handles potential race conditions or errors
            app.logger.error(f"DB delete failed for issue {issue_id} (deleted count: {result.deleted_count}) by admin '{admin_email}' even after finding the document initially.")
            return jsonify({'error': 'Issue found but failed to delete from database'}), 500
            
    except Exception as e:
        app.logger.error(f"Error during deletion process for issue {issue_id} by admin '{admin_email}': {e} - Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'An unexpected error occurred during deletion: {str(e)}'}), 500

if __name__ == '__main__':
    # Your existing __main__ block, for example:
    if(debug):
        app.run(debug=True, host='0.0.0.0') 
    # Using the line from the user's current_file context
