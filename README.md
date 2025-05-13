# Urban Issues Detection App

An AI-powered web application that analyzes uploaded images to detect urban issues such as potholes, graffiti, and more using Gemini 2.0 Flash API.

## Features

- **Image Analysis (Single & Batch):**
  - Upload individual images or a ZIP file containing multiple images.
  - AI-powered analysis using Google Gemini 2.0 Flash to detect a comprehensive range of urban issues, including:
    - Potholes, Unauthorized graffiti, Overflowing trash bins
    - Illegally parked cars (on road, sidewalk, no parking sign areas)
    - Broken sidewalks, Damaged street signs, Poor lighting, Abandoned vehicles
    - Dirty streets (litter, debris, spills)
    - Broken urban furniture (benches, bus stops, fountains)
    - Incorrect signage (wrong directions, misleading, damaged/illegible)
    - Broken playground equipment
    - Street flooding
    - Cars occupying multiple parking spots
    - Sidewalks occupied by construction
    - Dead animals (dogs, cats, birds, etc.)
    - Dead trees
    - Dangerous animals or wildlife outside their habitat
    - Peeling paint or damaged building facades
    - Excessive birds on electric lines
  - Identification of well-maintained elements (e.g., clean streets, intact furniture, green spaces).
  - Extraction of GPS coordinates from image EXIF data, if available.
- **Data Management & Storage:**
  - Securely uploads processed images to AWS S3.
  - Stores analysis results, image metadata, and location data in MongoDB.
- **Issue Tracking & Management:**
  - View all submitted issues and their details.
  - Update issue status (e.g., mark as "solved") and location information.
  - Delete issues (admin-only functionality).
- **User Authentication:**
  - Secure user registration and login system using email and password.
  - JWT (JSON Web Tokens) for session management.
  - Endpoint to check user's admin status.
- **API & Backend:**
  - RESTful API built with Flask and Python.
  - CORS configured for frontend integration.
  - Image proxy endpoint to serve S3 images securely.
- **Frontend Integration:**
  - Designed to work with a modern React and Tailwind CSS frontend (as per project structure).

## Project Structure

```
Bitstone_AIcontest/
├── bitstone/                 # React frontend
│   ├── public/
│   ├── src/
│   ├── package.json
│   ├── tailwind.config.js
│   └── postcss.config.js
├── bitstone-backend/         # Flask backend
│   ├── app.py                  # Main Flask application
│   ├── requirements.txt        # Python dependencies
│   └── .python-version         # Python version
└── README.md
```

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
   ```
   cd bitstone-backend
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file
   ```
   # Create .env file if needed, e.g., by copying an example if one exists
   # or by creating it manually.
   # Add your Google Gemini API key to the .env file if GOOGLE_API_KEY is used:
   # GOOGLE_API_KEY=your_actual_api_key_here
   #
   # Add your AWS S3 credentials:
   # AWS_ACCESS_KEY_ID=your_aws_access_key_id
   # AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
   # S3_BUCKET_NAME=your_s3_bucket_name
   #
   # Add your MongoDB connection string:
   # MONGODB_URI=your_mongodb_connection_string
   ```
  
5. Run the Flask server:
   ```
   python app.py
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```
   cd bitstone
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the development server:
   ```
   npm start
   ```

4. Open your browser and navigate to http://localhost:3000

## Usage

1. Upload an image of an urban scene using the file input
2. Click "Analyze Image"
3. View the AI analysis results showing detected issues

## Technologies Used

- **Frontend**: React, Tailwind CSS
- **Backend**: Flask, Python
- **AI**: Google Gemini 2.0 Flash API
- **Image Processing**: Pillow (PIL)
- **Storage**: AWS S3
- **Database**: MongoDB

# Video showcase
https://streamable.com/0fv3fx?src=player-page-share


# Hosted website 
[website link](https://snaptheissue.xyz/)