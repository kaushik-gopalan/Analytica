import streamlit as st
from openai import OpenAI
import time
import os
import glob
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import json

# Initialize OpenAI client
client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])

# Google OAuth Configuration
GOOGLE_CLIENT_CONFIG = json.loads(st.secrets["GOOGLE_CLIENT_CONFIG"])
REDIRECT_URI = 'http://localhost:8501'  # Replace with your actual Streamlit app URL
GOOGLE_CLIENT_CONFIG['web']['redirect_uris'] = [REDIRECT_URI]

# Whitelist of allowed Gmail accounts
ALLOWED_EMAILS = [
    "kaushik.gopalan@flame.edu.in",
    "krutarth@flame.edu.in",
    # Add more allowed email addresses here
]

# Function to create OAuth flow
def create_flow():
    flow = Flow.from_client_config(
        GOOGLE_CLIENT_CONFIG,
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    )
    flow.redirect_uri = REDIRECT_URI
    return flow

# Function to get user info
def get_user_info(credentials):
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    return user_info

# Function to create or get assistant
def create_assistant(file_ids):
    assistant = client.beta.assistants.create(
        name="Analytica: Data Assistant",
        instructions="You are a custom Data Analysis assistant designed to perform data analysis tasks on uploaded xlsx files. Base all responses strictly on the data from these files, providing concise and direct answers without showing code or giving explanations. Do not generate any data that isn't explicitly found in the files. Make the Python queries robust: Handle variations in user terminology like Math/Maths, US/USA, Delhi/New Delhi, Mumbai/Bombay etc.",
        model="gpt-4o",
        tools=[{"type": "code_interpreter"}],
        tool_resources={
            "code_interpreter": {
                "file_ids": file_ids
            }
        }
    )
    return assistant

# Function to upload file to OpenAI
def upload_file(file_path):
    with open(file_path, "rb") as file:
        return client.files.create(file=file, purpose='assistants')

# Function to process user question
def process_question(assistant_id, thread_id, user_question):
    client.beta.threads.messages.create(
        thread_id=thread_id,
        role="user",
        content=user_question
    )
    
    run = client.beta.threads.runs.create(
        thread_id=thread_id,
        assistant_id=assistant_id
    )
    
    while run.status not in ["completed", "failed"]:
        time.sleep(1)
        run = client.beta.threads.runs.retrieve(thread_id=thread_id, run_id=run.id)
    
    if run.status == "failed":
        return "An error occurred while processing your question."
    
    messages = client.beta.threads.messages.list(thread_id=thread_id)
    return messages.data[0].content[0].text.value


# Streamlit app
st.title("Analytica: Data Assistant")

# Check for OAuth callback
if 'code' in st.query_params:
    try:
        flow = create_flow()
        flow.fetch_token(code=st.query_params['code'])
        credentials = flow.credentials
        st.session_state.credentials = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        st.success("Successfully logged in!")
        st.query_params.clear()
        st.session_state.just_logged_in = True
    except Exception as e:
        st.error(f"An error occurred during login: {str(e)}")
        if hasattr(e, 'error_details'):
            st.error(f"Error details: {e.error_details}")
elif st.session_state.get('just_logged_in'):
    # Clear the flag and show a welcome message
    del st.session_state.just_logged_in
    st.success("Welcome! You're now logged in.")
    
# Check if user is logged in
if 'credentials' not in st.session_state:
    flow = create_flow()
    authorization_url, _ = flow.authorization_url(prompt='consent')
    
    st.write("Please log in to use the application.")
    st.markdown(f"[Login with Google]({authorization_url})")
else:
    credentials = Credentials(**st.session_state.credentials)
    user_info = get_user_info(credentials)
    
    if user_info['email'] in ALLOWED_EMAILS:
        st.write(f"Welcome, {user_info['name']}!")
        
        # Directory containing XLSX files
        excel_directory = "."

        # Upload files and create a new thread for each session
        if 'assistant' not in st.session_state:
            # Find all XLSX files in the directory
            xlsx_files = glob.glob(os.path.join(excel_directory, "*.xlsx"))
            
            if xlsx_files:
                uploaded_file_ids = []
                for file_path in xlsx_files:
                    uploaded_file = upload_file(file_path)
                    uploaded_file_ids.append(uploaded_file.id)
                    st.write(f"Uploaded: {os.path.basename(file_path)}")
                
                # Create the assistant with the file IDs
                st.session_state.assistant = create_assistant(uploaded_file_ids)
                
                # Create a new thread
                thread = client.beta.threads.create()
                st.session_state.thread_id = thread.id
                
                st.success("Excel files uploaded and attached to the assistant successfully!")
            else:
                st.error("No XLSX files found in the specified directory.")

        # User input for questions
        user_question = st.text_input("Ask a question about the data:")

        if user_question:
            with st.spinner("Processing your question..."):
                response = process_question(st.session_state.assistant.id, st.session_state.thread_id, user_question)
            
            st.write("Assistant's response:")
            st.write(response)

        # Logout button
        if st.button("Logout"):
            del st.session_state.credentials
            st.rerun()
    else:
        st.error("You are not authorized to use this application.")
        if st.button("Logout"):
            del st.session_state.credentials
            st.rerun()