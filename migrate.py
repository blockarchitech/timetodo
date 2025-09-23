"""
Script to add 'scopes' and 'preferences' fields to all user documents
in a Firestore collection.
"""

import firebase_admin
from firebase_admin import credentials, firestore

# --- Configuration ---
PROJECT_ID = 'timetodo-460603'
COLLECTION_NAME = 'users'

# --- Fields to Add ---
# The 'scopes' field with its default value
SCOPES_FIELD = 'scopes'
SCOPES_VALUE = ["data:read"]

# The 'preferences' field with its default value
PREFERENCES_FIELD = 'preferences'
PREFERENCES_VALUE = {
    "shouldPinWithNoDate": False,
    "shouldPinWithNoTime": False,
    "shouldPinWithNoTimeAt": "",
    "shouldRemindOnDueTime": False,
    "reminderTiming": ""
}

def update_collection():
    """
    Adds new fields with default values to every document in a specified
    Firestore collection. It uses Application Default Credentials from the
    gcloud CLI and a manually specified Project ID.
    """
    try:
        # 1. Initialize Firebase Admin SDK
        # The SDK automatically finds default credentials from the gcloud CLI.
        # We explicitly provide the project ID from the configuration above.
        firebase_admin.initialize_app(
            credentials.ApplicationDefault(),
            {
                'projectId': PROJECT_ID,
            }
        )
        db = firestore.client()
        print(f"✅ Successfully initialized Firebase app for project: {PROJECT_ID}")

        # 2. Get a reference to the collection
        collection_ref = db.collection(COLLECTION_NAME)
        docs = collection_ref.stream()

        # 3. Iterate over documents and update each one
        print(f"🚀 Starting update for collection '{COLLECTION_NAME}'...")
        doc_count = 0
        update_payload = {
            SCOPES_FIELD: SCOPES_VALUE,
            PREFERENCES_FIELD: PREFERENCES_VALUE
        }

        for doc in docs:
            doc.reference.update(update_payload)
            doc_count += 1
            print(f"  -> Updated document: {doc.id}")

        print(f"\n✨ Success! Updated {doc_count} documents in '{COLLECTION_NAME}'.")

    except Exception as e:
        print(f"❌ An error occurred: {e}")

if __name__ == '__main__':
    update_collection()
