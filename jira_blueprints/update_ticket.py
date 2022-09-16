import argparse
import sys
import requests
from requests.auth import HTTPBasicAuth
import shipyard_utils as shipyard
try:
    import exit_codes
except BaseException:
    from . import exit_codes


# create Artifacts folder paths
base_folder_name = shipyard.logs.determine_base_artifact_folder('jira')
artifact_subfolder_paths = shipyard.logs.determine_artifact_subfolders(
    base_folder_name)
shipyard.logs.create_artifacts_folders(artifact_subfolder_paths)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--jira-url', dest='jira_url', required=True)
    parser.add_argument('--project-key', dest='project_key', required=True)
    parser.add_argument('--username', dest='username', required=True)
    parser.add_argument('--access-token', dest='access_token', required=True)
    parser.add_argument('--ticket-key', dest='ticket_key', required=True)
    parser.add_argument('--summary', dest='summary', required=True)
    parser.add_argument('--description', dest='description', required=True)
    parser.add_argument('--issue-type', dest='issue_type', required=True)
    parser.add_argument('--additional-fields', dest='additional_fields', required=False)
    args = parser.parse_args()
    return args


def generate_payload_with_custom(project_key, summary, 
                     description, issue_type, custom_fields=None):
    """ Generates a JIRA Ticket json payload as well as adds custom fields
    to the payload if any are present.
    see: https://developer.atlassian.com/server/jira/platform
                /jira-rest-api-examples/#editing-an-issue-examples
    for an example of a basic payload.
    """
    
    payload = {
        "fields" : {
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type}
        }
    }
    if custom_fields:
        # add custom fields to the update fields payload
        payload['fields'].update()
    return payload


def update_existing_ticket(username, token, jira_url, ticket_key, payload):
    """ Triggers the Create Issue API and adds a new ticket onto JIRA"""
    
    update_ticket_endpoint = f"https://{jira_url}/rest/api/2/issue/{ticket_key}"
    headers = {
      'Content-Type': 'application/json'
    }

    response = requests.put(update_ticket_endpoint, 
                             headers=headers, 
                             json=payload, 
                             auth=HTTPBasicAuth(username, token)
                             )
    
    if response.status_code == requests.codes.ok:
        print(f"Ticket {ticket_key} created updated")
        return
        
    elif response.status_code == 401: # Permissions Error
        print("You do not have the required permissions to create an issue in ",
              "this project")
        sys.exit(exit_codes.INVALID_CREDENTIALS)

    elif response.status_code == 400: # Bad Request
        print("JIRA responded with Bad Request Error. ",
              f"Response message: {response.text}")
        sys.exit(exit_codes.BAD_REQUEST)

    else: # Some other error
        print("an Unknown Error has occured when attempting your request:",
              f"{response.text}")
        sys.exit(exit_codes.UNKNOWN_ERROR)
    

def main():
    args = get_args()
    username = args.username
    access_token = args.access_token
    project_key = args.project_key
    jira_url = args.jira_url
    additional_fields = args.additional_fields
    summary = args.summary
    description = args.description
    issue_type = args.issue_type
    ticket_key = args.ticket_key
    # generate payload
    payload = generate_payload_with_custom(project_key, summary, 
                                description, issue_type, custom_fields=additional_fields)

    update_existing_ticket(username, access_token, jira_url, ticket_key, payload)
    

