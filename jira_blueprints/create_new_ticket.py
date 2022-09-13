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
    parser.add_argument('--summary', dest='summary', required=False)
    parser.add_argument('--description', dest='description', required=False)
    parser.add_argument('--issue-type', dest='issue_type', required=False)
    parser.add_argument('--custom-json', dest='custom_json', required=False)
    args = parser.parse_args()
    return args


def generate_payload(project_key, summary, 
                     description, issue_type):
    """ Creates a JIRA Ticket json payload for use with the Jira create ticket
    rest API. 
    see: https://developer.atlassian.com/server/jira/platform
                /jira-rest-api-examples/#creating-an-issue-examples
    for an example of a basic payload.
    """
    
    payload = {
        "fields": {
           "project":
           {
              "key": project_key
           },
           "summary": summary,
           "description": description,
           "issuetype": {
              "name": issue_type
           }
       }
    }
    return payload


def create_ticket(username, token, jira_url, payload):
    """ Triggers the Create Issue API and adds a new ticket onto JIRA"""
    
    create_ticket_endpoint = f"https://{jira_url}/rest/api/3/issue"
    headers = {
      'Content-Type': 'application/json'
    }

    response = requests.post(create_ticket_endpoint, 
                             headers=headers, 
                             json=payload, 
                             auth=HTTPBasicAuth(username, token)
                             )
    
    if response.status_code == requests.codes.ok:
        new_ticket_key =  response.json()['key']
        print(f"Ticket created successfully with Key name: {new_ticket_key}")
        return response.json()
        
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
    
    # check if custom json first, else generate payload using args
    if args.custom_json:
        payload = args.custom_json
    else:
        summary = args.summary
        description = args.description
        issue_type = args.issue_type
        payload = generate_payload(project_key, summary, 
                                   description, issue_type)
        

    issue_data = create_ticket(username, access_token, jira_url, payload)
    issue_id = issue_data['id']
    
    # save issue to responses
    issue_data_filename = shipyard.files.combine_folder_and_file_name(
        artifact_subfolder_paths['responses'],
        f'create_ticket_{issue_id}_response.json')
    shipyard.files.write_json_to_file(issue_data, issue_data_filename)

    

